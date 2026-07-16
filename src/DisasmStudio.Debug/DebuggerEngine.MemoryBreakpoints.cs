using System.Runtime.InteropServices;

namespace DisasmStudio.Debug;

/// <summary>
/// Software memory breakpoints — data read/write breakpoints on an arbitrary byte <b>range</b>, implemented
/// with page protection (the technique x64dbg calls a "memory breakpoint", and a generalization of the SMC
/// write-protect path in the SelfModifying partial). The pages covering each watched range are protected:
/// a <see cref="MemAccess.Write"/> breakpoint strips PAGE_WRITE (only writes fault; reads/execution still
/// work), <see cref="MemAccess.Read"/>/<see cref="MemAccess.ReadWrite"/> use PAGE_NOACCESS (any access faults),
/// and <see cref="MemAccess.Execute"/> strips only the execute bit (only instruction fetches fault; reads/writes
/// still work). On a fault we read the access type and faulting address from the exception record: if the access
/// lands in a watched range with a matching kind we let it complete (single-step) then stop; otherwise we
/// transparently pass the access through and re-protect — so unrelated accesses to the same 4&#160;KiB page never
/// surface. Unlike a hardware watchpoint (4 slots, 1/2/4/8 aligned bytes) this covers any length.
/// </summary>
public sealed partial class DebuggerEngine
{
    private sealed class MemBp
    {
        public required ulong Start;      // inclusive
        public required ulong End;        // exclusive
        public required MemAccess Access;
        public bool Contains(ulong va) => va >= Start && va < End;
    }

    private sealed class MemPage
    {
        public uint OriginalProtect;   // the page's protection before we touched it — restored on removal/cleanup
        public uint AppliedProtect;    // what we keep applied (PAGE_NOACCESS or the write-stripped protection)
    }

    /// <summary>A pending trap-step: after a faulting access on <see cref="Page"/> is let through, re-protect the
    /// page and — if it was a real hit (<see cref="Stop"/>) — surface a stop at the accessing instruction.</summary>
    private readonly record struct MemStepState(ulong Page, bool Stop, ulong InstrAddr, ulong DataVa, int Access);

    private readonly List<MemBp> _memBps = [];
    private readonly Dictionary<ulong, MemPage> _memPages = [];    // page VA -> protection state
    private readonly Dictionary<uint, MemStepState> _memStep = []; // thread id -> pending trap-step

    /// <summary>Data address of the most recent memory-breakpoint hit (for the UI status line).</summary>
    public ulong LastMemoryHitVa { get; private set; }
    /// <summary>Access type of the most recent memory-breakpoint hit: 0 = read, 1 = write, 8 = execute.</summary>
    public int LastMemoryHitAccess { get; private set; }

    /// <summary>True if any software memory breakpoint is set.</summary>
    public bool HasMemoryBreakpoints { get { lock (_lock) return _memBps.Count > 0; } }

    /// <summary>A memory breakpoint for display: start VA, byte length, and access kind.</summary>
    public readonly record struct MemBpInfo(ulong Start, int Length, MemAccess Access);

    /// <summary>Snapshot of the current memory breakpoints (for the debugger panel's Breakpoints list).</summary>
    public IReadOnlyList<MemBpInfo> MemoryBreakpoints
    {
        get { lock (_lock) return _memBps.Select(b => new MemBpInfo(b.Start, (int)(b.End - b.Start), b.Access)).ToList(); }
    }

    /// <summary>Set a software memory breakpoint on <paramref name="len"/> bytes at <paramref name="start"/>,
    /// breaking on read / write / either per <paramref name="access"/>. Any length (protects the covering
    /// pages). Replaces an existing memory breakpoint with the same start. Call while the debuggee is stopped.</summary>
    public void SetMemoryBreakpoint(ulong start, ulong len, MemAccess access)
    {
        if (_proc == IntPtr.Zero || len == 0) return;
        lock (_lock)
        {
            ulong end = start + len;
            // Gather the pages of any breakpoint we're replacing as well, so a page the new (possibly smaller)
            // range no longer covers gets its protection recomputed/restored instead of being left orphaned.
            var pages = new HashSet<ulong>();
            foreach (var old in _memBps.Where(b => b.Start == start))
                for (ulong p = old.Start & ~0xFFFUL; p < old.End; p += 0x1000) pages.Add(p);
            _memBps.RemoveAll(b => b.Start == start);
            _memBps.Add(new MemBp { Start = start, End = end, Access = access });
            for (ulong p = start & ~0xFFFUL; p < end; p += 0x1000) pages.Add(p);
            foreach (ulong p in pages) ApplyPageProtection(p);
        }
    }

    /// <summary>Remove the memory breakpoint that starts at <paramref name="start"/>; restore (or downgrade) the
    /// protection of the pages it covered. Call while the debuggee is stopped.</summary>
    public void RemoveMemoryBreakpoint(ulong start)
    {
        lock (_lock)
        {
            int idx = _memBps.FindIndex(b => b.Start == start);
            if (idx < 0) return;
            var bp = _memBps[idx];
            _memBps.RemoveAt(idx);
            for (ulong p = bp.Start & ~0xFFFUL; p < bp.End; p += 0x1000)
                ApplyPageProtection(p);   // recomputes — restores the page if nothing needs it anymore
        }
    }

    /// <summary>True if a memory breakpoint starts exactly at <paramref name="start"/>.</summary>
    public bool HasMemoryBreakpoint(ulong start) { lock (_lock) return _memBps.Any(b => b.Start == start); }

    // Recompute and apply the protection a single page needs, given the memory bps overlapping it. Under _lock.
    private void ApplyPageProtection(ulong page)
    {
        ulong pageEnd = page + 0x1000;
        bool needRead = false, needWrite = false, needExec = false;
        foreach (var b in _memBps)
        {
            if (b.End <= page || b.Start >= pageEnd) continue;   // this bp doesn't overlap the page
            if (b.Access is MemAccess.Read or MemAccess.ReadWrite) needRead = true;
            if (b.Access is MemAccess.Write or MemAccess.ReadWrite) needWrite = true;
            if (b.Access is MemAccess.Execute) needExec = true;
        }

        if (!needRead && !needWrite && !needExec)
        {
            if (_memPages.Remove(page, out var gone))     // no bp needs this page — restore its original protection
                Native.VirtualProtectEx(_proc, page, (nuint)0x1000, gone.OriginalProtect, out _);
            return;
        }

        if (!_memPages.TryGetValue(page, out var mp))     // capture the original protection the first time
        {
            int mbiSize = Marshal.SizeOf<Native.MEMORY_BASIC_INFORMATION>();
            if (Native.VirtualQueryEx(_proc, page, out var mbi, (nuint)mbiSize) == 0) return;
            if (mbi.State != Native.MEM_COMMIT) return;
            mp = new MemPage { OriginalProtect = mbi.Protect & 0xFF };
            _memPages[page] = mp;
        }

        // Read detection needs NO_ACCESS (no protection faults on read alone); write detection strips the write
        // bit; execute detection strips only the execute bit (keeps read/write so data accesses don't fault and
        // int3 planting still works). NO_ACCESS already faults instruction fetches, so it subsumes an execute
        // watch — hence strip write/execute only when read isn't already forcing NO_ACCESS.
        uint target;
        if (needRead) target = Native.PAGE_NOACCESS;
        else
        {
            target = needWrite ? StripWrite(mp.OriginalProtect) : mp.OriginalProtect;
            if (needExec) target = StripExecute(target);
        }
        mp.AppliedProtect = target;
        Native.VirtualProtectEx(_proc, page, (nuint)0x1000, target, out _);
    }

    /// <summary>Handle a data access violation (read Info0==0 / write Info0==1) whose faulting page we protected
    /// for a memory breakpoint. Restores the page, arms a trap-step to let the access complete, and records
    /// whether a matching breakpoint means we stop afterwards. Returns false (fall through to normal AV
    /// reporting) when the page isn't ours — i.e. a genuine program access violation.</summary>
    private bool MemHandleFault(uint tid, ulong faultVa, int accessType, ulong instrAddr, ref uint cont)
    {
        ulong page = faultVa & ~0xFFFUL;
        bool stop;
        lock (_lock)
        {
            if (!_memPages.ContainsKey(page)) return false;   // not our page — a genuine AV, report it
            stop = _memBps.Any(b => b.Contains(faultVa) && Matches(b.Access, accessType));
        }
        IntPtr hThread = ThreadHandle(tid);
        if (hThread == IntPtr.Zero) return false;

        lock (_lock)
        {
            if (_memPages.TryGetValue(page, out var mp))      // restore so the faulting instruction can complete
                Native.VirtualProtectEx(_proc, page, (nuint)0x1000, mp.OriginalProtect, out _);
            _memStep[tid] = new MemStepState(page, stop, instrAddr, faultVa, accessType);
        }
        using (var c = new Ctx(Is32))
            if (c.Get(hThread)) { c.TrapFlag = true; c.Set(hThread); }

        cont = Native.DBG_CONTINUE;
        return true;
    }

    /// <summary>Complete a memory-breakpoint trap-step armed by <see cref="MemHandleFault"/>: re-protect the page.
    /// Returns false (a no-op) when this thread has no pending memory step, so it is safe to consult on every
    /// single-step. When it returns true, <paramref name="step"/> says whether the access was a real hit.</summary>
    private bool MemHandleStep(uint tid, out MemStepState step)
    {
        lock (_lock)
        {
            if (!_memStep.Remove(tid, out step)) return false;
            if (_memPages.TryGetValue(step.Page, out var mp))
                Native.VirtualProtectEx(_proc, step.Page, (nuint)0x1000, mp.AppliedProtect, out _);
            if (step.Stop) { LastMemoryHitVa = step.DataVa; LastMemoryHitAccess = step.Access; }
            return true;
        }
    }

    private static bool Matches(MemAccess kind, int accessType) => kind switch
    {
        MemAccess.Read => accessType == 0,
        MemAccess.Write => accessType == 1,
        MemAccess.Execute => accessType == 8,   // instruction fetch
        _ => accessType is 0 or 1,   // ReadWrite
    };

    /// <summary>While stopped, temporarily restore any PAGE_NOACCESS memory-bp pages overlapping [addr,addr+count)
    /// so the debugger's own ReadProcessMemory (memory dump / disassembly) can read them; returns the pages it
    /// opened so the caller can re-protect afterwards. Under _lock. Null when nothing needed opening.</summary>
    private List<ulong>? OpenMemPagesForRead(ulong addr, int count)
    {
        List<ulong>? opened = null;
        ulong end = addr + (ulong)count;
        for (ulong p = addr & ~0xFFFUL; p < end; p += 0x1000)
        {
            if (_memPages.TryGetValue(p, out var mp) && mp.AppliedProtect == Native.PAGE_NOACCESS)
            {
                Native.VirtualProtectEx(_proc, p, (nuint)0x1000, mp.OriginalProtect, out _);
                (opened ??= []).Add(p);
            }
        }
        return opened;
    }

    private void ReprotectMemPages(List<ulong> pages)
    {
        foreach (ulong p in pages)
            if (_memPages.TryGetValue(p, out var mp))
                Native.VirtualProtectEx(_proc, p, (nuint)0x1000, mp.AppliedProtect, out _);
    }

    /// <summary>Restore every memory-bp page's protection and drop all memory-breakpoint state (detach / exit).</summary>
    internal void MemCleanup()
    {
        lock (_lock)
        {
            if (_proc != IntPtr.Zero)
                foreach (var (page, mp) in _memPages)
                    Native.VirtualProtectEx(_proc, page, (nuint)0x1000, mp.OriginalProtect, out _);
            _memPages.Clear();
            _memBps.Clear();
            _memStep.Clear();
        }
    }
}

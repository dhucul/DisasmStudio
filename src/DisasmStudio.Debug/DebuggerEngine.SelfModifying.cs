using System.Runtime.InteropServices;

namespace DisasmStudio.Debug;

/// <summary>
/// Self-modifying code (SMC) detection and breakpoint resilience. Every code page that carries a software
/// breakpoint is <b>write-protected</b> — its PAGE_WRITE bit is stripped (e.g. PAGE_EXECUTE_READWRITE →
/// PAGE_EXECUTE_READ) — so the page still reads and executes normally (breakpoints fire, the disassembly
/// reads fine) but any <b>write</b> to it faults with an access violation. On such a write we restore write
/// access, let the write complete (single-step), re-evaluate/re-arm the page's breakpoints (an overwritten
/// 0xCC is replanted over the new instruction), re-protect the page, and notify the UI. This keeps every
/// breakpoint alive even when a protector decrypts / patches the code over it.
///
/// (The earlier design used PAGE_GUARD, which fires on <i>any</i> access including instruction fetch — so
/// execution on a guarded page faulted, breakpoints got stepped over without firing, and cross-process reads
/// returned nothing ("??"). Write-protection only faults on writes, which is what SMC tracking actually needs.)
/// </summary>
public sealed partial class DebuggerEngine
{
    /// <summary>Raised on the debug-loop thread when a write-protected code page was written to, after the
    /// page's breakpoints have been re-evaluated. The set of VAs lists every breakpoint address whose 0xCC
    /// byte was overwritten by the write (re-armed over the new instruction). Empty if the write didn't touch
    /// any of our breakpoints. The UI can use this to refresh the disassembly of that page.</summary>
    public event Action<ulong, ulong[]>? CodeModified;

    /// <summary>When true (default), every code page that gets a breakpoint is write-protected (PAGE_WRITE
    /// stripped) so writes to it surface as an access violation and the breakpoint is re-armed over the new
    /// code, instead of the write silently overwriting our int3. Reads and execution are unaffected. Disable
    /// to avoid the per-write fault overhead on a target that writes heavily to a breakpoint'd code page.</summary>
    public bool SmcTrackingEnabled { get; set; } = true;

    // Page VA -> protection metadata for pages we've write-protected.
    private readonly Dictionary<ulong, ProtectedCodePage> _codeGuards = [];

    private sealed class ProtectedCodePage
    {
        /// <summary>The page's original (writable) protection — restored to let a write through and on untrack.</summary>
        public uint OriginalProtect;
        /// <summary>The write-stripped protection we keep applied (e.g. PAGE_EXECUTE_READ).</summary>
        public uint ProtectedProtect;
        /// <summary>Breakpoint addresses on this page whose 0xCC must survive writes.</summary>
        public readonly HashSet<ulong> Breakpoints = [];
    }

    private const uint ExecBits = Native.PAGE_EXECUTE | Native.PAGE_EXECUTE_READ
                                | Native.PAGE_EXECUTE_READWRITE | Native.PAGE_EXECUTE_WRITECOPY;   // 0xF0

    /// <summary>Map a writable protection to its write-stripped equivalent (unchanged if already non-writable).</summary>
    private static uint StripWrite(uint p) => p switch
    {
        Native.PAGE_EXECUTE_READWRITE => Native.PAGE_EXECUTE_READ,
        Native.PAGE_EXECUTE_WRITECOPY => Native.PAGE_EXECUTE_READ,
        Native.PAGE_READWRITE => Native.PAGE_READONLY,
        Native.PAGE_WRITECOPY => Native.PAGE_READONLY,
        _ => p,
    };

    // ---- public control ----

    /// <summary>Begin write-protecting all code pages that already carry breakpoints, and enable automatic
    /// protection for any future breakpoints. Idempotent. Call while the debuggee is stopped.</summary>
    public void EnableSmcTracking()
    {
        SmcTrackingEnabled = true;
        if (_proc == IntPtr.Zero) return;
        // Snapshot the armed breakpoint addresses under the lock; ProtectPageForBreakpoint re-acquires
        // _lock internally for each page, so we don't hold it across all the VirtualProtectEx syscalls.
        List<ulong> bps;
        lock (_lock) bps = _swBps.Values.Where(b => b.Armed).Select(b => b.Address).ToList();
        foreach (var va in bps)
            ProtectPageForBreakpoint(va);
    }

    /// <summary>Stop tracking: restore every page we protected to its original (writable) protection.
    /// Breakpoints themselves are left armed. Call while the debuggee is stopped.</summary>
    public void DisableSmcTracking()
    {
        SmcTrackingEnabled = false;
        if (_proc == IntPtr.Zero) return;
        lock (_lock) UnprotectAllPages();
    }

    // ---- page protection helpers (debug loop / stopped) ----
    //
    // All helpers below take _lock internally (Monitor is re-entrant). This keeps _codeGuards consistent
    // whether the caller is the UI thread (breakpoint add/remove while stopped) or the debug-loop thread.

    private void ProtectPageForBreakpoint(ulong bpVa)
    {
        lock (_lock)
        {
            ulong page = bpVa & ~0xFFFUL;
            if (_codeGuards.TryGetValue(page, out var g))
            {
                g.Breakpoints.Add(bpVa);
                return;
            }

            int mbiSize = Marshal.SizeOf<Native.MEMORY_BASIC_INFORMATION>();
            if (Native.VirtualQueryEx(_proc, page, out var mbi, (nuint)mbiSize) == 0) return;
            if (mbi.State != Native.MEM_COMMIT) return;
            uint prot = mbi.Protect & 0xFF;             // ignore PAGE_GUARD/NOCACHE/etc. modifier bits
            if ((prot & ExecBits) == 0) return;         // not executable — breakpoints are on code only
            uint stripped = StripWrite(prot);
            if (stripped == prot) return;               // already read-only — the program can't self-modify it

            if (!Native.VirtualProtectEx(_proc, page, (nuint)0x1000, stripped, out uint old)) return;

            g = new ProtectedCodePage { OriginalProtect = prot, ProtectedProtect = stripped };
            g.Breakpoints.Add(bpVa);
            _codeGuards[page] = g;
        }
    }

    private void UnprotectAllPages()
    {
        lock (_lock)
        {
            foreach (var (page, g) in _codeGuards)
                Native.VirtualProtectEx(_proc, page, (nuint)0x1000, g.OriginalProtect, out _);
            _codeGuards.Clear();
        }
    }

    private void UnprotectPageIfEmpty(ulong page)
    {
        lock (_lock)
        {
            if (!_codeGuards.TryGetValue(page, out var g)) return;
            if (g.Breakpoints.Count > 0) return;
            Native.VirtualProtectEx(_proc, page, (nuint)0x1000, g.OriginalProtect, out _);
            _codeGuards.Remove(page);
        }
    }

    internal void SmcUntrackBreakpoint(ulong bpVa)
    {
        lock (_lock)
        {
            ulong page = bpVa & ~0xFFFUL;
            if (!_codeGuards.TryGetValue(page, out var g)) return;
            g.Breakpoints.Remove(bpVa);
            UnprotectPageIfEmpty(page);
        }
    }

    // ---- write fault: intercept the AV, run the write, re-evaluate ----
    //
    // Concurrency: the debug loop is single-threaded; the whole process is suspended during each event, so
    // write faults/steps are serialized. After restoring write on a page, no other thread can fault on it
    // until the write-step re-protects it, so same-page concurrent writes are naturally serialized. The one
    // edge case is a single instruction (e.g. rep stos) faulting on two protected pages: the second fault
    // supersedes the first's trap, so we drain the pending re-eval in SmcHandleWriteFault.

    // Pending re-evaluation: thread id -> page that had its write access temporarily restored.
    private readonly Dictionary<uint, ulong> _pendingGuardReeval = [];

    /// <summary>Handle a write access violation on a page we write-protected (called when code==AV, Info0==1).
    /// Restores write, disarms the page's breakpoints, and single-steps so the write completes; the resulting
    /// single-step is finished by <see cref="SmcHandleWriteStep"/>. Returns false (so the AV falls through to
    /// normal handling) when the faulting page isn't one of ours — i.e. a genuine program access violation.</summary>
    internal bool SmcHandleWriteFault(uint tid, ulong faultVa, ref uint cont)
    {
        ulong page = faultVa & ~0xFFFUL;
        ProtectedCodePage? prot;
        lock (_lock) _codeGuards.TryGetValue(page, out prot);
        if (prot is null) return false;            // not our page — a real AV; let normal handling report it

        IntPtr hThread = ThreadHandle(tid);
        if (hThread == IntPtr.Zero) return false;

        // If this thread already has a pending re-eval, its earlier write-step's single-step was superseded by
        // this new fault (a single instruction, e.g. rep stos, faulting on a second protected page before the
        // first's trap fired). Complete it now so the previous page's breakpoints aren't left disarmed when
        // _pendingGuardReeval[tid] is overwritten below.
        ulong[]? prevModified = null;
        ulong prevPage = 0;
        lock (_lock)
        {
            if (_pendingGuardReeval.Remove(tid, out prevPage))
                prevModified = RearmAndReprotect(prevPage);
        }
        if (prevModified is not null && prevModified.Length > 0)
            CodeModified?.Invoke(prevPage, prevModified);

        // 1. Restore write access so the faulting instruction can complete on the retry.
        Native.VirtualProtectEx(_proc, page, (nuint)0x1000, prot.OriginalProtect, out _);

        // 2. Temporarily disarm every breakpoint on this page so (a) the single-step raises EXCEPTION_SINGLE_STEP
        //    rather than hitting a 0xCC, and (b) the post-write re-eval reads the program's real bytes, not ours.
        List<ulong>? disarmed = null;
        lock (_lock)
        {
            foreach (ulong va in prot.Breakpoints)
            {
                if (!_swBps.TryGetValue(va, out var bp) || !bp.Armed) continue;
                WriteCodeNoLock(va, [bp.Original]);
                bp.Armed = false;
                (disarmed ??= []).Add(va);
            }
            if (disarmed is not null)
                _guardDisarmedByPage[page] = disarmed;
            _pendingGuardReeval[tid] = page;
        }

        // 3. Single-step so the write instruction executes (its access is now permitted).
        using (var c = new Ctx(Is32))
        {
            if (c.Get(hThread))
            {
                c.TrapFlag = true;
                c.Set(hThread);
            }
        }

        cont = Native.DBG_CONTINUE;
        return true;
    }

    // page -> list of VAs we temporarily disarmed for a write-fault step
    private readonly Dictionary<ulong, List<ulong>> _guardDisarmedByPage = [];

    /// <summary>Finish the single-step armed by <see cref="SmcHandleWriteFault"/>: re-arm the page's
    /// breakpoints (replanting over any new code) and re-protect it. A no-op (returns false) when this thread
    /// has no pending write-fault re-eval, so it is safe to consult on every single-step event.</summary>
    internal bool SmcHandleWriteStep(uint tid, out ulong page)
    {
        page = 0;
        ulong[] modified;
        lock (_lock)
        {
            if (!_pendingGuardReeval.Remove(tid, out page))
                return false;
            modified = RearmAndReprotect(page);
        }
        // Notify (outside the lock so handlers can call back into the engine).
        if (modified.Length > 0)
            CodeModified?.Invoke(page, modified);
        return true;
    }

    /// <summary>Re-arm every breakpoint disarmed on <paramref name="page"/> for a write-step, re-apply
    /// write-protection, and return the VAs whose byte was changed by the write. Called under _lock.</summary>
    private ulong[] RearmAndReprotect(ulong page)
    {
        var modified = new List<ulong>();
        if (_guardDisarmedByPage.Remove(page, out var disarmed))
        {
            foreach (ulong va in disarmed)
            {
                if (!_swBps.TryGetValue(va, out var bp)) continue;
                var live = ReadMemory(va, 1);
                if (live.Length != 1) continue;
                // The write clobbered our breakpoint if the live byte differs from the original we
                // restored before the step (an untouched address still holds bp.Original).
                bool clobbered = live[0] != bp.Original;
                bp.Original = live[0];
                WriteCodeNoLock(va, [0xCC]);
                bp.Armed = true;
                if (clobbered)
                    modified.Add(va);
            }
        }
        // Re-apply write-protection.
        if (_codeGuards.TryGetValue(page, out var prot))
            Native.VirtualProtectEx(_proc, page, (nuint)0x1000, prot.ProtectedProtect, out _);
        return modified.ToArray();
    }

    /// <summary>Write bytes and flush the instruction cache, without the protect-toggling <see cref="WriteCode"/>
    /// does (the SMC paths manage page protection themselves around these writes). Call under _lock when
    /// touching armed breakpoints.</summary>
    private bool WriteCodeNoLock(ulong addr, byte[] bytes)
    {
        if (_proc == IntPtr.Zero) return false;
        bool ok = Native.WriteProcessMemory(_proc, addr, bytes, (nuint)bytes.Length, out _);
        Native.FlushInstructionCache(_proc, addr, (nuint)bytes.Length);
        return ok;
    }

    internal void SmcCleanup()
    {
        lock (_lock)
        {
            foreach (var (page, g) in _codeGuards)
                if (_proc != IntPtr.Zero)
                    Native.VirtualProtectEx(_proc, page, (nuint)0x1000, g.OriginalProtect, out _);
            _codeGuards.Clear();
            _guardDisarmedByPage.Clear();
            _pendingGuardReeval.Clear();
        }
    }

    /// <summary>True if the given address lives on a page we have write-protected for SMC tracking.</summary>
    public bool IsSmcGuardedPage(ulong va)
    {
        lock (_lock) return _codeGuards.ContainsKey(va & ~0xFFFUL);
    }

    /// <summary>Number of code pages currently write-protected for SMC tracking.</summary>
    public int SmcGuardedPageCount { get { lock (_lock) return _codeGuards.Count; } }
}

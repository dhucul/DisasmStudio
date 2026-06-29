using System.Runtime.InteropServices;

namespace DisasmStudio.Debug;

/// <summary>
/// Self-modifying code (SMC) detection and breakpoint resilience. When code pages carrying software
/// breakpoints are written to, the writes are intercepted via PAGE_GUARD, breakpoints are re-evaluated
/// and re-armed, and the UI is notified so it can refresh its disassembly. This keeps every breakpoint
/// alive even when a protector decrypts / patches the code over it.
/// </summary>
public sealed partial class DebuggerEngine
{
    /// <summary>Raised on the debug-loop thread when a guarded code page was written to, after breakpoints
    /// on that page have been re-evaluated. The set of VAs lists every breakpoint address on the page that
    /// needed re-arming (i.e. whose 0xCC byte was overwritten by the write). Empty if the write didn't
    /// touch any of our breakpoints. The UI can use this to refresh the disassembly of those pages.</summary>
    public event Action<ulong, ulong[]>? CodeModified;

    /// <summary>When true (default), every code page that gets a breakpoint is automatically guarded so
    /// writes to it surface as a guard-page violation rather than silently overwriting our int3 bytes.
    /// Disable to suppress the PAGE_GUARD overhead during sections with heavy write traffic.</summary>
    public bool SmcTrackingEnabled { get; set; } = true;

    // page VA -> guard metadata
    private readonly Dictionary<ulong, CodePageGuard> _codeGuards = [];

    private sealed class CodePageGuard
    {
        /// <summary>The original page protection before we added PAGE_GUARD.</summary>
        public uint OriginalProtect;
        /// <summary>Breakpoint addresses on this page whose 0xCC must survive writes.</summary>
        public readonly HashSet<ulong> Breakpoints = [];
    }

    // ---- public control ----

    /// <summary>Begin guarding all code pages that already carry breakpoints, and enable automatic
    /// guarding for any future breakpoints. Idempotent. Call while the debuggee is stopped.</summary>
    public void EnableSmcTracking()
    {
        SmcTrackingEnabled = true;
        if (_proc == IntPtr.Zero) return;
        Dictionary<ulong, Breakpoint> bps;
        lock (_lock) bps = _swBps.Values.Where(b => b.Armed).ToDictionary(b => b.Address);
        foreach (var (va, _) in bps)
            GuardPageForBreakpoint(va);
    }

    /// <summary>Stop guarding: restore every page we protected to its original protection. Breakpoints
    /// themselves are left armed. Call while the debuggee is stopped.</summary>
    public void DisableSmcTracking()
    {
        SmcTrackingEnabled = false;
        if (_proc == IntPtr.Zero) return;
        lock (_lock) UnguardAllPages();
    }

    // ---- page guard helpers (debug loop / stopped) ----

    private void GuardPageForBreakpoint(ulong bpVa)
    {
        ulong page = bpVa & ~0xFFFUL;
        if (_codeGuards.TryGetValue(page, out var g))
        {
            g.Breakpoints.Add(bpVa);
            return;
        }

        int mbiSize = Marshal.SizeOf<Native.MEMORY_BASIC_INFORMATION>();
        if (Native.VirtualQueryEx(_proc, page, out var mbi, (nuint)mbiSize) == 0)
            return;
        if (mbi.State != Native.MEM_COMMIT) return;
        uint prot = mbi.Protect;
        if ((prot & 0xF0) == 0) return;        // not executable - skip
        if ((prot & Native.PAGE_GUARD) != 0)   // already guarded (unlikely for code, but tolerate)
        {
            g = new CodePageGuard { OriginalProtect = prot };
            g.Breakpoints.Add(bpVa);
            _codeGuards[page] = g;
            return;
        }

        // Add PAGE_GUARD on top of the current execute+read(+write) protection.
        uint guarded = prot | Native.PAGE_GUARD;
        if (!Native.VirtualProtectEx(_proc, page, (nuint)0x1000, guarded, out uint old))
            return;

        g = new CodePageGuard { OriginalProtect = old };
        g.Breakpoints.Add(bpVa);
        _codeGuards[page] = g;
    }

    private void UnguardAllPages()
    {
        foreach (var (page, g) in _codeGuards)
            Native.VirtualProtectEx(_proc, page, (nuint)0x1000, g.OriginalProtect, out _);
        _codeGuards.Clear();
    }

    private void UnguardPageIfEmpty(ulong page)
    {
        if (!_codeGuards.TryGetValue(page, out var g)) return;
        if (g.Breakpoints.Count > 0) return;
        Native.VirtualProtectEx(_proc, page, (nuint)0x1000, g.OriginalProtect, out _);
        _codeGuards.Remove(page);
    }

    internal void SmcUntrackBreakpoint(ulong bpVa)
    {
        ulong page = bpVa & ~0xFFFUL;
        if (!_codeGuards.TryGetValue(page, out var g)) return;
        g.Breakpoints.Remove(bpVa);
        UnguardPageIfEmpty(page);
    }

    // ---- guard-page violation: intercept the exception, run the write, re-evaluate ----

    // Pending re-evaluation: thread id -> page that had its guard temporarily lifted.
    private readonly Dictionary<uint, ulong> _pendingGuardReeval = [];

    internal bool SmcHandleGuardViolation(uint tid, ulong faultVa, ref uint cont)
    {
        ulong page = faultVa & ~0xFFFUL;
        CodePageGuard? guard;
        lock (_lock) _codeGuards.TryGetValue(page, out guard);
        if (guard is null) return false;           // not our page - let the program handle it

        IntPtr hThread = ThreadHandle(tid);
        if (hThread == IntPtr.Zero) return false;

        // 1. Lift the guard so the write can complete without re-faulting.
        Native.VirtualProtectEx(_proc, page, (nuint)0x1000, guard.OriginalProtect, out _);

        // 2. Temporarily disarm every breakpoint on this page so the single-step doesn't hit one
        //    instead of raising EXCEPTION_SINGLE_STEP.
        List<ulong>? disarmed = null;
        lock (_lock)
        {
            foreach (ulong va in guard.Breakpoints)
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

        // 3. Single-step to execute the write instruction.
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

    // page -> list of VAs we temporarily disarmed for a guard-violation step
    private readonly Dictionary<ulong, List<ulong>> _guardDisarmedByPage = [];

    internal bool SmcHandleGuardStep(uint tid, out ulong page)
    {
        page = 0;
        lock (_lock)
        {
            if (!_pendingGuardReeval.Remove(tid, out page))
                return false;
        }

        // Re-arm every breakpoint we disarmed for the step. For each, read the current byte:
        // if the write didn't touch it, the byte is still the original and we restore 0xCC;
        // if it WAS overwritten, the live byte is the new code, so we save it and write 0xCC.
        var modified = new List<ulong>();
        lock (_lock)
        {
            if (_guardDisarmedByPage.Remove(page, out var disarmed))
            {
                foreach (ulong va in disarmed)
                {
                    if (!_swBps.TryGetValue(va, out var bp)) continue;
                    var live = ReadMemory(va, 1);
                    if (live.Length != 1) continue;
                    bp.Original = live[0];
                    WriteCodeNoLock(va, [0xCC]);
                    bp.Armed = true;
                    // If the byte we just read (the restored original from the write) is not 0xCC,
                    // the write clobbered our 0xCC - report it.
                    if (live[0] != 0xCC)
                        modified.Add(va);
                }
            }
        }

        // Re-apply the guard.
        CodePageGuard? guard;
        lock (_lock) _codeGuards.TryGetValue(page, out guard);
        if (guard is not null)
        {
            uint guarded = guard.OriginalProtect | Native.PAGE_GUARD;
            Native.VirtualProtectEx(_proc, page, (nuint)0x1000, guarded, out _);
        }

        // Notify.
        if (modified.Count > 0)
            CodeModified?.Invoke(page, modified.ToArray());

        return true;
    }

    /// <summary>Write bytes without VirtualProtect/FlushInstructionCache (callers already manage that).
    /// Must be called under _lock when touching armed breakpoints.</summary>
    private bool WriteCodeNoLock(ulong addr, byte[] bytes)
    {
        if (_proc == IntPtr.Zero) return false;
        return Native.WriteProcessMemory(_proc, addr, bytes, (nuint)bytes.Length, out _);
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

    /// <summary>True if the given address lives on a page we have guarded for SMC tracking.</summary>
    public bool IsSmcGuardedPage(ulong va)
    {
        lock (_lock) return _codeGuards.ContainsKey(va & ~0xFFFUL);
    }

    /// <summary>Number of code pages currently guarded for SMC tracking.</summary>
    public int SmcGuardedPageCount { get { lock (_lock) return _codeGuards.Count; } }
}
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
        // Snapshot the armed breakpoint addresses under the lock; GuardPageForBreakpoint re-acquires
        // _lock internally for each page, so we don't hold it across all the VirtualProtectEx syscalls.
        List<ulong> bps;
        lock (_lock) bps = _swBps.Values.Where(b => b.Armed).Select(b => b.Address).ToList();
        foreach (var va in bps)
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
    //
    // All helpers below take _lock internally (Monitor is re-entrant). This keeps _codeGuards consistent
    // whether the caller is the UI thread (breakpoint add/remove while stopped) or the debug-loop thread.

    private void GuardPageForBreakpoint(ulong bpVa)
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
    }

    private void UnguardAllPages()
    {
        lock (_lock)
        {
            foreach (var (page, g) in _codeGuards)
                Native.VirtualProtectEx(_proc, page, (nuint)0x1000, g.OriginalProtect, out _);
            _codeGuards.Clear();
        }
    }

    private void UnguardPageIfEmpty(ulong page)
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
            UnguardPageIfEmpty(page);
        }
    }

    // ---- guard-page violation: intercept the exception, run the write, re-evaluate ----
    //
    // Concurrency: the debug loop is single-threaded; the whole process is suspended during each event, so
    // guard violations/steps are serialized. After lifting a page's guard, no other thread can fault on it
    // until the guard-step re-applies it, so same-page concurrent writes are naturally serialized. The one
    // edge case is a single instruction (e.g. rep stos) faulting on two guarded pages: the second fault
    // supersedes the first's trap, so we drain the pending re-eval in SmcHandleGuardViolation.

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

        // If this thread already has a pending guard re-eval, its earlier guard-step's single-step was
        // superseded by this new fault (a single instruction, e.g. rep stos, faulting on a second guarded
        // page before the first's trap fired). Complete it now so the previous page's breakpoints aren't
        // left disarmed when _pendingGuardReeval[tid] is overwritten below.
        ulong[]? prevModified = null;
        ulong prevPage = 0;
        lock (_lock)
        {
            if (_pendingGuardReeval.Remove(tid, out prevPage))
                prevModified = RearmAndReguard(prevPage);
        }
        if (prevModified is not null && prevModified.Length > 0)
            CodeModified?.Invoke(prevPage, prevModified);
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
        ulong[] modified;
        lock (_lock)
        {
            if (!_pendingGuardReeval.Remove(tid, out page))
                return false;
            modified = RearmAndReguard(page);
        }
        // Notify (outside the lock so handlers can call back into the engine).
        if (modified.Length > 0)
            CodeModified?.Invoke(page, modified);
        return true;
    }

    /// <summary>Re-arm every breakpoint disarmed on <paramref name="page"/> for a guard-step, re-apply
    /// PAGE_GUARD, and return the VAs whose byte was changed by the write. Called under _lock.</summary>
    private ulong[] RearmAndReguard(ulong page)
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
        // Re-apply the guard.
        if (_codeGuards.TryGetValue(page, out var guard))
        {
            uint guarded = guard.OriginalProtect | Native.PAGE_GUARD;
            Native.VirtualProtectEx(_proc, page, (nuint)0x1000, guarded, out _);
        }
        return modified.ToArray();
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

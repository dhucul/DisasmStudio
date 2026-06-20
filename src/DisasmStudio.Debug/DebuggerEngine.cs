using System.Collections.Concurrent;
using Iced.Intel;

namespace DisasmStudio.Debug;

/// <summary>
/// A user-mode debugger engine. One dedicated thread launches or attaches and owns the
/// <c>WaitForDebugEvent</c>/<c>ContinueDebugEvent</c> loop (Windows requires the same thread for both).
/// The UI enqueues resume commands (Go/Step/…); while the debuggee is frozen at a stop, memory and
/// register reads/writes and breakpoint changes are done directly (the loop thread is idle). Supports
/// software breakpoints, hardware breakpoints/watchpoints (Dr0–3/Dr7), single-step, step over/out,
/// run-to-cursor, and both x64 and x86 (WOW64) targets.
/// </summary>
public sealed class DebuggerEngine
{
    public event Action<StopInfo>? Stopped;
    public event Action? Running;
    public event Action<int>? Exited;
    public event Action<string>? Output;
    public event Action? ModulesChanged;
    public event Action? ThreadsChanged;

    private Thread? _thread;
    private string? _launchPath;
    private uint _attachPid;
    private bool _attached;

    private IntPtr _proc;
    private uint _pid;
    public bool Is32 { get; private set; }
    public ulong ImageBase { get; private set; }
    public ulong EntryPoint { get; private set; }
    public IntPtr ProcessHandle => _proc;
    public bool IsActive { get; private set; }
    public bool IsStopped { get; private set; }
    public uint CurrentThreadId { get; private set; }

    /// <summary>When set (during capture), first-chance exceptions are passed to the debuggee's own
    /// handlers without stopping; only a second-chance (fatal/unhandled) exception surfaces.</summary>
    public bool PassFirstChanceExceptions { get; set; }

    /// <summary>Per-exception-code policy (x64dbg/IDA-style): which exceptions break the UI vs pass straight
    /// to the program. Defaults to "break on everything, pass to the program" — the original behaviour.</summary>
    public ExceptionFilter ExceptionFilter { get; set; } = new();

    /// <summary>When set before launching, stop at the loader (system) breakpoint instead of skipping to
    /// the entry point — earlier, so capture can include TLS callbacks and static DLL DllMains.</summary>
    public bool StopAtLoaderBreakpoint { get; set; }

    private readonly object _lock = new();
    private readonly Dictionary<uint, IntPtr> _threads = [];
    private readonly Dictionary<ulong, ModuleInfo> _modules = [];
    private readonly Dictionary<ulong, Breakpoint> _swBps = [];
    private readonly List<Breakpoint> _hwBps = [];
    private readonly Dictionary<ulong, byte> _tempBps = [];

    private readonly BlockingCollection<(ResumeMode Mode, ulong Target)> _resume = new();

    // Step state (loop-thread only) — keyed by debuggee thread id. A multi-threaded debuggee can have several
    // threads each mid single-step at once (e.g. each stepping off a breakpoint during a Go), so this must not
    // be a single global, or one thread's step event clobbers/cross-attributes another's → a breakpoint left
    // un-rearmed (lost) or a stray 0xCC / misclassified stop.
    private readonly Dictionary<uint, StepState> _stepping = [];   // thread -> in-flight single-step
    private readonly HashSet<ulong> _reArmOnNextStop = [];         // bps disarmed for step-over/out/run-to, re-armed on the next stop
    private bool _seenSystemBp;
    private bool _pauseRequested;
    private bool _stopping;
    private bool _ended;

    public IReadOnlyList<ModuleInfo> Modules { get { lock (_lock) return _modules.Values.OrderBy(m => m.Base).ToList(); } }
    public IReadOnlyList<ThreadInfo> Threads { get { lock (_lock) return _threads.Keys.Select(id => new ThreadInfo(id, 0)).ToList(); } }
    public IReadOnlyList<Breakpoint> BreakpointList { get { lock (_lock) return _swBps.Values.Concat(_hwBps).ToList(); } }

    // ---- start ----
    public void Launch(string path)
    {
        _launchPath = path; _attached = false;
        _thread = new Thread(DebugLoop) { IsBackground = true, Name = "Debugger" };
        _thread.Start();
    }

    public void Attach(uint pid)
    {
        _attachPid = pid; _attached = true;
        _thread = new Thread(DebugLoop) { IsBackground = true, Name = "Debugger" };
        _thread.Start();
    }

    private bool StartTarget()
    {
        if (_attached)
        {
            Native.DebugSetProcessKillOnExit(false);
            if (!Native.DebugActiveProcess(_attachPid)) { Output?.Invoke($"DebugActiveProcess failed ({Marshal_LastError()})"); return false; }
            _pid = _attachPid;
            return true;
        }
        var si = new Native.STARTUPINFO { cb = (uint)System.Runtime.InteropServices.Marshal.SizeOf<Native.STARTUPINFO>() };
        bool ok = Native.CreateProcessW(_launchPath, null, IntPtr.Zero, IntPtr.Zero, false,
            Native.DEBUG_ONLY_THIS_PROCESS | Native.CREATE_NEW_CONSOLE, IntPtr.Zero, null, ref si, out var pi);
        if (!ok) { Output?.Invoke($"CreateProcess failed ({Marshal_LastError()})"); return false; }
        _pid = pi.dwProcessId;
        Native.CloseHandle(pi.hThread);
        return true;
    }

    private static int Marshal_LastError() => System.Runtime.InteropServices.Marshal.GetLastWin32Error();

    // ---- the loop ----
    private void DebugLoop()
    {
        if (!StartTarget()) { Exited?.Invoke(-1); return; }
        IsActive = true;

        while (!_ended)
        {
            if (!Native.WaitForDebugEvent(out var ev, 0xFFFFFFFF)) break;
            CurrentThreadId = ev.dwThreadId;
            uint cont = Native.DBG_CONTINUE;
            bool stop = HandleEvent(ev, ref cont);
            if (_ended) { Native.ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, cont); break; }
            if (_stopping) { DoStop(ev); break; }

            if (stop)
            {
                // Re-arm any breakpoints we stepped off (for step over/out/run-to) regardless of why we stopped.
                if (_reArmOnNextStop.Count > 0) { foreach (var a in _reArmOnNextStop) ArmAddr(a); _reArmOnNextStop.Clear(); }
                IsStopped = true;
                var (mode, target) = _resume.Take();
                IsStopped = false;
                if (mode == ResumeMode.Stop) { DoStop(ev); break; }
                Running?.Invoke();
                DoResume(mode, target, ev, cont);
            }
            else Native.ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, cont);
        }

        Cleanup();
    }

    private bool HandleEvent(in Native.DEBUG_EVENT ev, ref uint cont)
    {
        switch (ev.dwDebugEventCode)
        {
            case Native.CREATE_PROCESS_DEBUG_EVENT:
            {
                var info = ev.CreateProcess;
                _proc = info.hProcess;
                ImageBase = info.lpBaseOfImage;
                EntryPoint = info.lpStartAddress;
                Native.IsWow64Process(_proc, out bool wow);
                Is32 = wow;
                lock (_lock)
                {
                    _threads[ev.dwThreadId] = info.hThread;
                    _modules[ImageBase] = new ModuleInfo(ImageBase, ModulePath(ImageBase) ?? _launchPath ?? "(target)");
                }
                ThreadsChanged?.Invoke(); ModulesChanged?.Invoke();
                if (!_attached) AddTempBp(EntryPoint);   // launched: break at the entry point
                if (info.hFile != IntPtr.Zero) Native.CloseHandle(info.hFile);   // the debugger owns the image file handle
                return false;
            }
            case Native.CREATE_THREAD_DEBUG_EVENT:
                lock (_lock) _threads[ev.dwThreadId] = ev.CreateThread.hThread;
                ProgramHwForThread(ev.CreateThread.hThread);
                ThreadsChanged?.Invoke();
                return false;
            case Native.EXIT_THREAD_DEBUG_EVENT:
                lock (_lock) { if (_threads.Remove(ev.dwThreadId, out var h)) Native.CloseHandle(h); }
                _stepping.Remove(ev.dwThreadId);   // a thread that exited mid-step leaves no stale entry
                ThreadsChanged?.Invoke();
                return false;
            case Native.LOAD_DLL_DEBUG_EVENT:
            {
                ulong b = ev.LoadDll.lpBaseOfDll;
                lock (_lock) _modules[b] = new ModuleInfo(b, ModulePath(b) ?? $"module_{b:X}");
                if (ev.LoadDll.hFile != IntPtr.Zero) Native.CloseHandle(ev.LoadDll.hFile);   // close the DLL file handle
                ModulesChanged?.Invoke();
                return false;
            }
            case Native.UNLOAD_DLL_DEBUG_EVENT:
                lock (_lock) _modules.Remove(ev.UnloadDll.lpBaseOfDll);
                ModulesChanged?.Invoke();
                return false;
            case Native.OUTPUT_DEBUG_STRING_EVENT:
                return false;
            case Native.EXIT_PROCESS_DEBUG_EVENT:
                _ended = true;
                Exited?.Invoke((int)ev.ExitProcess.dwExitCode);
                return false;
            case Native.EXCEPTION_DEBUG_EVENT:
                return HandleException(ev, ref cont);
            default:
                return false;
        }
    }

    private bool HandleException(in Native.DEBUG_EVENT ev, ref uint cont)
    {
        var er = ev.Exception.ExceptionRecord;
        uint code = er.ExceptionCode;
        ulong addr = er.ExceptionAddress;
        IntPtr hThread = ThreadHandle(ev.dwThreadId);

        if (code is Native.EXCEPTION_BREAKPOINT or Native.STATUS_WX86_BREAKPOINT)
        {
            // temp / one-shot breakpoint
            if (RemoveTempBpIfPresent(addr))
            {
                SetIp(hThread, addr);   // _reArmOnNextStop is handled centrally in the loop's stop branch
                bool entry = !_attached && addr == EntryPoint && !_seenEntry;
                _seenEntry = true;
                Stopped?.Invoke(new StopInfo(entry ? StopReason.EntryPoint : StopReason.Breakpoint, ev.dwThreadId, addr, code));
                return true;
            }
            // user software breakpoint
            Breakpoint? bp; lock (_lock) _swBps.TryGetValue(addr, out bp);
            if (bp is { Armed: true })
            {
                SetIp(hThread, addr);   // rewind over the 0xCC
                Stopped?.Invoke(new StopInfo(StopReason.Breakpoint, ev.dwThreadId, addr, code));
                return true;
            }
            // first breakpoint(s) = loader/system (or attach-injected). A WOW64 launch delivers both a
            // 64-bit and a 32-bit (STATUS_WX86_BREAKPOINT) system breakpoint, so allow one of each.
            bool isWx86 = code == Native.STATUS_WX86_BREAKPOINT;
            if ((isWx86 && !_seenWx86Bp) || (!isWx86 && !_seenSystemBp))
            {
                if (isWx86) _seenWx86Bp = true; else _seenSystemBp = true;
                if (_attached) { Stopped?.Invoke(new StopInfo(StopReason.Attached, ev.dwThreadId, addr, code)); return true; }
                // Optionally stop at the loader breakpoint of the target's bitness (the matching loader has
                // mapped the modules) instead of skipping to the entry point, so capture can begin earlier.
                if (StopAtLoaderBreakpoint && isWx86 == Is32)
                {
                    RemoveTempBpIfPresent(EntryPoint);   // breaking earlier — drop the redundant entry-point stop
                    _seenEntry = true;
                    Stopped?.Invoke(new StopInfo(StopReason.Breakpoint, ev.dwThreadId, addr, code));
                    return true;
                }
                return false;   // launched: skip past it toward the entry bp
            }
            // A breakpoint exception at an address that is no longer one of ours is a *stale/phantom*
            // breakpoint: the CPU hit our 0xCC, the kernel queued the event, and the breakpoint was removed
            // and its byte restored before we processed the queue (capture teardown, a capture-once entry, or
            // a sibling thread that hit it while it was briefly disarmed for a single-step). RIP is now parked
            // one byte into the restored instruction — rewind over the (now-absent) 0xCC and continue
            // silently, or resuming would execute mid-instruction and fault (0xC0000005). A byte that is still
            // 0xCC is a genuine int3 in the program (e.g. __debugbreak / anti-debug), so leave it to surface.
            var live = ReadMemory(addr, 1);   // active bps were handled above, so this is the true byte
            if (live.Length == 1 && live[0] != 0xCC) { SetIp(hThread, addr); return false; }
            if (_pauseRequested) { _pauseRequested = false; Stopped?.Invoke(new StopInfo(StopReason.Paused, ev.dwThreadId, addr, code)); return true; }
            Stopped?.Invoke(new StopInfo(StopReason.Breakpoint, ev.dwThreadId, addr, code));
            return true;
        }

        if (code is Native.EXCEPTION_SINGLE_STEP or Native.STATUS_WX86_SINGLE_STEP)
        {
            bool stepping = _stepping.TryGetValue(ev.dwThreadId, out var st);
            // Hardware watchpoint? Dr6 low bits identify the slot — but only when THIS thread isn't the one we
            // armed a software single-step on (its trap #DB is indistinguishable from a watchpoint otherwise).
            using (var c = new Ctx(Is32))
            {
                if (c.Get(hThread) && (c.Dr6 & 0xF) != 0 && !stepping)
                {
                    c.Dr6 = 0; c.Set(hThread);
                    Stopped?.Invoke(new StopInfo(StopReason.Watchpoint, ev.dwThreadId, c.Ip, code));
                    return true;
                }
            }
            if (!stepping) return false;   // a single-step we didn't arm for this thread (e.g. debuggee set TF) — keep running
            _stepping.Remove(ev.dwThreadId);
            if (st.ReArm != 0) ArmAddr(st.ReArm);   // re-arm the breakpoint this thread stepped off
            if (st.StopAfter) { Stopped?.Invoke(new StopInfo(StopReason.Step, ev.dwThreadId, CurrentIp(hThread), code)); return true; }
            return false;   // step-off of a breakpoint during a Go — keep running
        }

        // Any other exception (AV, C++ EH, etc.). The filter decides whether to break and whether to pass it
        // to the debuggee's own handler (DBG_EXCEPTION_NOT_HANDLED) or swallow it (DBG_CONTINUE) on resume.
        bool firstChance = ev.Exception.dwFirstChance != 0;
        var (brk, pass) = ExceptionFilter.Decide(code, firstChance);
        cont = pass ? Native.DBG_EXCEPTION_NOT_HANDLED : Native.DBG_CONTINUE;
        if (_pauseRequested || _stopping) return false;
        // While capturing, let the program handle all its own first-chance exceptions without stopping.
        if (PassFirstChanceExceptions && firstChance) return false;
        if (!brk) return false;   // filter: don't break — exception was passed/swallowed per `pass`
        Stopped?.Invoke(new StopInfo(StopReason.Exception, ev.dwThreadId, addr, code));
        return true;
    }

    private bool _seenEntry;
    private bool _seenWx86Bp;

    /// <summary>A debuggee thread's in-flight single-step: the breakpoint to re-arm when its step completes
    /// (0 if none) and whether to surface a Step stop (StepInto/StepOver) vs silently continue (a step-off of
    /// a breakpoint during a Go).</summary>
    private readonly record struct StepState(ulong ReArm, bool StopAfter);

    // ---- resume / stepping (loop thread) ----
    // cont carries the continuation status from HandleEvent: DBG_CONTINUE for our breakpoints/steps, or
    // DBG_EXCEPTION_NOT_HANDLED for a real exception so the debuggee's own handler runs when we resume.
    private void DoResume(ResumeMode mode, ulong target, in Native.DEBUG_EVENT ev, uint cont)
    {
        IntPtr hThread = ThreadHandle(ev.dwThreadId);
        using var c = new Ctx(Is32);
        if (!c.Get(hThread)) { Native.ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, cont); return; }
        ulong ip = c.Ip;
        bool onBp = false; lock (_lock) onBp = _swBps.TryGetValue(ip, out var b) && b.Armed;

        // Skip an execute hardware breakpoint at the current IP for one instruction so it doesn't re-fire.
        bool atExecHw; lock (_lock) atExecHw = _hwBps.Any(b => b.Kind == HwKind.Execute && b.Enabled && b.Address == ip);
        if (atExecHw) { c.ResumeFlag = true; c.Set(hThread); }

        switch (mode)
        {
            case ResumeMode.StepOver when IsCallAt(ip, out int len):
                AddTempBp(ip + (ulong)len);
                if (onBp) { DisarmAddr(ip); _reArmOnNextStop.Add(ip); }
                break;
            case ResumeMode.StepOut:
            {
                ulong ret = FindReturnAddress(c.Sp);
                if (ret != 0) AddTempBp(ret);
                if (onBp) { DisarmAddr(ip); _reArmOnNextStop.Add(ip); }
                break;
            }
            case ResumeMode.RunToCursor:
                AddTempBp(target);
                if (onBp) { DisarmAddr(ip); _reArmOnNextStop.Add(ip); }
                break;
            default: // Go, StepInto, StepOver-of-noncall
            {
                bool single = mode is ResumeMode.StepInto || mode == ResumeMode.StepOver;
                if (onBp) { DisarmAddr(ip); _stepping[ev.dwThreadId] = new StepState(ip, single); c.TrapFlag = true; }
                else if (single) { _stepping[ev.dwThreadId] = new StepState(0, true); c.TrapFlag = true; }
                c.Set(hThread);
                break;
            }
        }
        Native.ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, cont);
    }

    // ---- public commands (UI thread) ----
    public void Go() => _resume.Add((ResumeMode.Go, 0));
    public void StepInto() => _resume.Add((ResumeMode.StepInto, 0));
    public void StepOver() => _resume.Add((ResumeMode.StepOver, 0));
    public void StepOut() => _resume.Add((ResumeMode.StepOut, 0));
    public void RunToCursor(ulong va) => _resume.Add((ResumeMode.RunToCursor, va));
    public void Pause() { _pauseRequested = true; if (_proc != IntPtr.Zero) Native.DebugBreakProcess(_proc); }

    public void Stop()
    {
        _stopping = true;
        if (IsStopped) _resume.Add((ResumeMode.Stop, 0));
        else if (_proc != IntPtr.Zero) { if (_attached) Native.DebugBreakProcess(_proc); else Native.TerminateProcess(_proc, 0); }
    }

    private void DoStop(in Native.DEBUG_EVENT ev)
    {
        if (_attached) { Native.DebugActiveProcessStop(_pid); }
        else { Native.TerminateProcess(_proc, 0); Native.ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, Native.DBG_CONTINUE); }
        _ended = true;
        Exited?.Invoke(0);
    }

    private void Cleanup()
    {
        IsActive = false; IsStopped = false;
        if (_attached && _proc != IntPtr.Zero) { /* detached */ }
    }

    // ---- breakpoints ----
    public void SetBreakpoint(ulong va)
    {
        lock (_lock)
        {
            if (_swBps.ContainsKey(va)) return;
            var bp = new Breakpoint { Address = va };
            _swBps[va] = bp;
            ArmAddr(va);
        }
    }

    /// <summary>
    /// Arm many software breakpoints with page-batched memory access: for thousands of breakpoints
    /// clustered on a few code pages this does one protect-change + read + write + flush per page instead
    /// of per byte (≈5 syscalls per page vs per breakpoint). Must be called while the debuggee is frozen,
    /// as all breakpoint changes must. Addresses already set are skipped.
    /// </summary>
    public void SetBreakpoints(IReadOnlyCollection<ulong> addresses)
    {
        if (_proc == IntPtr.Zero || addresses.Count == 0) return;

        // Register the new breakpoints (skip duplicates) and group them by 4 KiB page.
        var byPage = new Dictionary<ulong, List<ulong>>();
        lock (_lock)
            foreach (var va in addresses)
            {
                if (!_swBps.TryAdd(va, new Breakpoint { Address = va })) continue;
                ulong page = va & ~0xFFFUL;
                if (!byPage.TryGetValue(page, out var list)) { list = []; byPage[page] = list; }
                list.Add(va);
            }

        const int PageSize = 0x1000;
        var buf = new byte[PageSize];
        foreach (var (page, vas) in byPage)
        {
            Native.ReadProcessMemory(_proc, page, buf, (nuint)PageSize, out var read);
            int n = (int)read;
            if (n == 0) { lock (_lock) foreach (var va in vas) _swBps.Remove(va); continue; }

            Native.VirtualProtectEx(_proc, page, (nuint)n, Native.PAGE_EXECUTE_READWRITE, out uint old);
            var originals = new List<(ulong Va, byte Orig)>(vas.Count);
            foreach (var va in vas)
            {
                int off = (int)(va - page);
                if (off >= n) continue;          // in the page's unreadable tail
                originals.Add((va, buf[off]));
                buf[off] = 0xCC;
            }
            Native.WriteProcessMemory(_proc, page, buf, (nuint)n, out _);
            Native.VirtualProtectEx(_proc, page, (nuint)n, old, out _);
            Native.FlushInstructionCache(_proc, page, (nuint)n);

            lock (_lock)
                foreach (var (va, orig) in originals)
                    if (_swBps.TryGetValue(va, out var bp)) { bp.Original = orig; bp.Armed = true; }
        }
    }

    public void RemoveBreakpoint(ulong va)
    {
        lock (_lock)
        {
            // Restore the byte using the removed entry (DisarmAddr re-looks-up _swBps, which is now empty).
            if (_swBps.Remove(va, out var bp) && bp.Armed) WriteCode(va, [bp.Original]);
            var hw = _hwBps.FirstOrDefault(b => b.Address == va);
            if (hw is not null) { _hwBps.Remove(hw); ProgramHwAllThreads(); }
        }
    }

    public bool HasBreakpoint(ulong va) { lock (_lock) return _swBps.ContainsKey(va) || _hwBps.Any(b => b.Address == va); }

    public void SetHardwareBreakpoint(ulong va, HwKind kind, int size)
    {
        lock (_lock)
        {
            var used = _hwBps.Select(b => b.Slot).ToHashSet();
            int slot = Enumerable.Range(0, 4).FirstOrDefault(s => !used.Contains(s), -1);
            if (slot < 0) { Output?.Invoke("All 4 hardware breakpoint slots are in use."); return; }
            _hwBps.Add(new Breakpoint { Address = va, Hardware = true, Kind = kind, Size = size, Slot = slot });
            ProgramHwAllThreads();
        }
    }

    private void ArmAddr(ulong va)
    {
        Breakpoint? bp; lock (_lock) _swBps.TryGetValue(va, out bp);
        if (bp is null || bp.Armed) return;
        var o = ReadMemory(va, 1);
        if (o.Length < 1) return;
        bp.Original = o[0];
        if (WriteCode(va, [0xCC])) bp.Armed = true;
    }

    private void DisarmAddr(ulong va)
    {
        Breakpoint? bp; lock (_lock) _swBps.TryGetValue(va, out bp);
        if (bp is { Armed: true }) { WriteCode(va, [bp.Original]); bp.Armed = false; }
    }

    private void AddTempBp(ulong va)
    {
        lock (_lock)
        {
            if (_tempBps.ContainsKey(va) || _swBps.ContainsKey(va)) return;
            var o = ReadMemory(va, 1);
            if (o.Length < 1) return;
            _tempBps[va] = o[0];
        }
        WriteCode(va, [0xCC]);
    }

    private bool RemoveTempBpIfPresent(ulong va)
    {
        byte orig; lock (_lock) { if (!_tempBps.Remove(va, out orig)) return false; }
        WriteCode(va, [orig]);
        return true;
    }

    private void ProgramHwAllThreads() { lock (_lock) foreach (var h in _threads.Values) ProgramHwForThread(h); }

    private void ProgramHwForThread(IntPtr hThread)
    {
        using var c = new Ctx(Is32);
        if (!c.Get(hThread)) return;
        ulong dr7 = 0;
        var slots = new ulong[4];
        lock (_lock)
            foreach (var bp in _hwBps)
            {
                if (bp.Slot is < 0 or > 3 || !bp.Enabled) continue;
                slots[bp.Slot] = bp.Address;
                dr7 |= 1UL << (bp.Slot * 2);                       // local enable
                int rw = bp.Kind == HwKind.Execute ? 0 : bp.Kind == HwKind.Write ? 1 : 3;
                int len = bp.Size == 8 ? 2 : bp.Size == 4 ? 3 : bp.Size == 2 ? 1 : 0;
                dr7 |= ((ulong)rw << (16 + bp.Slot * 4)) | ((ulong)len << (18 + bp.Slot * 4));
            }
        if (dr7 != 0) dr7 |= 0x100;   // LE (local exact) — recommended for data breakpoints
        for (int i = 0; i < 4; i++) c.SetDr(i, slots[i]);
        c.Dr7 = dr7;
        c.Set(hThread);
    }

    // ---- memory & registers (safe while stopped) ----
    public byte[] ReadMemory(ulong addr, int count)
    {
        if (_proc == IntPtr.Zero || count <= 0) return [];
        var buf = new byte[count];
        Native.ReadProcessMemory(_proc, addr, buf, (nuint)count, out var read);
        if ((int)read != count) Array.Resize(ref buf, (int)read);
        MaskBreakpoints(addr, buf);
        return buf;
    }

    /// <summary>Replace our injected 0xCC breakpoint bytes with the originals so callers (disassembly,
    /// dump, call-stack, step-over) see the program's real bytes rather than the instrumentation.</summary>
    private void MaskBreakpoints(ulong addr, byte[] buf)
    {
        if (buf.Length == 0) return;
        ulong end = addr + (ulong)buf.Length;
        lock (_lock)
        {
            foreach (var bp in _swBps.Values)
                if (bp.Armed && bp.Address >= addr && bp.Address < end) buf[bp.Address - addr] = bp.Original;
            foreach (var kv in _tempBps)
                if (kv.Key >= addr && kv.Key < end) buf[kv.Key - addr] = kv.Value;
        }
    }

    public bool WriteMemory(ulong addr, byte[] bytes) => WriteCode(addr, bytes);

    private bool WriteCode(ulong addr, byte[] bytes)
    {
        if (_proc == IntPtr.Zero) return false;
        Native.VirtualProtectEx(_proc, addr, (nuint)bytes.Length, Native.PAGE_EXECUTE_READWRITE, out uint old);
        bool ok = Native.WriteProcessMemory(_proc, addr, bytes, (nuint)bytes.Length, out _);
        Native.VirtualProtectEx(_proc, addr, (nuint)bytes.Length, old, out _);
        Native.FlushInstructionCache(_proc, addr, (nuint)bytes.Length);
        return ok;
    }

    public RegisterSet? GetRegisters(uint threadId = 0)
    {
        IntPtr h = threadId == 0 ? ThreadHandle(CurrentThreadId) : ThreadHandle(threadId);
        if (h == IntPtr.Zero) return null;
        using var c = new Ctx(Is32);
        return c.Get(h) ? c.Snapshot() : null;
    }

    public void SetRegister(string name, ulong value, uint threadId = 0)
    {
        IntPtr h = threadId == 0 ? ThreadHandle(CurrentThreadId) : ThreadHandle(threadId);
        if (h == IntPtr.Zero) return;
        using var c = new Ctx(Is32);
        if (c.Get(h) && c.TrySetByName(name, value)) c.Set(h);
    }

    public bool IsExecutable(ulong addr)
    {
        if (_proc == IntPtr.Zero) return false;
        if (Native.VirtualQueryEx(_proc, addr, out var mbi, (nuint)System.Runtime.InteropServices.Marshal.SizeOf<Native.MEMORY_BASIC_INFORMATION>()) == 0) return false;
        return mbi.State == Native.MEM_COMMIT && (mbi.Protect & 0xF0) != 0;   // any PAGE_EXECUTE_*
    }

    // ---- helpers ----
    private IntPtr ThreadHandle(uint tid) { lock (_lock) return _threads.TryGetValue(tid, out var h) ? h : IntPtr.Zero; }
    private void SetIp(IntPtr h, ulong ip) { using var c = new Ctx(Is32); if (c.Get(h)) { c.Ip = ip; c.Set(h); } }
    private ulong CurrentIp(IntPtr h) { using var c = new Ctx(Is32); return c.Get(h) ? c.Ip : 0; }

    private bool IsCallAt(ulong ip, out int len)
    {
        len = 1;
        var bytes = ReadMemory(ip, 16);
        if (bytes.Length == 0) return false;
        var dec = Decoder.Create(Is32 ? 32 : 64, new ByteArrayCodeReader(bytes));
        dec.IP = ip;
        dec.Decode(out var instr);
        if (instr.IsInvalid) return false;
        len = instr.Length;
        return instr.FlowControl is FlowControl.Call or FlowControl.IndirectCall;
    }

    /// <summary>Heuristic step-out target: the first stack value that is a return address (executable,
    /// and the bytes just before it decode as a call).</summary>
    /// <summary>True if <paramref name="addr"/> is a plausible return address: executable, with the bytes
    /// just before it decoding as a call that ends exactly there. Used to avoid writing a capture return
    /// breakpoint onto unrelated stack data when a function was reached by a jump rather than a call.</summary>
    public bool IsReturnAddress(ulong addr)
    {
        if (addr == 0 || addr < 16 || !IsExecutable(addr)) return false;
        var pre = ReadMemory(addr - 16, 16);
        return pre.Length == 16 && EndsWithCall(pre, addr);
    }

    private ulong FindReturnAddress(ulong sp)
    {
        var stack = ReadMemory(sp, 0x400);
        int ptr = Is32 ? 4 : 8;
        for (int i = 0; i + ptr <= stack.Length; i += ptr)
        {
            ulong v = ptr == 8 ? BitConverter.ToUInt64(stack, i) : BitConverter.ToUInt32(stack, i);
            if (IsReturnAddress(v)) return v;
        }
        return 0;
    }

    private bool EndsWithCall(byte[] pre, ulong end)
    {
        // try decode positions so that an instruction ends exactly at `end` and is a call
        for (int start = 1; start <= 7; start++)
        {
            var dec = Decoder.Create(Is32 ? 32 : 64, new ByteArrayCodeReader(pre, 16 - start, start));
            dec.IP = end - (ulong)start;
            dec.Decode(out var instr);
            if (!instr.IsInvalid && instr.Length == start && instr.FlowControl is FlowControl.Call or FlowControl.IndirectCall)
                return true;
        }
        return false;
    }

    private string? ModulePath(ulong baseAddr)
    {
        if (_proc == IntPtr.Zero) return null;
        var buf = new char[260];
        uint n = Native.GetModuleFileNameEx(_proc, baseAddr, buf, (uint)buf.Length);
        return n > 0 ? new string(buf, 0, (int)n) : null;
    }
}

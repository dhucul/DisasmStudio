using System.Collections.Concurrent;
using DisasmStudio.Core.Unpacking;
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
public sealed partial class DebuggerEngine
{
    public event Action<StopInfo>? Stopped;
    public event Action? Running;
    /// <summary>Raised immediately after <c>ContinueDebugEvent</c> resumes the target.</summary>
    public event Action? Resumed;
    /// <summary>Raised on EXIT_PROCESS_DEBUG_EVENT before the debug event is continued.</summary>
    public event Action<int>? ProcessExiting;
    public event Action<int>? Exited;
    /// <summary>Raised when the debugger has detached but left the debuggee running (see <see cref="Detach"/>).
    /// Distinct from <see cref="Exited"/> so the UI can report "still running" rather than an exit code.</summary>
    public event Action? Detached;
    public event Action<string>? Output;
    public event Action? ModulesChanged;
    public event Action? ThreadsChanged;

    /// <summary>Raised on the debug-loop thread for every real exception (AV / illegal / etc.; not our own
    /// breakpoints or single-steps), before the break/pass decision — so a caller can localize a fault even
    /// when first-chance exceptions are being passed straight to the program (capture/unpack mode).</summary>
    public event Action<ExceptionEvent>? ExceptionObserved;

    /// <summary>Raised on the debug-loop thread when the target DLL (hosted in an EXE) is mapped — i.e. when
    /// <see cref="ImageBase"/> becomes the DLL's real base. Lets the UI build the rebased live analysis with
    /// the correct slide, since for a hosted DLL the launched process is the host, not the debugged module.</summary>
    public event Action? TargetLoaded;

    private Thread? _thread;
    private string? _launchPath;
    private uint _attachPid;
    private bool _attached;

    // ---- hosting a DLL: launch a host EXE (rundll32 / custom) that LoadLibrary's the target DLL ----
    private bool _hostingDll;
    private string? _hostExe, _hostCmdLine, _hostWorkingDir;
    private string? _targetDllPath;   // Path.GetFullPath of the DLL; path fallback when file identity is unavailable
    private (uint Vol, uint Hi, uint Lo)? _targetFileId;   // authoritative match: volume serial + file index
    private uint _breakRva;           // DllMain RVA, else the chosen export RVA, else 0 (stop at the load event)
    private bool _breakIsEntry;       // the hosted break is the DLL entry (DllMain) → EntryPoint reason; an export → Breakpoint
    private bool _targetLoaded;

    private IntPtr _proc;
    private uint _pid;
    private bool _useJob;
    private IntPtr _job;
    public bool Is32 { get; private set; }
    public ulong ImageBase { get; private set; }
    public ulong EntryPoint { get; private set; }
    public IntPtr ProcessHandle => _proc;
    public bool IsActive { get; private set; }
    public bool IsStopped { get => _isStopped; private set => _isStopped = value; }   // read on the UI thread
    private volatile bool _isStopped;
    public uint CurrentThreadId { get; private set; }

    /// <summary>When set (during capture), first-chance exceptions are passed to the debuggee's own
    /// handlers without stopping; only a second-chance (fatal/unhandled) exception surfaces.</summary>
    public bool PassFirstChanceExceptions { get => _passFirstChance; set => _passFirstChance = value; }   // cross-thread
    private volatile bool _passFirstChance;

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
    private readonly Dictionary<ulong, byte> _coverageBps = [];   // one-shot silent BPs at block leaders (execution coverage)
    private readonly HashSet<ulong> _coveredPoints = [];          // executed points that have fired — block leaders (coverage) or instructions (trace), live VAs
    private volatile bool _clearCoverageRequested;               // UI asked to stop tracing while running; honoured at the next event

    // ---- instruction trace (single-step the loaded module; run through foreign code) ----
    private volatile bool _traceMode;                 // instruction trace active: single-step + record each executed instruction
    private volatile bool _clearTraceRequested;       // UI asked to stop the trace while running; honoured at the next event
    private ulong _traceLo, _traceHi;                 // [lo, hi): the loaded module's VA span — single-step inside it, run through outside
    private readonly Dictionary<uint, ulong> _traceStep = [];        // thread -> user bp disarmed to take its trace step (0 = none)
    private readonly Dictionary<ulong, byte> _traceResumeBps = [];   // run-through return addrs; on hit, silently resume tracing

    private readonly BlockingCollection<(ResumeMode Mode, ulong Target)> _resume = new();
    private readonly Queue<ulong[]> _runToAnyTargets = new();

    // Step state (loop-thread only) — keyed by debuggee thread id. A multi-threaded debuggee can have several
    // threads each mid single-step at once (e.g. each stepping off a breakpoint during a Go), so this must not
    // be a single global, or one thread's step event clobbers/cross-attributes another's → a breakpoint left
    // un-rearmed (lost) or a stray 0xCC / misclassified stop.
    private readonly Dictionary<uint, StepState> _stepping = [];   // thread -> in-flight single-step
    private readonly HashSet<ulong> _reArmOnNextStop = [];         // bps disarmed for step-over/out/run-to, re-armed on the next stop
    private readonly Dictionary<ulong, uint> _guarded = [];        // execute-stripped page -> original protect (unpacker OEP catch)
    private bool _seenSystemBp;
    private volatile bool _pauseRequested;   // set by the UI thread (Pause), read by the debug loop
    private volatile bool _breakinPending;   // a deliberate DebugBreakProcess (Pause) is in flight; its int3 must be consumed once
    private volatile bool _stopping;         // set by the UI thread (Stop), read by the debug loop
    private volatile bool _detaching;        // set by the UI thread (Detach), read by the debug loop
    private bool _ended;

    public IReadOnlyList<ModuleInfo> Modules { get { lock (_lock) return _modules.Values.OrderBy(m => m.Base).ToList(); } }
    public IReadOnlyList<ThreadInfo> Threads { get { lock (_lock) return _threads.Keys.Select(id => new ThreadInfo(id, 0)).ToList(); } }
    public IReadOnlyList<Breakpoint> BreakpointList { get { lock (_lock) return _swBps.Values.Concat(_hwBps).ToList(); } }

    /// <summary>Before launching, request that the debuggee be placed in a Win32 job object with kill-on-close
    /// and a one-process limit (blocks child-process spawning). This is process-level containment only — it does
    /// NOT isolate network or filesystem access; use a VM for truly untrusted samples.</summary>
    public void EnableJobContainment() => _useJob = true;

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

    /// <summary>Launch <paramref name="hostExe"/> (rundll32 or a custom host) under the debugger so it loads
    /// the target DLL. When the DLL maps, <see cref="ImageBase"/>/<see cref="EntryPoint"/> are set to the
    /// DLL (not the host) and a temporary breakpoint is planted at <paramref name="breakRva"/> (the DLL's
    /// DllMain, or a chosen export), so the first stop is inside the DLL. <paramref name="breakRva"/> of 0
    /// (no DllMain / no chosen export) stops at the load event instead. <paramref name="breakIsEntry"/> is
    /// true when the break is the DLL entry (DllMain) — it then surfaces as <see cref="StopReason.EntryPoint"/>;
    /// a break at a chosen export surfaces as a normal <see cref="StopReason.Breakpoint"/>.</summary>
    public void LaunchHostingDll(string hostExe, string commandLine, string? workingDir,
                                 string targetDllPath, uint breakRva, bool breakIsEntry)
    {
        _hostExe = hostExe; _hostCmdLine = commandLine; _hostWorkingDir = workingDir;
        _targetDllPath = SafeFullPath(targetDllPath);
        _targetFileId = FileIdentityOfPath(_targetDllPath);
        _breakRva = breakRva; _breakIsEntry = breakIsEntry; _hostingDll = true; _attached = false;
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
        // Hosting a DLL: run the host EXE with the composed command line (which already starts with argv0, as
        // CreateProcessW requires when lpApplicationName is set). Otherwise launch the target path directly.
        string? appName = _hostingDll ? _hostExe        : _launchPath;
        string? cmdLine = _hostingDll ? _hostCmdLine    : null;
        string? workDir = _hostingDll ? _hostWorkingDir : null;
        uint baseFlags = Native.DEBUG_ONLY_THIS_PROCESS | Native.CREATE_NEW_CONSOLE;
        // To job-contain the target we must first pull it out of any job the host itself was launched into
        // (Windows Terminal, a CI runner, VS, …), since such a job usually forbids nesting ours — the later
        // AssignProcessToJobObject would fail with ERROR_ACCESS_DENIED. CREATE_BREAKAWAY_FROM_JOB breaks the
        // child out, but only if the host's job permits breakaway; if it doesn't, CreateProcess itself fails
        // with ERROR_ACCESS_DENIED, so we fall back to a normal, uncontained launch. (When the host is in no
        // job, the flag is simply ignored.)
        bool wantBreakaway = _useJob;
        uint flags = baseFlags | (wantBreakaway ? Native.CREATE_BREAKAWAY_FROM_JOB : 0);
        bool ok = Native.CreateProcessW(appName, cmdLine, IntPtr.Zero, IntPtr.Zero, false,
            flags, IntPtr.Zero, workDir, ref si, out var pi);
        if (!ok && wantBreakaway && Marshal_LastError() == 5)   // ERROR_ACCESS_DENIED: host job forbids breakaway
        {
            _useJob = false;   // can't contain in this environment — don't bother trying to assign a job later
            Output?.Invoke("Job containment: the host's job forbids breakaway; launching without containment.");
            ok = Native.CreateProcessW(appName, cmdLine, IntPtr.Zero, IntPtr.Zero, false,
                baseFlags, IntPtr.Zero, workDir, ref si, out pi);
        }
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
                if (mode == ResumeMode.Detach) { DoDetach(); break; }
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
                if (_useJob) TrySetupJob();
                Native.IsWow64Process(_proc, out bool wow);
                Is32 = wow;   // host bitness == DLL bitness (rundll32 is bitness-matched), so this is correct
                lock (_lock) _threads[ev.dwThreadId] = info.hThread;
                if (!_hostingDll)
                {
                    ImageBase = info.lpBaseOfImage;
                    EntryPoint = info.lpStartAddress;
                    lock (_lock) _modules[ImageBase] = new ModuleInfo(ImageBase, ModulePath(ImageBase) ?? _launchPath ?? "(target)");
                    if (!_attached) AddTempBp(EntryPoint);   // launched: break at the entry point
                }
                else
                {
                    // The launched process is the HOST, not the debugged module: record it but leave ImageBase
                    // (and the entry breakpoint) for the target DLL's LOAD_DLL event below.
                    ulong hb = info.lpBaseOfImage;
                    lock (_lock) _modules[hb] = new ModuleInfo(hb, ModulePath(hb) ?? _hostExe ?? "(host)");
                }
                ThreadsChanged?.Invoke(); ModulesChanged?.Invoke();
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
                // Resolve the path from the event's file handle: at LOAD_DLL time the loader hasn't registered
                // the module yet, so GetModuleFileNameEx usually returns null here (use it only as a fallback).
                string? path = PathFromFileHandle(ev.LoadDll.hFile) ?? ModulePath(b);
                lock (_lock) _modules[b] = new ModuleInfo(b, path ?? $"module_{b:X}");
                ModulesChanged?.Invoke();

                // Anti-anti-debug: if user32 maps after the loader breakpoint (e.g. a packer's runtime
                // LoadLibrary), arm the FindWindow* hooks now that it's present.
                if (HideFromDebugger && _adApplied && HideUseApiHooks) TryInstallWindowHooks();

                // Hosting a DLL: when the target maps, treat it as the debugged module — set ImageBase/EntryPoint
                // to the DLL (so the live view rebases by the DLL's real ASLR slide) and break at DllMain.
                bool matched = _hostingDll && !_targetLoaded && IsTargetModule(ev.LoadDll.hFile, path);
                if (ev.LoadDll.hFile != IntPtr.Zero) Native.CloseHandle(ev.LoadDll.hFile);   // close after using it
                if (matched)
                {
                    _targetLoaded = true;
                    ImageBase = b;
                    ulong entry = _breakRva != 0 ? b + _breakRva : 0;
                    EntryPoint = entry;
                    TargetLoaded?.Invoke();   // bridge builds the rebased live analysis now ImageBase is the DLL
                    if (entry != 0) { AddTempBp(entry); return false; }   // run on; stop AT DllMain when it's reached
                    // No DllMain and no chosen export: stop right here so the user can set breakpoints and Go.
                    Stopped?.Invoke(new StopInfo(StopReason.Breakpoint, ev.dwThreadId, b, 0));
                    return true;
                }
                return false;
            }
            case Native.UNLOAD_DLL_DEBUG_EVENT:
                lock (_lock) _modules.Remove(ev.UnloadDll.lpBaseOfDll);
                ModulesChanged?.Invoke();
                return false;
            case Native.OUTPUT_DEBUG_STRING_EVENT:
                return false;
            case Native.EXIT_PROCESS_DEBUG_EVENT:
                if (_hostingDll && !_targetLoaded)
                    Output?.Invoke("Target DLL was never loaded by the host (wrong-bitness rundll32, bad path, or the host didn't load it).");
                ProcessExiting?.Invoke((int)ev.ExitProcess.dwExitCode);
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
            // anti-anti-debug return-patch landing (scrub Dr regs from a NtGetContextThread result) — silent
            if (_pendingReturns.ContainsKey(addr)) { HandleReturnHook(addr, hThread); return false; }
            // internal anti-anti-debug hook (ntdll query emulation) — handled silently, never surfaced
            if (_internalBps.ContainsKey(addr)) { HandleAntiDebugHook(addr, ev.dwThreadId, hThread); return false; }
            // instruction-trace run-through: the return from foreign (system-DLL) code we ran at full speed.
            // Restore the byte, rewind over the 0xCC, record the landing, and resume single-step tracing — silently.
            if (_traceResumeBps.ContainsKey(addr)) { HandleTraceResume(addr, ev.dwThreadId, hThread); return false; }
            // execution-coverage one-shot: record the block leader and drop its entry. If a temp or user
            // breakpoint also sits here (e.g. a ret that is both a block leader and a "Continue to return"
            // target), leave the 0xCC and fall through so that stop still surfaces below; otherwise restore the
            // byte, rewind over the 0xCC, and continue silently — so a covered block costs nothing on re-entry.
            if (_coverageBps.ContainsKey(addr))
            {
                byte covOrig; bool otherBp;
                lock (_lock)
                {
                    _coverageBps.Remove(addr, out covOrig);
                    _coveredPoints.Add(addr);
                    otherBp = _tempBps.ContainsKey(addr) || (_swBps.TryGetValue(addr, out var ub) && ub.Armed);
                }
                // "Stop trace" while running: the process is frozen on this event, so remove every remaining
                // coverage breakpoint now (safe — single-threaded w.r.t. the debug loop) and the program then
                // runs clean at full speed. Driven off a coverage hit because the target is actively taking them.
                if (_clearCoverageRequested) { _clearCoverageRequested = false; ClearCoverage(); }
                if (!otherBp) { WriteCode(addr, [covOrig]); SetIp(hThread, addr); return false; }
            }
            // temp / one-shot breakpoint
            if (RemoveTempBpIfPresent(addr))
            {
                RemoveAllTempBps();
                SetIp(hThread, addr);   // _reArmOnNextStop is handled centrally in the loop's stop branch
                // EntryPoint reason for a launched EXE's entry or a hosted DLL's DllMain; a hosted break planted
                // at a chosen export (breakIsEntry == false) is a normal Breakpoint.
                bool entry = !_attached && addr == EntryPoint && !_seenEntry && (!_hostingDll || _breakIsEntry);
                _seenEntry = true;
                // Phase-2 anti-debug hooks: kernelbase/kernel32/user32 are now fully initialized — install them.
                if (HideFromDebugger && _adApplied && HideUseApiHooks) TryInstallLateHooks();
                Stopped?.Invoke(new StopInfo(entry ? StopReason.EntryPoint : StopReason.Breakpoint, ev.dwThreadId, addr, code));
                return true;
            }
            // user software breakpoint
            Breakpoint? bp; lock (_lock) _swBps.TryGetValue(addr, out bp);
            if (bp is { Armed: true })
            {
                SetIp(hThread, addr);   // rewind over the 0xCC (registers now valid for condition eval)
                if (ShouldStop(bp, ev.dwThreadId))
                {
                    Stopped?.Invoke(new StopInfo(StopReason.Breakpoint, ev.dwThreadId, addr, code));
                    return true;
                }
                // condition / hit-count not met: step off the 0xCC and keep running, without surfacing a stop
                SilentStepOff(ev.dwThreadId, hThread, addr);
                return false;
            }
            // first breakpoint(s) = loader/system (or attach-injected). A WOW64 launch delivers both a
            // 64-bit and a 32-bit (STATUS_WX86_BREAKPOINT) system breakpoint, so allow one of each.
            bool isWx86 = code == Native.STATUS_WX86_BREAKPOINT;
            if ((isWx86 && !_seenWx86Bp) || (!isWx86 && !_seenSystemBp))
            {
                if (isWx86) _seenWx86Bp = true; else _seenSystemBp = true;
                // Install anti-anti-debug at the loader breakpoint of the target's bitness — early enough to
                // beat the program's own anti-debug (TLS callbacks / entry run after this), and late enough
                // that the PEB and the matching-bitness ntdll are mapped.
                if (HideFromDebugger && !_adApplied && isWx86 == Is32) { ApplyAntiAntiDebug(); _adApplied = true; }
                if (_attached) { Stopped?.Invoke(new StopInfo(StopReason.Attached, ev.dwThreadId, addr, code)); return true; }
                // Optionally stop at the loader breakpoint of the target's bitness (the matching loader has
                // mapped the modules) instead of skipping to the entry point, so capture can begin earlier.
                // When hosting a DLL the target isn't mapped yet (ImageBase is still 0), so always run on to
                // the DLL's LOAD_DLL/DllMain stop rather than surfacing the host's loader breakpoint.
                if (StopAtLoaderBreakpoint && !_hostingDll && isWx86 == Is32)
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
            if (live.Length == 1 && live[0] != 0xCC)
            {
                // Anti-debug instruction (int 2Dh / 2-byte int3) whose exception we'd otherwise swallow: when
                // hiding, deliver it to the program's own handler so it behaves as if undebugged.
                if (HideFromDebugger && IsProgramDebugInstruction(addr, step: false)) { cont = Native.DBG_EXCEPTION_NOT_HANDLED; return false; }
                SetIp(hThread, addr); return false;   // stale phantom: rewind over the absent 0xCC and continue
            }
            // Our own deliberate breakin from Pause(): consume it exactly once. If the pause was already surfaced
            // elsewhere (a trace single-step on another thread consumed _pauseRequested first), this leftover int3
            // would otherwise show up as a spurious Breakpoint in ntdll — swallow it. Gated on _breakinPending so a
            // program's own __debugbreak is untouched, and handled before HideFromDebugger since this int3 is ours.
            if (_breakinPending)
            {
                _breakinPending = false;
                if (_pauseRequested) { _pauseRequested = false; Stopped?.Invoke(new StopInfo(StopReason.Paused, ev.dwThreadId, addr, code)); return true; }
                return false;   // pause already surfaced — drop the duplicate breakin
            }
            // A genuine int3 in the program (__debugbreak / anti-debug). When hiding, pass it to the program's
            // SEH (no-debugger behaviour) instead of surfacing it.
            if (HideFromDebugger) { cont = Native.DBG_EXCEPTION_NOT_HANDLED; return false; }
            if (_pauseRequested) { _pauseRequested = false; Stopped?.Invoke(new StopInfo(StopReason.Paused, ev.dwThreadId, addr, code)); return true; }
            Stopped?.Invoke(new StopInfo(StopReason.Breakpoint, ev.dwThreadId, addr, code));
            return true;
        }

        if (code is Native.EXCEPTION_SINGLE_STEP or Native.STATUS_WX86_SINGLE_STEP)
        {
            // SMC write-step: a single-step we armed (in SmcHandleWriteFault) to let a write complete through a
            // write-protected code page. Re-arm the page's breakpoints and re-apply write-protection. This must
            // run BEFORE the internal-step and !stepping handling below: the SMC trap flag is armed directly,
            // without a StepState, so a write-step during a Go has stepping == false and would otherwise be
            // misclassified as a single-step we didn't arm and silently dropped, leaving every breakpoint on
            // the page disarmed, the page never re-protected, and _pendingGuardReeval/_guardDisarmedByPage leaked.
            // SmcHandleWriteStep is a no-op (returns false) when this thread has no pending write-fault re-eval,
            // so it is safe to consult first on every single-step event.
            bool smcStep = SmcHandleWriteStep(ev.dwThreadId, out _);

            // A step armed only to run one instruction off an internal anti-debug hook, then re-arm it.
            if (_internalStep.Remove(ev.dwThreadId, out ulong isAddr))
            {
                ArmInternal(isAddr);
                if (!_stepping.ContainsKey(ev.dwThreadId)) return false;
            }
            bool tracing = _traceStep.ContainsKey(ev.dwThreadId);
            bool stepping = _stepping.TryGetValue(ev.dwThreadId, out var st) || tracing;   // a trace step is a step too (not a watchpoint)
            // Hardware watchpoint? Dr6 low bits identify the slot — but only when THIS thread isn't the one we
            // armed a software single-step on (its trap #DB is indistinguishable from a watchpoint otherwise), nor the one completing an SMC guard-step (same trap-flag #DB).
            using (var c = new Ctx(Is32))
            {
                if (c.Get(hThread) && (c.Dr6 & 0xF) != 0 && !stepping && !smcStep)
                {
                    int slot = System.Numerics.BitOperations.TrailingZeroCount(c.Dr6 & 0xF);
                    Breakpoint? hb; lock (_lock) hb = _hwBps.FirstOrDefault(b => b.Slot == slot);
                    c.Dr6 = 0;
                    if (hb is null || ShouldStop(hb, ev.dwThreadId))
                    {
                        c.Set(hThread);
                        Stopped?.Invoke(new StopInfo(StopReason.Watchpoint, ev.dwThreadId, c.Ip, code));
                        return true;
                    }
                    // condition / hit-count not met: keep running. An execute hw bp would re-fire on this same
                    // instruction, so set the Resume Flag to skip it for one instruction.
                    if (hb.Kind == HwKind.Execute) c.ResumeFlag = true;
                    c.Set(hThread);
                    return false;
                }
            }
            if (!stepping)
            {
                if (smcStep) return false;   // SMC guard-step during a Go: keep running (breakpoints re-armed above)
                // ICEBP/int1 (or a debuggee-set trap flag) anti-debug: when hiding, deliver to the program's
                // handler instead of swallowing, so its single-step SEH fires as if undebugged.
                if (HideFromDebugger && IsProgramDebugInstruction(addr, step: true)) { cont = Native.DBG_EXCEPTION_NOT_HANDLED; return false; }
                return false;   // a single-step we didn't arm for this thread (e.g. debuggee set TF) — keep running
            }
            if (tracing) return HandleTraceStep(ev, hThread, ref cont);   // continuous instruction trace: record + re-step
            _stepping.Remove(ev.dwThreadId);
            // A write-step can coincide with a user single-step when the stepped instruction itself wrote to a
            // write-protected page: SmcHandleWriteStep already re-armed the page's breakpoints, so ArmAddr below
            // is a harmless no-op for any it already armed, and the user's StopAfter is still honored.
            if (st.ReArm != 0) ArmAddr(st.ReArm);   // re-arm the breakpoint this thread stepped off
            if (st.StopAfter) { Stopped?.Invoke(new StopInfo(StopReason.Step, ev.dwThreadId, CurrentIp(hThread), code)); return true; }
            return false;   // step-off of a breakpoint during a Go — keep running
        }

        // Self-modifying-code: a write (Info0 == 1) landed on a code page we write-protected for breakpoint
        // resilience. Restore write, let it complete (single-step), then re-evaluate breakpoints on that page.
        // SmcHandleWriteFault returns false for a write to any page that isn't ours, so a genuine program
        // access violation falls through to normal reporting below.
        if (code == Native.EXCEPTION_ACCESS_VIOLATION && er.Info0 == 1 && SmcTrackingEnabled)
        {
            if (SmcHandleWriteFault(ev.dwThreadId, er.Info1, ref cont))
                return false;
        }

        // A guard-page violation (we no longer use PAGE_GUARD ourselves; the OEP catch uses NX): e.g. a stack
        // auto-grow, or a program that uses PAGE_GUARD itself. Hand it to the program silently.
        if (code == Native.STATUS_GUARD_PAGE_VIOLATION)
        {
            cont = Native.DBG_EXCEPTION_NOT_HANDLED;
            return false;
        }

        // NX/DEP execute fault while section guards are armed: a code fetch landed in a guarded (originally
        // non-stub) section we made non-executable → the OEP. Info0 == 8 marks an execute access; Info1 is the
        // faulting VA, which equals the IP (== ExceptionAddress) for an execute fault. GuardRegion strips
        // execute (rather than PAGE_GUARDing) so the stub decompresses freely and only the OEP code fetch
        // faults — no per-write fault storm. Checked before the generic filter so PassFirstChanceExceptions
        // doesn't swallow it.
        if (code == Native.EXCEPTION_ACCESS_VIOLATION && er.Info0 == 8)
        {
            ulong ipPage = er.ExceptionAddress & ~0xFFFUL;
            bool ipGuarded; lock (_lock) ipGuarded = _guarded.Count > 0 && _guarded.ContainsKey(ipPage);
            if (ipGuarded)
            {
                ClearGuards();   // execution reached a guarded (originally non-stub) page → OEP candidate
                Stopped?.Invoke(new StopInfo(StopReason.GuardExec, ev.dwThreadId, er.ExceptionAddress, code));
                return true;
            }
        }

        // Anti-anti-debug: the "close an invalid handle" trick raises STATUS_INVALID_HANDLE only under a
        // debugger. Swallow it (continue as handled) so the program's __except never fires — exactly the
        // no-debugger behaviour, where closing a bad handle is silent.
        if (HideFromDebugger && code == 0xC0000008) { cont = Native.DBG_CONTINUE; return false; }

        // The CLR's debugger-notification exception (raised by every .NET process that runs under a native
        // debugger, on every managed module/class load). It carries no fault — it exists only to notify a
        // managed-aware debugger, which we aren't. Swallow it (continue as handled) and never surface it, or a
        // .NET target halts on the first one and can't run. Handled here, before the generic filter, so the fix
        // holds regardless of any persisted exception policy.
        if (code == Native.DBG_COMPLUS_NOTIFICATION) { cont = Native.DBG_CONTINUE; return false; }

        // Any other exception (AV, C++ EH, etc.). The filter decides whether to break and whether to pass it
        // to the debuggee's own handler (DBG_EXCEPTION_NOT_HANDLED) or swallow it (DBG_CONTINUE) on resume.
        bool firstChance = ev.Exception.dwFirstChance != 0;
        bool isAv = code == Native.EXCEPTION_ACCESS_VIOLATION;
        ExceptionObserved?.Invoke(new ExceptionEvent(code, addr, firstChance, ev.dwThreadId,
            isAv ? (int)er.Info0 : -1, isAv ? er.Info1 : 0));
        var (brk, pass) = ExceptionFilter.Decide(code, firstChance);
        cont = pass ? Native.DBG_EXCEPTION_NOT_HANDLED : Native.DBG_CONTINUE;
        if (_pauseRequested || _stopping || _detaching) return false;
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
        if (!c.Get(hThread))
        {
            Native.ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, cont);
            Resumed?.Invoke();
            return;
        }
        ulong ip = c.Ip;
        uint tid = ev.dwThreadId;
        bool onBp = false; lock (_lock) onBp = _swBps.TryGetValue(ip, out var b) && b.Armed;

        void SingleStepFallback()
        {
            if (onBp)
            {
                DisarmAddr(ip);
                _stepping[tid] = new StepState(ip, true);
            }
            else
            {
                _stepping[tid] = new StepState(0, true);
            }
            c.TrapFlag = true;
            c.Set(hThread);
        }

        // Skip an execute hardware breakpoint at the current IP for one instruction so it doesn't re-fire.
        bool atExecHw; lock (_lock) atExecHw = _hwBps.Any(b => b.Kind == HwKind.Execute && b.Enabled && b.Address == ip);
        if (atExecHw) { c.ResumeFlag = true; c.Set(hThread); }

        switch (mode)
        {
            case ResumeMode.StepOver when IsCallAt(ip, out int len):
                if (AddTempBp(ip + (ulong)len))
                {
                    if (onBp) { DisarmAddr(ip); _reArmOnNextStop.Add(ip); }
                }
                else SingleStepFallback();
                break;
            case ResumeMode.StepOut:
            {
                ulong ret = FindReturnAddress(c.Sp);
                if (ret != 0 && AddTempBp(ret))
                {
                    if (onBp) { DisarmAddr(ip); _reArmOnNextStop.Add(ip); }
                }
                else SingleStepFallback();
                break;
            }
            case ResumeMode.RunToCursor:
                if (AddTempBp(target))
                {
                    if (onBp) { DisarmAddr(ip); _reArmOnNextStop.Add(ip); }
                }
                else SingleStepFallback();
                break;
            case ResumeMode.RunToAny:
            {
                ulong[] targets;
                lock (_lock) targets = _runToAnyTargets.Count > 0 ? _runToAnyTargets.Dequeue() : [];
                bool armed = false;
                foreach (ulong t in targets.Where(t => t != 0).Distinct())
                    armed |= AddTempBp(t);
                if (armed)
                {
                    if (onBp) { DisarmAddr(ip); _reArmOnNextStop.Add(ip); }
                }
                else SingleStepFallback();
                break;
            }
            default: // Go, StepInto, StepOver-of-noncall
            {
                bool single = mode is ResumeMode.StepInto || mode == ResumeMode.StepOver;
                if (_traceMode && mode == ResumeMode.Go)
                {
                    // Instruction trace: record the instruction we're on and single-step. The continuous trace is
                    // then driven entirely from the EXCEPTION_SINGLE_STEP handler (HandleTraceStep), which records
                    // each instruction and re-arms the trap flag without surfacing a UI stop.
                    if (ip >= _traceLo && ip < _traceHi) lock (_lock) _coveredPoints.Add(ip);
                    if (onBp) DisarmAddr(ip);   // step off the user bp; re-armed when this trace step completes
                    _traceStep[tid] = onBp ? ip : 0;
                    c.TrapFlag = true;
                }
                else if (onBp) { DisarmAddr(ip); _stepping[tid] = new StepState(ip, single); c.TrapFlag = true; }
                else if (single) { _stepping[tid] = new StepState(0, true); c.TrapFlag = true; }
                c.Set(hThread);
                break;
            }
        }
        Native.ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, cont);
        Resumed?.Invoke();
    }

    // ---- public commands (UI thread) ----
    public void Go() => _resume.Add((ResumeMode.Go, 0));
    public void StepInto() => _resume.Add((ResumeMode.StepInto, 0));
    public void StepOver() => _resume.Add((ResumeMode.StepOver, 0));
    public void StepOut() => _resume.Add((ResumeMode.StepOut, 0));
    public void RunToCursor(ulong va) => _resume.Add((ResumeMode.RunToCursor, va));
    public void RunToAny(IEnumerable<ulong> targets)
    {
        ulong[] copy = targets.Where(t => t != 0).Distinct().ToArray();
        lock (_lock) _runToAnyTargets.Enqueue(copy);
        _resume.Add((ResumeMode.RunToAny, 0));
    }
    public void Pause() { _pauseRequested = true; if (_proc != IntPtr.Zero) { _breakinPending = true; Native.DebugBreakProcess(_proc); } }

    public void Stop()
    {
        _stopping = true;
        if (IsStopped) _resume.Add((ResumeMode.Stop, 0));
        else if (_proc != IntPtr.Zero) { if (_attached) Native.DebugBreakProcess(_proc); else Native.TerminateProcess(_proc, 0); }
    }

    private void DoStop(in Native.DEBUG_EVENT ev)
    {
        if (_attached)
        {
            // Attached targets are left running on Stop (we didn't create them), so this is really a detach:
            // strip our instrumentation first or a leftover 0xCC / kill-on-close job would crash or kill the
            // process. Same cleanup as Detach; the threads are frozen here (outstanding event), so it is safe.
            RestoreAllInstrumentation();
            ReleaseJob();
            Native.DebugActiveProcessStop(_pid);
        }
        else { Native.TerminateProcess(_proc, 0); Native.ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, Native.DBG_CONTINUE); }
        _ended = true;
        Exited?.Invoke(0);
    }

    /// <summary>Detach the debugger but leave the debuggee running. Only valid from a clean stop (the loop is
    /// blocked on <see cref="_resume"/>, so memory edits are safe). Restores every byte we wrote (breakpoints +
    /// hide-layer hooks/rdtsc patches) and clears the debug registers so the program runs exactly as if it had
    /// never been debugged; drops our job's kill-on-close so closing the handle in <see cref="Cleanup"/> can't
    /// kill the survivor; turns off kill-on-debugger-exit (a launched debuggee is otherwise killed when we stop
    /// debugging); then <c>DebugActiveProcessStop</c>. Mirrors <see cref="DoStop"/> but never terminates.</summary>
    public void Detach()
    {
        if (_ended || !IsStopped) return;   // only from a stop; the UI gates the button on IsStopped too
        _detaching = true;
        _resume.Add((ResumeMode.Detach, 0));
    }

    private void DoDetach()
    {
        RestoreAllInstrumentation();
        ReleaseJob();
        Native.DebugSetProcessKillOnExit(false);
        Native.DebugActiveProcessStop(_pid);
        _ended = true;
        Detached?.Invoke();
    }

    /// <summary>Strip all instrumentation we wrote into the debuggee so it runs clean after a detach: restore the
    /// saved original byte of every software int3 (user, temp, anti-debug/rdtsc hooks, return patches) and zero
    /// the debug registers on every thread. Safe only while stopped (single-threaded w.r.t. the debug loop).</summary>
    private void RestoreAllInstrumentation()
    {
        SmcCleanup();
        lock (_lock)
        {
            foreach (var bp in _swBps.Values) if (bp.Armed) WriteCode(bp.Address, [bp.Original]);
            _swBps.Clear();
            foreach (var (va, orig) in _tempBps) WriteCode(va, [orig]);
            _tempBps.Clear();
            foreach (var (va, orig) in _coverageBps) WriteCode(va, [orig]);   // else a detached survivor keeps our 0xCCs and crashes
            _coverageBps.Clear();
            foreach (var (va, orig) in _traceResumeBps) WriteCode(va, [orig]);   // run-through return bps (if any survived a stop)
            _traceResumeBps.Clear();
            _coveredPoints.Clear();
            foreach (var (va, bp) in _internalBps) WriteCode(va, [bp.Original]);
            _internalBps.Clear();
            foreach (var (va, pend) in _pendingReturns) WriteCode(va, [pend.Orig]);
            _pendingReturns.Clear();
            _hwBps.Clear();
        }
        ProgramHwAllThreads();   // _hwBps now empty -> writes a zeroed Dr0-3/Dr7 to each thread
    }

    /// <summary>Before a detach, clear our job's limits so the survivor isn't killed (kill-on-close) or
    /// restricted (active-process limit blocks child spawning) once we close the handle. No-op if we never
    /// created a job (uncontained, or contained by the host's job, which we don't own and can't relax).</summary>
    private void ReleaseJob()
    {
        if (_job == IntPtr.Zero) return;
        var info = new Native.JOBOBJECT_EXTENDED_LIMIT_INFORMATION();
        info.BasicLimitInformation.LimitFlags = 0;   // drop kill-on-close AND the child-process block: run free
        uint sz = (uint)System.Runtime.InteropServices.Marshal.SizeOf<Native.JOBOBJECT_EXTENDED_LIMIT_INFORMATION>();
        Native.SetInformationJobObject(_job, Native.JobObjectExtendedLimitInformation, ref info, sz);
    }

    private void Cleanup()
    {
        IsActive = false; IsStopped = false;
        // Release the OS handles the debug events handed us: any thread handles still open (threads that never
        // delivered EXIT_THREAD because the process was terminated) and the process handle itself.
        lock (_lock) { foreach (var h in _threads.Values) Native.CloseHandle(h); _threads.Clear(); }
        if (_proc != IntPtr.Zero) { Native.CloseHandle(_proc); _proc = IntPtr.Zero; }
        // Closing the job kills any survivors (kill-on-close), so the contained sample can't outlive the session.
        if (_job != IntPtr.Zero) { Native.CloseHandle(_job); _job = IntPtr.Zero; }
    }

    /// <summary>Create a job object (kill-on-close + one active process) and assign the debuggee to it.
    /// Best-effort: failures are reported but do not abort the launch. If the process is already in a
    /// job (e.g. the host terminal's) and can't be moved, that's still acceptable — it's already
    /// contained by the host's job; we note it and drop our own (now-unused) job handle.</summary>
    private void TrySetupJob()
    {
        // Is the process already in a job (e.g. launched by Windows Terminal/VS)? If so, it's already
        // contained and we cannot re-assign it. Err 5 (ACCESS_DENIED) from AssignProcessToJobObject is a
        // reliable "already in a job" signal; we check proactively to give a better diagnostic.
        if (Native.IsProcessInJob(_proc, IntPtr.Zero, out bool alreadyJob) && alreadyJob)
        {
            Output?.Invoke("Job containment: process is already in a host job (Terminal/VS runner); containment is active from the host side.");
            return;
        }
        _job = Native.CreateJobObjectW(IntPtr.Zero, null);
        if (_job == IntPtr.Zero) { Output?.Invoke("Job containment: CreateJobObject failed; running uncontained."); return; }
        var info = new Native.JOBOBJECT_EXTENDED_LIMIT_INFORMATION();
        info.BasicLimitInformation.LimitFlags = Native.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | Native.JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
        info.BasicLimitInformation.ActiveProcessLimit = 1;   // block child-process spawning
        uint sz = (uint)System.Runtime.InteropServices.Marshal.SizeOf<Native.JOBOBJECT_EXTENDED_LIMIT_INFORMATION>();
        if (!Native.SetInformationJobObject(_job, Native.JobObjectExtendedLimitInformation, ref info, sz))
            Output?.Invoke($"Job containment: SetInformationJobObject failed (err {System.Runtime.InteropServices.Marshal.GetLastWin32Error()}).");

        // AssignProcessToJobObject requires PROCESS_SET_QUOTA and PROCESS_TERMINATE on the process handle.
        // The handle from CREATE_PROCESS_DEBUG_EVENT may not carry these. Open a fresh handle via the PID.
        IntPtr hProc = Native.OpenProcess(Native.PROCESS_SET_QUOTA | Native.PROCESS_TERMINATE, false, _pid);
        if (hProc == IntPtr.Zero) hProc = _proc;   // fall back to the event handle
        bool assigned = Native.AssignProcessToJobObject(_job, hProc);
        int assignErr = System.Runtime.InteropServices.Marshal.GetLastWin32Error();
        if (hProc != _proc) Native.CloseHandle(hProc);
        if (assigned)
            Output?.Invoke("Job containment active (child processes blocked, kill-on-close).");
        else
        {
            // If the process is already in a job (CREATE_BREAKAWAY_FROM_JOB couldn't pull it out because
            // the host job doesn't allow breakaway), AssignProcessToJobObject returns ERROR_ACCESS_DENIED.
            // That containment is still active — just not ours. Report it and drop our unused job handle.
            if (assignErr == 5 || assignErr == 0)
                Output?.Invoke("Job containment: process was not breakable from its host job; it remains contained by the host (Terminal/VS runner).");
            else
                Output?.Invoke($"Job containment: AssignProcessToJobObject failed (err {assignErr}).");
            Native.CloseHandle(_job); _job = IntPtr.Zero;
        }
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
            List<ulong>? tail = null;
            foreach (var va in vas)
            {
                int off = (int)(va - page);
                if (off >= n) { (tail ??= []).Add(va); continue; }   // in the page's unreadable tail — can't arm
                originals.Add((va, buf[off]));
                buf[off] = 0xCC;
            }
            // Don't leave breakpoints we couldn't arm registered as phantoms (listed but never fire).
            if (tail is not null) lock (_lock) foreach (var va in tail) _swBps.Remove(va);
            Native.WriteProcessMemory(_proc, page, buf, (nuint)n, out _);
            Native.VirtualProtectEx(_proc, page, (nuint)n, old, out _);
            Native.FlushInstructionCache(_proc, page, (nuint)n);

            lock (_lock)
                foreach (var (va, orig) in originals)
                    if (_swBps.TryGetValue(va, out var bp)) { bp.Original = orig; bp.Armed = true; }

            // SMC: write-protect all pages that now carry armed breakpoints.
            if (SmcTrackingEnabled)
                lock (_lock) foreach (var (va, _) in originals) ProtectPageForBreakpoint(va);
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
        SmcUntrackBreakpoint(va);
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

    /// <summary>Set the condition / hit-count / enabled state of the software or hardware breakpoint at
    /// <paramref name="va"/> (a no-op if none exists). The condition text is parsed here; a malformed
    /// expression clears the condition and is reported via <see cref="Output"/>. Resets the hit counter.
    /// Call while stopped (it may arm/disarm a software int3 or reprogram the debug registers).</summary>
    public void ConfigureBreakpoint(ulong va, string? condition, HitCountMode mode, int target, bool enabled)
    {
        ConditionExpr.TryParse(condition, out var expr, out var error);
        if (error is not null) Output?.Invoke($"Breakpoint condition error: {error}");

        Breakpoint? sw, hw;
        lock (_lock)
        {
            _swBps.TryGetValue(va, out sw);
            hw = _hwBps.FirstOrDefault(b => b.Address == va);
        }
        foreach (var bp in new[] { sw, hw })
        {
            if (bp is null) continue;
            bp.Condition = error is null ? (string.IsNullOrWhiteSpace(condition) ? null : condition!.Trim()) : null;
            bp.CompiledCondition = error is null ? expr : null;
            bp.HitMode = mode;
            bp.HitTarget = target;
            bp.HitCount = 0;
            bp.Enabled = enabled;
        }
        if (sw is not null) { if (enabled) ArmAddr(va); else DisarmAddr(va); }
        if (hw is not null) ProgramHwAllThreads();   // honours Enabled
    }

    /// <summary>Decide, at a breakpoint hit, whether to actually stop: evaluate the condition (if any) against
    /// the stopped thread's registers/memory, then apply the hit-count rule (counting only condition-passing
    /// hits). Runs on the loop thread with the debuggee frozen, so register/memory reads are consistent.</summary>
    private bool ShouldStop(Breakpoint bp, uint tid)
    {
        if (bp.CompiledCondition is { } expr)
        {
            var regs = GetRegisters(tid);
            if (regs is null) return true;   // can't evaluate → stop (safe default)
            var ctx = new EvalContext
            {
                Regs = regs,
                ReadMem = (a, n) =>
                {
                    var b = ReadMemory(a, n);
                    if (b.Length != n) return null;
                    ulong v = 0;
                    for (int i = 0; i < n; i++) v |= (ulong)b[i] << (8 * i);
                    return v;
                },
            };
            if (!expr.EvaluateBool(ctx)) return false;
        }
        if (bp.HitMode != HitCountMode.None)
        {
            bp.HitCount++;
            bool meets = bp.HitMode switch
            {
                HitCountMode.Equals => bp.HitCount == bp.HitTarget,
                HitCountMode.AtLeast => bp.HitCount >= bp.HitTarget,
                HitCountMode.Multiple => bp.HitTarget > 0 && bp.HitCount % bp.HitTarget == 0,
                _ => true,
            };
            if (!meets) return false;
        }
        return true;
    }

    /// <summary>Silently continue past an armed software breakpoint at <paramref name="addr"/> whose condition /
    /// hit-count was not met: disarm the 0xCC, arm a non-surfacing single-step (the EXCEPTION_SINGLE_STEP
    /// handler re-arms the byte and keeps running), and set the trap flag. Mirrors the on-breakpoint branch of
    /// <see cref="DoResume"/>'s SingleStepFallback. RIP must already be rewound to <paramref name="addr"/>.</summary>
    private void SilentStepOff(uint tid, IntPtr hThread, ulong addr)
    {
        DisarmAddr(addr);
        _stepping[tid] = new StepState(addr, StopAfter: false);
        using var c = new Ctx(Is32);
        if (c.Get(hThread)) { c.TrapFlag = true; c.Set(hThread); }
    }

    private void ArmAddr(ulong va)
    {
        Breakpoint? bp; lock (_lock) _swBps.TryGetValue(va, out bp);
        if (bp is null || bp.Armed || !bp.Enabled) return;   // a disabled breakpoint is not planted
        var o = ReadMemory(va, 1);
        if (o.Length < 1) return;
        bp.Original = o[0];
        if (WriteCode(va, [0xCC]))
        {
            bp.Armed = true;
            if (SmcTrackingEnabled) ProtectPageForBreakpoint(va);
        }
    }

    private void DisarmAddr(ulong va)
    {
        Breakpoint? bp; lock (_lock) _swBps.TryGetValue(va, out bp);
        if (bp is { Armed: true }) { WriteCode(va, [bp.Original]); bp.Armed = false; }
    }

    private bool AddTempBp(ulong va)
    {
        lock (_lock)
        {
            if (_tempBps.ContainsKey(va) || _swBps.ContainsKey(va)) return false;
            var o = ReadMemory(va, 1);
            if (o.Length < 1) return false;
            _tempBps[va] = o[0];
        }
        return WriteCode(va, [0xCC]);
    }

    public bool SetTemporaryBreakpoint(ulong va) => AddTempBp(va);

    private bool RemoveTempBpIfPresent(ulong va)
    {
        byte orig; lock (_lock) { if (!_tempBps.Remove(va, out orig)) return false; }
        WriteCode(va, [orig]);
        return true;
    }

    private void RemoveAllTempBps()
    {
        KeyValuePair<ulong, byte>[] bps;
        lock (_lock)
        {
            if (_tempBps.Count == 0) return;
            bps = _tempBps.ToArray();
            _tempBps.Clear();
        }
        foreach (var (va, orig) in bps)
            WriteCode(va, [orig]);
    }

    // ---- execution coverage (silent one-shot breakpoints at basic-block leaders) ----

    /// <summary>Plant one-shot silent breakpoints at the given (live) basic-block leaders. Call while stopped
    /// (the debuggee is frozen). Skips an address that already carries a software / temp / internal breakpoint.
    /// Each fires at most once: on hit it is removed, the leader recorded, and execution continues without a
    /// surfaced stop — so a covered block costs nothing on re-entry.</summary>
    public void SetCoveragePoints(IEnumerable<ulong> vas)
    {
        _clearCoverageRequested = false;   // a fresh instrumentation supersedes any pending stop request
        foreach (ulong va in vas)
        {
            bool plant = false;
            lock (_lock)
            {
                if (!_coverageBps.ContainsKey(va) && !_swBps.ContainsKey(va) && !_tempBps.ContainsKey(va)
                    && !_internalBps.ContainsKey(va))
                {
                    var o = ReadMemory(va, 1);
                    if (o.Length == 1) { _coverageBps[va] = o[0]; plant = true; }
                }
            }
            if (plant) WriteCode(va, [0xCC]);
        }
    }

    /// <summary>A snapshot of the block leaders hit so far (live VAs). Cheap; safe to poll while running.</summary>
    public ulong[] CoveredPoints() { lock (_lock) return _coveredPoints.ToArray(); }

    /// <summary>Forget the recorded leaders without touching the breakpoints (no memory writes) — safe to call
    /// while the debuggee is running. Blocks executed afterwards are recorded afresh.</summary>
    public void ClearCoveredPoints() { lock (_lock) _coveredPoints.Clear(); }

    /// <summary>Stop tracing while the debuggee keeps running: request that every remaining coverage breakpoint
    /// be removed at the next debug event (it is unsafe to rewrite the running target's code from another
    /// thread). The target is actively taking coverage hits, so this is honoured almost immediately and the
    /// program then runs clean at full speed — no pause required.</summary>
    public void RequestStopCoverage() => _clearCoverageRequested = true;

    /// <summary>Remove any outstanding coverage breakpoints (restoring their bytes) and forget the recorded
    /// leaders. Call while stopped; a no-op once the process has exited.</summary>
    public void ClearCoverage()
    {
        KeyValuePair<ulong, byte>[] bps;
        lock (_lock) { bps = _coverageBps.ToArray(); _coverageBps.Clear(); _coveredPoints.Clear(); }
        if (_proc == IntPtr.Zero) return;
        foreach (var (va, orig) in bps) WriteCode(va, [orig]);
    }

    // ---- instruction trace (single-step the loaded module; run through foreign code at full speed) ----

    /// <summary>Begin an instruction trace from the current stop: on the next Continue, single-step every
    /// instruction whose address is in [<paramref name="loVa"/>, <paramref name="hiVa"/>) (the loaded module),
    /// recording each into the covered set (live VAs); when execution leaves that range — a call into a system
    /// DLL — run it at full speed and resume single-stepping the instant it returns, rather than stepping
    /// through tens of thousands of library instructions. Call while stopped; nothing is planted up front.</summary>
    public void StartTrace(ulong loVa, ulong hiVa)
    {
        _traceLo = loVa; _traceHi = hiVa;
        _clearTraceRequested = false;
        _traceMode = true;
    }

    /// <summary>Stop the instruction trace (call while stopped). Removes any outstanding run-through
    /// breakpoints; the recorded set (<see cref="CoveredPoints"/>) is left intact for inspection.</summary>
    public void StopTrace()
    {
        _traceMode = false;
        _clearTraceRequested = false;
        ClearTraceResumeBps();
    }

    /// <summary>Stop the trace while the debuggee keeps running: honoured at the next debug event (it is unsafe
    /// to rewrite the running target from another thread). The in-flight single-step then becomes a free run and
    /// the program continues at full speed.</summary>
    public void RequestStopTrace() => _clearTraceRequested = true;

    private void ClearTraceResumeBps()
    {
        KeyValuePair<ulong, byte>[] bps;
        lock (_lock) { bps = _traceResumeBps.ToArray(); _traceResumeBps.Clear(); }
        if (_proc == IntPtr.Zero) return;
        foreach (var (va, orig) in bps) WriteCode(va, [orig]);
    }

    /// <summary>A trace single-step completed on a debuggee thread. Record the instruction now at the IP and
    /// decide what next: surface a stop (pause / a user breakpoint on the path), run foreign code at full speed
    /// (a call left the loaded module — set a one-shot return bp and free-run), or keep single-stepping. Returns
    /// true to surface a UI stop; false to continue (the loop calls ContinueDebugEvent).</summary>
    private bool HandleTraceStep(in Native.DEBUG_EVENT ev, IntPtr hThread, ref uint cont)
    {
        uint tid = ev.dwThreadId;
        _traceStep.Remove(tid, out ulong reArm);
        if (reArm != 0) ArmAddr(reArm);   // re-arm the user bp we stepped off to begin this trace

        // Trace turned off (toggle while running): stop single-stepping and let the program run free.
        if (!_traceMode || _clearTraceRequested) { _clearTraceRequested = false; _traceMode = false; ClearTraceResumeBps(); return false; }

        using var c = new Ctx(Is32);
        if (!c.Get(hThread)) return false;
        ulong ip = c.Ip;

        // Pause requested: surface it at the instruction we're about to execute.
        if (_pauseRequested) { _pauseRequested = false; Stopped?.Invoke(new StopInfo(StopReason.Paused, tid, ip, 0)); return true; }

        // A user breakpoint at the next instruction → stop here (its int3 hasn't executed; IP already points at it).
        Breakpoint? ub; lock (_lock) _swBps.TryGetValue(ip, out ub);
        bool ubArmed = ub is { Armed: true };
        if (ubArmed && ShouldStop(ub!, tid)) { Stopped?.Invoke(new StopInfo(StopReason.Breakpoint, tid, ip, 0)); return true; }

        // Left the loaded module (a call/jump into a system DLL): run the foreign code at full speed and resume
        // tracing when it returns to our module, instead of single-stepping through the whole library.
        if (ip < _traceLo || ip >= _traceHi)
        {
            ulong ret = ModuleReturnAddress(c.Sp);
            if (ret != 0 && AddTraceResumeBp(ret)) return false;   // free-run (trap flag is auto-cleared) to the return
            // No sane in-module return found: fall back to single-stepping through it (records nothing until we
            // re-enter the module). Slow for that stretch, but bounded and never wedges.
            _traceStep[tid] = 0;
            c.TrapFlag = true; c.Set(hThread);
            return false;
        }

        // Inside the module: record this instruction and keep single-stepping.
        lock (_lock) _coveredPoints.Add(ip);
        if (ubArmed) DisarmAddr(ip);            // a not-taken conditional bp on the path — step off it, re-arm after
        _traceStep[tid] = ubArmed ? ip : 0;
        c.TrapFlag = true; c.Set(hThread);
        return false;
    }

    /// <summary>Hit a run-through return breakpoint: restore the byte, rewind RIP over the 0xCC, record the
    /// landing and resume single-step tracing (or, if the trace was turned off meanwhile, just remove it).</summary>
    private void HandleTraceResume(ulong addr, uint tid, IntPtr hThread)
    {
        byte orig; lock (_lock) _traceResumeBps.Remove(addr, out orig);
        WriteCode(addr, [orig]);
        SetIp(hThread, addr);   // rewind over the 0xCC so the instruction re-executes
        if (_traceMode && !_clearTraceRequested)
        {
            if (addr >= _traceLo && addr < _traceHi) lock (_lock) _coveredPoints.Add(addr);
            ArmTraceStep(tid, hThread);
        }
        else { _clearTraceRequested = false; _traceMode = false; ClearTraceResumeBps(); }
    }

    /// <summary>Mark <paramref name="tid"/> as trace-stepping and set its trap flag so the next instruction
    /// single-steps back into <see cref="HandleTraceStep"/>.</summary>
    private void ArmTraceStep(uint tid, IntPtr hThread)
    {
        _traceStep[tid] = 0;
        using var c = new Ctx(Is32);
        if (c.Get(hThread)) { c.TrapFlag = true; c.Set(hThread); }
    }

    /// <summary>Plant a one-shot run-through return breakpoint (silent; resumes tracing on hit). Skips an address
    /// that already carries any breakpoint, except a run-through bp already there (recursion into the same
    /// return) which is reused. Returns false if it could not be planted.</summary>
    private bool AddTraceResumeBp(ulong va)
    {
        lock (_lock)
        {
            if (_traceResumeBps.ContainsKey(va)) return true;   // already planted (recursive/repeated call) — free-run to it
            if (_swBps.ContainsKey(va) || _tempBps.ContainsKey(va) || _coverageBps.ContainsKey(va) || _internalBps.ContainsKey(va))
                return false;
            var o = ReadMemory(va, 1);
            if (o.Length < 1) return false;
            _traceResumeBps[va] = o[0];
        }
        return WriteCode(va, [0xCC]);
    }

    /// <summary>The first stack slot (from SP up) holding a plausible return address into the loaded module —
    /// i.e. <c>[SP]</c> right after a call, else the nearest in-module return frame. 0 if none is found.</summary>
    private ulong ModuleReturnAddress(ulong sp)
    {
        var stack = ReadMemory(sp, 0x400);
        int ptr = Is32 ? 4 : 8;
        for (int i = 0; i + ptr <= stack.Length; i += ptr)
        {
            ulong v = ptr == 8 ? BitConverter.ToUInt64(stack, i) : BitConverter.ToUInt32(stack, i);
            if (v >= _traceLo && v < _traceHi && IsReturnAddress(v)) return v;
        }
        return 0;
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
            foreach (var kv in _coverageBps)
                if (kv.Key >= addr && kv.Key < end) buf[kv.Key - addr] = kv.Value;
            foreach (var kv in _traceResumeBps)
                if (kv.Key >= addr && kv.Key < end) buf[kv.Key - addr] = kv.Value;
            foreach (var kv in _internalBps)
                if (kv.Value.Armed && kv.Key >= addr && kv.Key < end) buf[kv.Key - addr] = kv.Value.Original;
            foreach (var kv in _pendingReturns)
                if (kv.Key >= addr && kv.Key < end) buf[kv.Key - addr] = kv.Value.Orig;
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

    /// <summary>The loaded module whose base is the greatest at or below <paramref name="va"/> (best-effort
    /// containment; module sizes aren't tracked). Used to attribute a fault to the target vs. ntdll/etc.</summary>
    public ModuleInfo? ModuleContaining(ulong va)
    {
        lock (_lock)
        {
            ModuleInfo? best = null;
            foreach (var m in _modules.Values)
                if (m.Base <= va && (best is null || m.Base > best.Base)) best = m;
            return best;
        }
    }

    /// <summary>Snapshot a fault for diagnostics: which module faulted (and the offset into it), the faulting
    /// instruction disassembled from live memory, the registers, and — for an access violation — what address
    /// it tried to touch (read/write/execute) and the page state there. Call while frozen at the exception.</summary>
    public FaultSnapshot CaptureFault(in ExceptionEvent e)
    {
        var mod = ModuleContaining(e.Address);
        string instr = "";
        try { if (new LiveDisassembler(this).TryDecodeAt(e.Address, out var ins)) instr = new Core.Disasm.AsmFormatter().FormatText(ins); }
        catch { /* unreadable code page at the fault — leave blank */ }
        string regs = GetRegisters(e.ThreadId) is { } r ? FormatRegisters(r) : "";
        // For an AV, describe the page at the *target* address (what was inaccessible); else the faulting IP's page.
        string mem = DescribeMemory(e.AccessType >= 0 ? e.FaultAddress : e.Address);
        return new FaultSnapshot(e.Code, e.Address, e.FirstChance, mod?.Name ?? "?",
            mod is null ? 0 : e.Address - mod.Base, instr, regs, e.AccessType, e.FaultAddress, mem);
    }

    private static string FormatRegisters(RegisterSet r)
    {
        string[] keys = r.Is32
            ? ["eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp", "eip"]
            : ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "rip"];
        return string.Join(" ", keys.Select(k => $"{k}={r[k]:X}"));
    }

    /// <summary>Describe a page's commit state + protection, e.g. "committed RW (non-exec)" — so an execute
    /// fault on a non-executable page (NX / control-flow derail) or a read of unmapped memory is obvious.</summary>
    private string DescribeMemory(ulong va)
    {
        if (_proc == IntPtr.Zero) return "";
        int sz = System.Runtime.InteropServices.Marshal.SizeOf<Native.MEMORY_BASIC_INFORMATION>();
        if (Native.VirtualQueryEx(_proc, va, out var mbi, (nuint)sz) == 0) return "unqueryable";
        if (mbi.State != Native.MEM_COMMIT) return mbi.State == 0x2000 ? "reserved (uncommitted)" : "free (unmapped)";
        return "committed " + ProtName(mbi.Protect);
    }

    private static string ProtName(uint p) => (p & 0xFF) switch
    {
        0x01 => "no-access",
        0x02 => "R (non-exec)",
        0x04 => "RW (non-exec)",
        0x08 => "WC (non-exec)",
        0x10 => "X-only",
        0x20 => "RX",
        0x40 => "RWX",
        0x80 => "WCX",
        _ => $"prot 0x{p:X}",
    };

    public bool IsExecutable(ulong addr)
    {
        if (_proc == IntPtr.Zero) return false;
        if (Native.VirtualQueryEx(_proc, addr, out var mbi, (nuint)System.Runtime.InteropServices.Marshal.SizeOf<Native.MEMORY_BASIC_INFORMATION>()) == 0) return false;
        return mbi.State == Native.MEM_COMMIT && (mbi.Protect & 0xF0) != 0;   // any PAGE_EXECUTE_*
    }

    // ---- execute (NX/DEP) memory breakpoints (generic unpacker OEP catch) ----
    /// <summary>Trap execution into [<paramref name="va"/>, va+<paramref name="size"/>) by stripping execute
    /// permission from every committed page (keeping read/write), so a code fetch there raises an execute
    /// access violation (DEP). The section-execute OEP strategy guards the original (non-stub) sections, then
    /// breaks (<see cref="StopReason.GuardExec"/>) when execution first lands in one. Unlike PAGE_GUARD, this
    /// does <i>not</i> fault on data reads/writes, so the still-running stub can freely decompress into the
    /// target section without a per-write fault storm (which made multi-MB sections like UPX0 appear to hang).
    /// Pages that are already non-executable are tracked but left untouched — they DEP-fault on execution on
    /// their own. Original protections are restored by <see cref="ClearGuards"/>. Call while frozen at a stop.</summary>
    public void GuardRegion(ulong va, ulong size)
    {
        if (_proc == IntPtr.Zero || size == 0) return;
        ulong start = va & ~0xFFFUL;
        ulong end = (va + size + 0xFFF) & ~0xFFFUL;
        int mbiSize = System.Runtime.InteropServices.Marshal.SizeOf<Native.MEMORY_BASIC_INFORMATION>();
        for (ulong p = start; p < end; p += 0x1000)
        {
            if (Native.VirtualQueryEx(_proc, p, out var mbi, (nuint)mbiSize) == 0) continue;
            if (mbi.State != Native.MEM_COMMIT) continue;
            uint prot = mbi.Protect;
            if ((prot & Native.PAGE_GUARD) != 0 || (prot & 0xFF) == Native.PAGE_NOACCESS) continue;
            uint nx = StripExecute(prot);
            // Executable page: strip execute (record it only if the reprotect takes). Already non-executable:
            // track it without touching protection — execution into it still DEP-faults, and changing nothing
            // means no data faults.
            if (nx != prot)
            {
                if (Native.VirtualProtectEx(_proc, p, 0x1000, nx, out _))
                    lock (_lock) _guarded[p] = prot;
            }
            else lock (_lock) _guarded[p] = prot;
        }
    }

    /// <summary>Map an executable page protection to its non-executable equivalent, preserving read/write
    /// access and any modifier bits (PAGE_GUARD/NOCACHE/…). Non-executable protections are returned unchanged.</summary>
    private static uint StripExecute(uint prot)
    {
        uint stripped = (prot & 0xFF) switch
        {
            Native.PAGE_EXECUTE          => Native.PAGE_READONLY,
            Native.PAGE_EXECUTE_READ     => Native.PAGE_READONLY,
            Native.PAGE_EXECUTE_READWRITE => Native.PAGE_READWRITE,
            Native.PAGE_EXECUTE_WRITECOPY => Native.PAGE_WRITECOPY,
            uint other                   => other,
        };
        return (prot & ~0xFFu) | stripped;
    }

    /// <summary>Remove every guard page we set, restoring original protections. Idempotent.</summary>
    public void ClearGuards()
    {
        if (_proc == IntPtr.Zero) return;
        lock (_lock)
        {
            foreach (var (page, prot) in _guarded) Native.VirtualProtectEx(_proc, page, 0x1000, prot, out _);
            _guarded.Clear();
        }
    }

    public bool HasGuards { get { lock (_lock) return _guarded.Count > 0; } }

    /// <summary>Capture the full in-memory image at <paramref name="imageBase"/> as a virtual-address-indexed
    /// buffer (buffer offset == RVA) by reading every committed region across SizeOfImage. Breakpoints are
    /// masked by <see cref="ReadMemory"/>, so the dump is clean. Returns [] if the PE headers can't be parsed.
    /// Shares its region-walk with the non-invasive dumper via <see cref="Unpacking.MemoryImageDump"/>.</summary>
    public byte[] DumpImage(ulong imageBase, out uint sizeOfImage) =>
        Unpacking.MemoryImageDump.Dump(_proc, imageBase, ReadMemory, out sizeOfImage);

    /// <summary>True if the bytes around a (foreign) breakpoint/single-step exception are a program anti-debug
    /// instruction — int 2Dh (CD 2D), 2-byte int3 (CD 03), int3 (CC), or ICEBP/int1 (F1) — so it should be
    /// delivered to the program rather than swallowed. Tolerates the differing exception-address conventions.</summary>
    private bool IsProgramDebugInstruction(ulong addr, bool step)
    {
        if (addr < 2) return false;
        var b = ReadMemory(addr - 2, 4);   // b[0]=addr-2, b[1]=addr-1, b[2]=addr, b[3]=addr+1
        if (b.Length < 4) return false;
        if (step) return b[1] == 0xF1;     // ICEBP/int1 (exception address = icebp+1)
        return b[1] == 0xCC                                   // int3, addr = int3+1
            || b[2] == 0xCC                                   // int3, addr = int3
            || (b[0] == 0xCD && (b[1] == 0x03 || b[1] == 0x2D))   // CD 03 / CD 2D, addr = instr+2
            || (b[2] == 0xCD && b[3] == 0x2D);                // CD 2D, addr = instr
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
        if (instr.IsInvalid || instr.Length > bytes.Length) return false;   // invalid, or a truncated read at a region boundary
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

    /// <summary>The DOS path behind a file handle (the one a LOAD_DLL event hands us), or null. Reliable at
    /// load time, unlike GetModuleFileNameEx. Strips the \\?\ extended-length prefix for normal comparison.</summary>
    private static string? PathFromFileHandle(IntPtr hFile)
    {
        if (hFile == IntPtr.Zero) return null;
        var buf = new char[600];
        uint n = Native.GetFinalPathNameByHandleW(hFile, buf, (uint)buf.Length, 0);
        if (n == 0 || n > buf.Length) return null;
        string s = new(buf, 0, (int)n);
        if (s.StartsWith(@"\\?\UNC\", StringComparison.Ordinal)) return @"\\" + s[8..];
        if (s.StartsWith(@"\\?\", StringComparison.Ordinal)) return s[4..];
        return s;
    }

    /// <summary>True if the module just loaded (handle from the LOAD_DLL event, plus its resolved path) is the
    /// target DLL. Prefers file identity (volume serial + file index) — authoritative and immune to casing /
    /// 8.3 / subst / symlink and to a same-named DLL loaded from another directory. Falls back to a path/
    /// filename compare only when an identity can't be obtained for either side.</summary>
    private bool IsTargetModule(IntPtr moduleFile, string? modulePath)
    {
        if (_targetFileId is { } want && FileIdentity(moduleFile) is { } got)
            return got == want;   // authoritative
        return modulePath is not null && PathMatchesTarget(modulePath);
    }

    private bool PathMatchesTarget(string modulePath)
    {
        if (_targetDllPath is null) return false;
        if (string.Equals(SafeFullPath(modulePath), _targetDllPath, StringComparison.OrdinalIgnoreCase)) return true;
        return string.Equals(System.IO.Path.GetFileName(modulePath), System.IO.Path.GetFileName(_targetDllPath),
                             StringComparison.OrdinalIgnoreCase);
    }

    private static (uint Vol, uint Hi, uint Lo)? FileIdentity(IntPtr hFile)
    {
        if (hFile == IntPtr.Zero || !Native.GetFileInformationByHandle(hFile, out var bi)) return null;
        return (bi.dwVolumeSerialNumber, bi.nFileIndexHigh, bi.nFileIndexLow);
    }

    private static (uint Vol, uint Hi, uint Lo)? FileIdentityOfPath(string path)
    {
        IntPtr h = Native.CreateFileW(path, Native.FILE_READ_ATTRIBUTES,
            Native.FILE_SHARE_READ | Native.FILE_SHARE_WRITE | Native.FILE_SHARE_DELETE,
            IntPtr.Zero, Native.OPEN_EXISTING, 0, IntPtr.Zero);
        if (h == Native.INVALID_HANDLE_VALUE) return null;
        try { return FileIdentity(h); } finally { Native.CloseHandle(h); }
    }

    private static string SafeFullPath(string path)
    {
        try { return System.IO.Path.GetFullPath(path); } catch { return path; }
    }
}

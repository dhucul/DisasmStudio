using System.Windows.Threading;
using DisasmStudio.Core.Analysis;
using DisasmStudio.Core.Disasm;
using DisasmStudio.Core.Formats;
using DisasmStudio.Debug;
using DisasmStudio.Debug.Unpacking;

namespace DisasmStudio.Wpf.Services;

/// <summary>
/// Bridges the <see cref="DebuggerEngine"/> (debug thread) to the WPF UI: marshals engine events to the
/// Dispatcher, builds the rebased live <see cref="AnalysisResult"/> + decoder + dereference resolver on
/// the first stop, and exposes the current register/stop state. Commands forward to the engine.
/// </summary>
public sealed class DebugSession
{
    private readonly Dispatcher _ui;
    private readonly AnalysisResult? _static;   // null when attaching with no file open
    private AnalysisResult? _synthStatic;        // analysis synthesized from the live image (attach-without-file)
    private bool _synthAttempted;                // synthesize once, even if it fails, so stops don't re-analyze

    /// <summary>Analysis rebuilt from the unpacked process image after a "run to OEP" hunt, or null. Takes
    /// precedence over the packed file's own analysis so every later stop rebases from the real program.</summary>
    private AnalysisResult? _unpackedStatic;

    /// <summary>The static analysis the live view is rebased from: the unpacked image's when one has been
    /// adopted, else the loaded file's, or — when attaching with no file open — one synthesized from the
    /// process's own image on the first stop.</summary>
    private AnalysisResult? BaseStatic => _unpackedStatic ?? _static ?? _synthStatic;

    public DebuggerEngine Engine { get; } = new();
    public AnalysisResult? LiveResult { get; private set; }
    public IInstructionDecoder? LiveDecoder { get; private set; }
    public DereferenceResolver? Deref { get; private set; }
    public RegisterSet? Registers { get; private set; }
    public ulong CurrentIp { get; private set; }
    public StopReason LastReason { get; private set; }
    public uint LastExceptionCode { get; private set; }
    public bool IsStopped { get; private set; }

    /// <summary>Active FunCap-style function-capture session, or null. Read on the UI thread (the capture
    /// poll timer) and written/read on the debug-loop thread (OnStopped nulls it during teardown), so the
    /// backing field is volatile — the null-swap must be visible across threads. FunctionCapture's own state
    /// is internally locked, so observing the reference (or null) is sufficient.</summary>
    public FunctionCapture? Capture { get => _capture; private set => _capture = value; }
    private volatile FunctionCapture? _capture;

    /// <summary>Active "run to OEP" hunt, or null. Started and cancelled on the UI thread, driven and completed
    /// on the debug-loop thread in <see cref="OnStopped"/>. Volatile so the null-swap is visible across threads,
    /// but visibility alone is not enough — see <see cref="_oepLock"/>.</summary>
    private volatile OepFinder? _oep;
    /// <summary>Serializes claiming the hunt. Both threads can end it (the user pressing Stop/Cancel, or the
    /// finder reporting the OEP), and a volatile read-then-act is not atomic: without this, a stop already being
    /// routed on the debug-loop thread would keep driving a finder the UI thread had just ended, raising a
    /// second outcome for one hunt — a duplicate prompt — and resuming a target the user asked to stop.
    /// Held only for cheap state transitions; disarming and event raising happen outside it.</summary>
    private readonly object _oepLock = new();
    /// <summary>A cancelled hunt whose instrumentation could not be removed yet because the debuggee was running.
    /// Rewriting page protections is only safe while it is frozen, so the teardown is deferred to the next stop.
    /// Exchanged rather than marked volatile, so the stop that claims it is the only one that disarms.</summary>
    private OepFinder? _oepPendingDisarm;
    /// <summary>True when the resume that will produce the next stop was issued by the finder rather than by a
    /// user command. Every user-facing resume clears it, so a stop the user asked for is never swallowed.</summary>
    private volatile bool _oepResumePending;
    /// <summary>The session's <see cref="DebuggerEngine.PassFirstChanceExceptions"/> before the hunt raised it.</summary>
    private bool _oepPrevPassFirstChance;
    /// <summary>User breakpoints resumed past during the current hunt (reported when the OEP is reached).</summary>
    private int _oepSkippedBps;
    /// <summary>Outcome stashed on the debug-loop thread and raised at the end of <see cref="OnStoppedUi"/>,
    /// so the caret and registers have already settled on the OEP before the UI reacts.</summary>
    private volatile OepHuntResult? _oepPendingOutcome;
    /// <summary>Every stop seen during the hunt and what was done with it. A hunt that silently resumes forever
    /// is otherwise invisible — this is what turns "it just ran to completion" into a diagnosable timeline.
    /// Appended on the debug-loop thread, read on the UI thread once the hunt is over; guarded by its own lock.</summary>
    private readonly List<string> _oepTimeline = [];
    private const int OepTimelineCap = 500;
    /// <summary>Lock-free mirror of the timeline length, so a caller can skip building a message it would only
    /// discard. A hunt can see stops far faster than a human can read them, and formatting one string per stop
    /// is itself enough allocation churn to matter.</summary>
    private volatile int _traceCount;

    private void Trace(string line)
    {
        if (_traceCount >= OepTimelineCap) return;
        lock (_oepTimeline)
        {
            if (_oepTimeline.Count < OepTimelineCap) _oepTimeline.Add(line);
            _traceCount = _oepTimeline.Count;
        }
    }

    /// <summary>The hunt's stop-by-stop timeline, newest last.</summary>
    public string OepTimeline { get { lock (_oepTimeline) return string.Join(Environment.NewLine, _oepTimeline); } }

    /// <summary>True while a "run to OEP" hunt is in flight.</summary>
    public bool IsHuntingOep => _oep is not null;

    /// <summary>How a "run to OEP" hunt ended. <paramref name="Oep"/> is 0 unless <paramref name="Found"/>.</summary>
    public sealed record OepHuntResult(bool Found, ulong Oep, OepMethod Method, int SkippedBreakpoints,
                                       string Log, string? Error);

    /// <summary>Raised on the UI thread when a hunt finishes — found, failed or cancelled.</summary>
    public event Action<OepHuntResult>? OepHuntFinished;

    public event Action? Stopped;
    public event Action? Running;
    public event Action<int>? Exited;
    public event Action<DebugStartFailure>? StartFailed;
    /// <summary>Raised when the debugger detached but left the process running (see <see cref="Detach"/>).</summary>
    public event Action? Detached;
    public event Action<string>? Output;

    /// <summary>Raised (on the UI thread) when a capture has finished draining and been torn down on the
    /// engine thread — the resume-after path returns without a <see cref="Stopped"/> callback, so this is the
    /// UI's signal to rebuild the final call graph from the now-complete edge set. Carries the finished
    /// capture (already stopped, but its edges are retained) so the handler can snapshot them.</summary>
    public event Action<FunctionCapture>? CaptureFinished;

    public DebugSession(Dispatcher ui, AnalysisResult? staticResult)
    {
        _ui = ui; _static = staticResult;
        Engine.Stopped += OnStopped;
        Engine.Running += () =>
        {
            // Resumes the *hunt* issued are dropped rather than posted to the UI: for a packed target under the
            // hide-debugger layer that is every anti-debug hook it calls and every breakpoint the hunt skips,
            // and a UI callback per resume floods the dispatcher until the window stops responding. The UI
            // already shows the hunt's own status, so they are pure noise.
            // Keyed on who resumed, not merely on a hunt existing: a hunt stays armed across a Pause, and the
            // user's own Continue from there must still drive the normal running/stopped UI transitions.
            if (_oep is not null && _oepResumePending) { IsStopped = false; return; }
            _ui.BeginInvoke(() => { IsStopped = false; Running?.Invoke(); });
        };
        Engine.StartFailed += failure => _ui.BeginInvoke(() => StartFailed?.Invoke(failure));
        // Raised on the debug-loop thread while the process still exists, so an in-flight hunt can re-query the
        // page protections it armed before they become unqueryable. This is the only moment "the target undid
        // our guard" can be distinguished from "it simply never reached the OEP".
        Engine.ProcessExiting += _ => DiagnoseHuntAtExit();
        Engine.Exited += code => _ui.BeginInvoke(() => { IsStopped = false; EndOepHuntOnSessionEnd("The target exited before reaching the OEP."); Exited?.Invoke(code); });
        Engine.Detached += () => _ui.BeginInvoke(() => { IsStopped = false; EndOepHuntOnSessionEnd("The debugger detached."); Detached?.Invoke(); });
        Engine.Output += m => _ui.BeginInvoke(() => Output?.Invoke(m));
    }

    public void Launch(string path, string? workingDirectory = null) => Engine.Launch(path, workingDirectory);
    public void Attach(uint pid) => Engine.Attach(pid);

    /// <summary>Debug a DLL by hosting it in <paramref name="hostExe"/> (rundll32 or a custom host) which
    /// LoadLibrary's it; the engine breaks at <paramref name="breakRva"/> (the DLL's DllMain or a chosen
    /// export) once it maps. <paramref name="breakIsEntry"/> marks a DllMain break (EntryPoint reason).</summary>
    public void LaunchDll(string hostExe, string commandLine, string? workingDir, string targetDllPath, uint breakRva, bool breakIsEntry)
        => Engine.LaunchHostingDll(hostExe, commandLine, workingDir, targetDllPath, breakRva, breakIsEntry);

    private void OnStopped(StopInfo s)
    {
        // Capture runs on the engine thread: one of its breakpoints records + auto-resumes (no UI stop).
        var cap = Capture;
        if (cap is { Active: true } && cap.Handle(s)) return;

        // Stopping a capture: now that the debuggee is frozen it is safe to remove the capture breakpoints.
        // If our own Pause caused this stop, resume so the program keeps running with capture off; otherwise
        // (a user breakpoint / exception happened first) let that stop surface normally.
        if (cap is { Draining: true })
        {
            cap.StopCapture();
            Capture = null;
            // The drain may have captured a few more edges after the UI's pre-stop graph build; tell the UI to
            // rebuild from the now-complete (retained) edge set. Marshalled because the resume path returns below
            // without ever reaching OnStoppedUi.
            var finished = cap;
            _ui.BeginInvoke(() => CaptureFinished?.Invoke(finished));
            if (cap.ResumeAfter && s.Reason == StopReason.Paused) { Engine.Go(); return; }
        }

        // A hunt cancelled while the debuggee was running left its guards and breakpoints in place, because
        // rewriting them is only safe once it is frozen. This is that moment: strip them, then let the stop
        // surface normally so the user has the session back.
        if (Interlocked.Exchange(ref _oepPendingDisarm, null) is { } stale)
        { try { stale.Abort(Engine); } catch { /* the debuggee may already be gone */ } }

        // A "run to OEP" hunt drives itself from here, exactly like a capture: stops it owns are fed back to
        // the finder (which resumes again, or reports the OEP) and never surface, while the user's own stops
        // are passed through untouched. Returning early keeps the debuggee running without a UI stop.
        if (_oep is { } finder && HandleOepStop(finder, s)) return;

        // Attach-without-file: build the static analysis from the live image once, here on the engine thread
        // (the heavy analysis must not run on the UI thread), so OnStoppedUi can rebase it like a file load.
        // Attempted exactly once — on failure we don't re-analyze on every later stop.
        if (_static is null && !_synthAttempted && Engine.ImageBase != 0)
        {
            _synthAttempted = true;
            _ui.BeginInvoke(() => Output?.Invoke("Analyzing attached process image…"));
            _synthStatic = SynthesizeStaticFromProcess();
        }

        _ui.BeginInvoke(() => OnStoppedUi(s));
    }

    /// <summary>Dump the live main image and run the standard analyzer on it, so an attach with no file open
    /// still gets functions, strings, xrefs and disassembly. Runs on the engine thread (the debuggee is frozen
    /// at the stop). Best-effort: returns null if the image can't be dumped or parsed (non-PE / hostile).
    /// Imports/API annotations are limited — the memory image's import directory isn't reconstructed here.</summary>
    private AnalysisResult? SynthesizeStaticFromProcess()
    {
        try
        {
            var bytes = Engine.DumpImage(Engine.ImageBase, out _);
            string path = Engine.Modules.FirstOrDefault(m => m.Base == Engine.ImageBase)?.Path ?? "(attached process)";
            return PeMemoryImage.TryLoadFromBytes(bytes, Engine.ImageBase, path, out var img)
                ? AnalysisEngine.Analyze(img)
                : null;
        }
        catch { return null; }
    }

    /// <summary>Analysis (functions, names/exports, disassembly) of the module — other than the main image — that
    /// contains <paramref name="va"/>, so the listing can follow the IP into it (e.g. ntdll at the loader break, or
    /// a called kernel32 export). The module image is dumped from process memory and run through the standard
    /// analyzer, then cached by module base so a step within the same module is instant. Returns null (also cached)
    /// when <paramref name="va"/> is in the main image or the module can't be dumped/parsed. Call while stopped
    /// (the debuggee is frozen at the stop).</summary>
    public AnalysisResult? ForeignModuleAnalysis(ulong va)
    {
        var mod = Engine.ModuleContaining(va);
        if (mod is null || mod.Base == Engine.ImageBase) return null;   // unknown, or the main image (handled elsewhere)
        if (_foreignModules.TryGetValue(mod.Base, out var cached)) return cached;   // resolved: a built analysis, or null = gave up
        AnalysisResult? res = null;
        try
        {
            var bytes = Engine.DumpImage(mod.Base, out _);
            if (PeMemoryImage.TryLoadFromBytes(bytes, mod.Base, mod.Path, out var img))
                res = AnalysisEngine.Analyze(img);
        }
        catch { res = null; }
        if (res is not null) { _foreignModules[mod.Base] = res; return res; }   // cache the success — built once per session
        // Failed: the module may simply not be fully mapped yet (e.g. very early in loader init). Retry on a later
        // stop up to a small cap, then give up and cache the null so a genuinely un-analyzable module isn't
        // re-dumped on every step for the rest of the session.
        int attempts = _foreignAttempts.GetValueOrDefault(mod.Base) + 1;
        _foreignAttempts[mod.Base] = attempts;
        if (attempts >= MaxForeignAnalysisAttempts) _foreignModules[mod.Base] = null;
        return null;
    }

    /// <summary>Per-session cache of successfully built foreign-module analyses keyed by module base (see
    /// <see cref="ForeignModuleAnalysis"/>). A cached null means "gave up after <see cref="MaxForeignAnalysisAttempts"/>
    /// failed attempts" — a definitive miss that stops further re-dumping.</summary>
    private readonly Dictionary<ulong, AnalysisResult?> _foreignModules = [];
    /// <summary>Failed-attempt counts per module base, so a module that can't be dumped/parsed yet is retried a few
    /// times (it may only be mid-initialization) before being cached as a permanent miss.</summary>
    private readonly Dictionary<ulong, int> _foreignAttempts = [];
    private const int MaxForeignAnalysisAttempts = 3;

    private void OnStoppedUi(StopInfo s)
    {
        // Build the rebased live analysis once the debugged module's base is known. For a launched EXE that is
        // the process base, set at process-create (so true on the first stop); for a DLL hosted in an EXE the
        // slide is only known when the DLL maps, so Engine.ImageBase stays 0 until then — defer the build.
        if (LiveResult is null && Engine.ImageBase != 0 && BaseStatic is { } baseStatic)
        {
            LiveResult = LiveAnalysis.Build(Engine, baseStatic).Result;
            LiveDecoder = new LiveDisassembler(Engine);
        }
        Registers = Engine.GetRegisters();
        // A memory-breakpoint stop reports the accessing instruction in s.Address; the thread's real IP has
        // already stepped one instruction past the access, so prefer the reported address for the caret/status.
        CurrentIp = s.Reason == StopReason.MemoryBreakpoint ? s.Address : Registers?.Ip ?? s.Address;
        LastReason = s.Reason;
        LastExceptionCode = s.ExceptionCode;
        IsStopped = true;
        if (LiveResult is not null) Deref = new DereferenceResolver(Engine, LiveResult.Names, Engine.Modules);
        Stopped?.Invoke();
        // Raised last, so a handler that prompts or re-analyzes sees the UI already settled on the OEP.
        if (_oepPendingOutcome is { } outcome) { _oepPendingOutcome = null; OepHuntFinished?.Invoke(outcome); }
    }

    // ---- run to OEP (packer stub → original entry point) ----

    /// <summary>Begin hunting the original entry point from the current stop, running the packer stub at full
    /// speed. Call on the UI thread while stopped. Returns null on success, or a message explaining why the
    /// hunt could not be armed — in which case nothing was resumed and the debuggee is still stopped.</summary>
    public string? StartOepHunt(OepMethod method, ulong? manualOep, ulong staticImageBase)
    {
        if (!IsStopped) return "The debuggee must be stopped to run to the OEP.";
        if (_oep is not null) return "An OEP hunt is already running.";
        if (Capture is { Active: true }) return "Stop the function capture first — it and the OEP hunt both drive the debuggee.";

        var finder = new OepFinder(method, manualOep, staticImageBase);
        _oepSkippedBps = 0;
        lock (_oepTimeline) { _oepTimeline.Clear(); _traceCount = 0; }
        Trace($"hunt started: {method}, entry {Engine.EntryPoint:X}, base {Engine.ImageBase:X}, {(Engine.Is32 ? "x86" : "x64")}");
        _oepPrevPassFirstChance = Engine.PassFirstChanceExceptions;
        // Packer stubs use SEH as ordinary control flow, so stopping on their first-chance exceptions would
        // strand the hunt. Every OEP-relevant handler in the engine (memory breakpoints, the guard-exec catch,
        // single-step/hardware) runs before its PassFirstChanceExceptions early-out, so the stops the finder
        // waits for still arrive. Restored however the hunt ends.
        Engine.PassFirstChanceExceptions = true;
        lock (_oepLock) { _oep = finder; _oepResumePending = true; }
        try
        {
            if (finder.Begin(Engine) is { } immediate)   // e.g. a manual OEP that is already the entry point
            {
                // Already there, and nothing was resumed. Claimed through the same lock as every other exit so
                // it still reports exactly once, and raised directly — this is already the UI thread.
                if (ClaimOepHunt() is not null)
                {
                    _oepPendingOutcome = null;
                    OepHuntFinished?.Invoke(new OepHuntResult(true, immediate, finder.ActiveMethod, 0, finder.Log, null));
                }
                return null;
            }
            // The strategy exhausted itself immediately (e.g. no valid OEP candidate found, no guardable
            // sections, baseline entropy already low). Begin returned null without resuming, and the finder
            // is already done — end the hunt now so the UI reports the failure instead of leaving the
            // debuggee stopped with an armed-but-dead hunt.
            if (finder.IsDone)
            {
                if (ClaimOepHunt() is not null)
                {
                    _oepPendingOutcome = null;
                    OepHuntFinished?.Invoke(new OepHuntResult(false, 0, finder.ActiveMethod, 0, finder.Log,
                        $"Strategy {finder.ActiveMethod} could not be armed — see the log for details."));
                }
                return null;
            }
            return null;
        }
        catch (Exception ex)
        {
            // The strategy could not be armed (no guardable section, unparseable headers). Begin throws before
            // issuing any resume, so nothing is in flight and the debuggee is still frozen at this stop.
            if (ClaimOepHunt() is not null)
                try { finder.Abort(Engine); } catch { /* best-effort teardown of a half-armed strategy */ }
            return ex.Message;
        }
    }

    /// <summary>Abandon an in-flight hunt and disarm everything it planted, without resuming. UI thread, while
    /// stopped. Disarming matters: guards left behind would surface later as an uninterpreted guard-exec stop.</summary>
    public void CancelOepHunt() => EndOepHunt(disarm: true, "Cancelled.");

    /// <summary>Drop the hunt and restore the session state it changed. <paramref name="disarm"/> also puts the
    /// debuggee's page protections and breakpoint bytes back, which is required whenever the process will keep
    /// running — but is measurable work (~2 µs per guarded page, so hundreds of milliseconds on a large unpacked
    /// section) held on the calling thread, so it is skipped when the process is about to be terminated.</summary>
    private void EndOepHunt(bool disarm, string reason)
    {
        if (ClaimOepHunt() is not { } finder) return;   // the debug loop already ended it — don't report twice
        var outcome = new OepHuntResult(false, 0, finder.ActiveMethod, _oepSkippedBps, finder.Log, reason);
        _oepPendingOutcome = null;
        if (disarm)
        {
            // Rewriting page protections and breakpoint bytes is only safe while the debuggee is frozen. If it
            // is running, hand the finder to the next stop and pause so one arrives — otherwise a cancel from a
            // running hunt would leave its guards behind for a later, uninterpretable guard-exec stop.
            if (IsStopped) { try { finder.Abort(Engine); } catch { /* the debuggee may already be gone */ } }
            else { Interlocked.Exchange(ref _oepPendingDisarm, finder); Engine.Pause(); }
        }
        Trace($"hunt ended: {reason}");
        OepHuntFinished?.Invoke(outcome);
    }

    /// <summary>Atomically take ownership of the in-flight hunt, restoring the engine state it changed. Returns
    /// null when another thread already claimed it, which is what makes ending a hunt exactly-once regardless of
    /// whether the user or the finder got there first.</summary>
    private OepFinder? ClaimOepHunt()
    {
        lock (_oepLock) return ClaimOepHuntLocked();
    }

    /// <summary>The body of <see cref="ClaimOepHunt"/>, for callers already holding <see cref="_oepLock"/>.</summary>
    private OepFinder? ClaimOepHuntLocked()
    {
        var finder = _oep;
        if (finder is null) return null;
        _oep = null;
        _oepResumePending = false;
        Engine.PassFirstChanceExceptions = _oepPrevPassFirstChance;
        return finder;
    }

    /// <summary>Engine-thread routing for a stop that arrives while a hunt is armed. Returns true when the stop
    /// was consumed — the debuggee has been resumed and no UI stop should surface.</summary>
    private bool HandleOepStop(OepFinder finder, StopInfo s)
    {
        // Held for the whole routing decision so the hunt cannot be ended underneath it by Stop/Cancel on the UI
        // thread. Only cheap engine calls happen in here (a resume is an enqueue), and no event is raised — the
        // outcome is stashed for OnStoppedUi — so there is nothing for this lock to deadlock against.
        lock (_oepLock)
        {
            // Re-checked under the lock: OnStopped read _oep before taking it, and the user may have ended the
            // hunt in between. If so this stop is no longer ours — let it surface.
            if (!ReferenceEquals(_oep, finder)) return false;

            bool owns;
            try { owns = finder.Owns(Engine, s); } catch { owns = false; }   // the debug loop must not die here

            var route = OepStopRouting.Decide(true, _oepResumePending, owns, s.Reason);
            // Guarded rather than formatted-then-dropped: this runs on the debug-loop thread once per stop.
            if (_traceCount < OepTimelineCap)
                Trace($"{s.Reason} @ {s.Address:X}  owns={owns} huntResume={_oepResumePending} → {route}");
            switch (route)
            {
                case OepRoute.Resume:
                    // A user breakpoint: the hunt outranks it while running, so resume and count it.
                    _oepSkippedBps++;
                    _oepResumePending = true;
                    Engine.Go();
                    return true;

                case OepRoute.Forward:
                    ulong? oep;
                    try { oep = finder.OnStop(Engine, s); }
                    catch (Exception ex)
                    {
                        // A strategy fallback threw. Disarm before giving up — the debuggee is frozen here, and
                        // guards left armed would surface later as a bare guard-exec stop nothing interprets —
                        // then let this stop surface so the user sees where it died.
                        try { finder.Abort(Engine); } catch { /* best-effort */ }
                        FinishOepHuntLocked(new OepHuntResult(false, 0, finder.ActiveMethod, _oepSkippedBps, finder.Log, ex.Message));
                        return false;
                    }
                    if (oep is null)
                    {
                        // The finder may have exhausted itself without finding the OEP (e.g. timeout, hit
                        // limit, all candidates rejected). When IsDone is true the finder issued no resume
                        // and the debuggee is still stopped — end the hunt so the failure is reported.
                        if (finder.IsDone)
                        {
                            FinishOepHuntLocked(new OepHuntResult(false, 0, finder.ActiveMethod, _oepSkippedBps, finder.Log,
                                $"Strategy {finder.ActiveMethod} exhausted without finding the OEP."));
                            return false;
                        }
                        _oepResumePending = true; return true;   // the finder resumed; no UI stop
                    }
                    // Found. The finder issued no resume, so let the stop fall through the normal path and land
                    // the caret, registers and stack on the OEP.
                    FinishOepHuntLocked(new OepHuntResult(true, oep.Value, finder.ActiveMethod, _oepSkippedBps, finder.Log, null));
                    return false;

                default:
                    // Surface: Pause, a genuine fault, or a stop the user's own resume produced. The hunt stays
                    // armed, so a later Continue still reaches the OEP and the finder still recognises it.
                    _oepResumePending = false;
                    return false;
            }
        }
    }

    /// <summary>Claim the hunt and stash its outcome for <see cref="OnStoppedUi"/> to raise, so the UI has
    /// already settled on the OEP before any handler runs. Debug-loop thread, <see cref="_oepLock"/> held.</summary>
    private void FinishOepHuntLocked(OepHuntResult outcome)
    {
        if (ClaimOepHuntLocked() is null) return;   // already ended elsewhere; do not report a second outcome
        _oepPendingOutcome = outcome;
    }

    /// <summary>Last chance to explain a hunt that never fired, while the debuggee still exists. Debug-loop
    /// thread, from <see cref="DebuggerEngine.ProcessExiting"/>.</summary>
    private void DiagnoseHuntAtExit()
    {
        if (_oep is not { } finder) return;
        try
        {
            string? why = finder.DiagnoseMissedGuard(Engine);
            Trace(why is null
                ? $"process exiting with the hunt still armed ({Engine.GuardedPageCount} guarded page(s) intact) — execution never entered a guarded section."
                : $"process exiting: {why}");
            _oepExitDiagnosis = why;
        }
        catch { /* diagnosis is best-effort; the process is on its way out */ }
    }

    /// <summary>Why the guard never fired, determined at process exit (see <see cref="DiagnoseHuntAtExit"/>).</summary>
    private string? _oepExitDiagnosis;

    /// <summary>End a hunt because the session itself ended. No disarming — the process is gone.</summary>
    private void EndOepHuntOnSessionEnd(string why)
    {
        // Claims through the same lock as every other exit, so a hunt that completes on the debug loop as the
        // process dies is still reported exactly once. Restoring PassFirstChanceExceptions happens inside the
        // claim, or a hunt interrupted by the target exiting would leave first-chance exceptions permanently
        // passed through and the user's exception filter silently inert for the rest of the session.
        Interlocked.Exchange(ref _oepPendingDisarm, null);   // the process is gone; nothing left to disarm
        if (ClaimOepHunt() is not { } finder) return;
        if (_oepExitDiagnosis is { } diag) { why = diag; _oepExitDiagnosis = null; }
        var outcome = new OepHuntResult(false, 0, finder.ActiveMethod, _oepSkippedBps, finder.Log, why);
        _oepPendingOutcome = null;
        Trace($"hunt ended: {why}");
        OepHuntFinished?.Invoke(outcome);
    }

    // ---- analysis rebuilt from unpacked process memory ----

    /// <summary>Snapshot the main image from the frozen debuggee. Call while stopped; the copy is detached from
    /// the process, so the analysis below can run on a background thread without further process access.</summary>
    public byte[]? DumpMainImage()
        => IsStopped && Engine.ImageBase != 0 ? Engine.DumpImage(Engine.ImageBase, out _) : null;

    /// <summary>Build a fresh static + live analysis from an unpacked memory snapshot, seeded at
    /// <paramref name="oepVa"/>. Pure CPU over <paramref name="dump"/> plus engine metadata — designed to run on
    /// a background thread. Returns null if the bytes don't parse as a PE.</summary>
    public (AnalysisResult Static, AnalysisResult Live)? BuildUnpackedAnalysis(
        byte[] dump, ulong oepVa, AnalysisOptions options, IProgress<string>? progress, CancellationToken token)
    {
        string path = Engine.Modules.FirstOrDefault(m => m.Base == Engine.ImageBase)?.Path ?? "(unpacked process)";
        // The dumped headers still point AddressOfEntryPoint at the loader stub, so the located OEP is supplied
        // explicitly — it becomes the "start" name, a recursive-descent seed and a function.
        if (!PeMemoryImage.TryLoadFromBytes(dump, Engine.ImageBase, path, out var img, entryVaOverride: oepVa))
            return null;
        var stat = AnalysisEngine.Analyze(img, options with { AssumeUnpacked = true }, progress, token);
        return (stat, LiveAnalysis.Build(Engine, stat).Result);
    }

    /// <summary>Install an unpacked analysis as the base of the live view, so later stops (and function capture)
    /// rebase from the real program rather than the packed file. UI thread.</summary>
    public void AdoptUnpackedAnalysis(AnalysisResult unpackedStatic, AnalysisResult live)
    {
        _unpackedStatic = unpackedStatic;
        LiveResult = live;
        LiveDecoder = new LiveDisassembler(Engine);
        Deref = new DereferenceResolver(Engine, live.Names, Engine.Modules);
    }

    // commands
    // Each user-facing resume clears the finder's ownership of the next stop, so a stop the user asked for
    // always surfaces even while a hunt is armed.
    public void Go() { _oepResumePending = false; Engine.Go(); }
    public void StepInto() { _oepResumePending = false; Engine.StepInto(); }
    public void StepOver() { _oepResumePending = false; Engine.StepOver(); }
    public void StepOut() { _oepResumePending = false; Engine.StepOut(); }
    public void Pause() => Engine.Pause();   // not a resume — leave the flag alone
    /// <summary>End the session. Any in-flight hunt is dropped first so its engine state (passed first-chance
    /// exceptions) is restored rather than leaking into whatever runs next. The hunt is NOT disarmed: the
    /// process is about to be terminated, so restoring its page protections is pure latency on the caller —
    /// and this is the UI thread, straight off the Stop button.</summary>
    public void Stop() { EndOepHunt(disarm: false, "Stopped."); Engine.Stop(); }
    /// <summary>Detach the debugger but keep the debuggee running. Only meaningful while stopped. Cancelling the
    /// hunt first matters here: the guards and breakpoints it planted must come out before the process is
    /// released, or it runs on with sections we made non-executable.</summary>
    public void Detach() { CancelOepHunt(); Engine.Detach(); }
    public void RunToCursor(ulong va) { _oepResumePending = false; Engine.RunToCursor(va); }
    /// <summary>Run until any of <paramref name="targets"/> is reached (used by "Continue to return" with the
    /// current function's ret sites). Stops at the first one hit; the function's calls run at full speed.</summary>
    public void RunToAny(IEnumerable<ulong> targets) { _oepResumePending = false; Engine.RunToAny(targets); }

    // ---- execution coverage ----
    public void SetCoveragePoints(IEnumerable<ulong> leaders) => Engine.SetCoveragePoints(leaders);
    public ulong[] CoveredPoints() => Engine.CoveredPoints();
    public void ClearCoveredPoints() => Engine.ClearCoveredPoints();
    public void RequestStopCoverage() => Engine.RequestStopCoverage();
    public void ClearCoverage() => Engine.ClearCoverage();

    // ---- instruction trace (single-step the loaded module from the current stop) ----
    public void StartTrace(ulong loVa, ulong hiVa) => Engine.StartTrace(loVa, hiVa);
    public void StopTrace() => Engine.StopTrace();
    public void RequestStopTrace() => Engine.RequestStopTrace();

    public bool HasBreakpoint(ulong va) => Engine.HasBreakpoint(va);
    public void ToggleBreakpoint(ulong va) { if (Engine.HasBreakpoint(va)) Engine.RemoveBreakpoint(va); else Engine.SetBreakpoint(va); }

    // ---- FunCap-style function capture ----

    /// <summary>Start capturing function I/O. <paramref name="funcVa"/> is 0 for "all functions", else a single one.</summary>
    public FunctionCapture? StartCapture(ulong funcVa, string? logPath, bool captureOnce, bool argsOnly, bool annotate)
    {
        // Capture toggles PassFirstChanceExceptions, which an in-flight OEP hunt depends on — they can't share.
        if (LiveResult is null || BaseStatic is not { } baseStatic || IsHuntingOep) return null;
        var deref = new DereferenceResolver(Engine, LiveResult.Names, Engine.Modules);
        // Gate breakpoint arming on "this VA is a genuine code instruction start" per the analysis's linear
        // index — so capture never writes a 0xCC into a jump/lookup table that sits in an executable section.
        var linear = LiveResult.Linear;
        bool isCodeStart(ulong va)
        {
            long line = linear.IndexOf(va);
            return linear.VaAt(line) == va && linear.IsReachableCodeAt(line);
        }
        // Reachability gate (used only when the analysis over-identifies code): a function is "real" if it is
        //   - in the x64 .pdata table (FunctionStarts) — the authoritative function list, which includes
        //     indirect-only functions (vtable methods/callbacks) but never data tables; or
        //   - a direct call target (static xref DB), a named symbol, or the entry point.
        // Data tables / pointer-scan false positives satisfy none of these, so they stay excluded. (A byte-
        // level "looks like code" heuristic was tried and removed: common opcodes are common byte values, so
        // table data decodes to a plausible first instruction and slipped through, re-corrupting the image.)
        ulong liveBase = LiveResult.Image.ImageBase;
        ulong staticBase = baseStatic.Image.ImageBase;
        ulong ToStatic(ulong live) => liveBase >= staticBase
            ? checked(live - (liveBase - staticBase))
            : checked(live + (staticBase - liveBase));
        var xrefs = baseStatic.Xrefs;
        var symVas = new HashSet<ulong>();
        foreach (var s in LiveResult.Image.Symbols) symVas.Add(s.Va);
        var pdata = new HashSet<ulong>(LiveResult.Image.FunctionStarts);
        ulong entryVa = LiveResult.Image.EntryVa;
        bool isReachable(ulong va) => va == entryVa || pdata.Contains(va) || symVas.Contains(va)
            || xrefs.To(ToStatic(va)).Any(x => x.Kind == XrefKind.Call);
        var cap = new FunctionCapture(Engine, deref, LiveResult.Functions.Select(f => (f.Va, f.Name)), captureOnce, argsOnly, annotate, isCodeStart, isReachable);
        if (logPath is not null) cap.SetLogFile(logPath);
        Capture = cap;
        if (funcVa == 0) cap.StartAll(); else cap.StartFunction(funcVa);
        return cap;
    }

    /// <summary>Stop capture safely. If the debuggee is frozen, remove the breakpoints now; if it is
    /// running, pause it first and tear down on the resulting stop (removing breakpoints from a running
    /// process corrupts it), then resume so the program keeps running with capture off.</summary>
    public void StopCapture()
    {
        var cap = Capture;
        if (cap is null) return;
        if (IsStopped) { cap.StopCapture(); Capture = null; }
        else { cap.BeginDraining(resumeAfter: true); Engine.Pause(); }
    }

    /// <summary>Immediate teardown for session end (the process is gone; breakpoint removal is a no-op).</summary>
    public void AbortCapture() { Capture?.StopCapture(); Capture = null; }
}

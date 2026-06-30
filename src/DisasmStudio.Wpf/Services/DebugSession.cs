using System.Windows.Threading;
using DisasmStudio.Core.Analysis;
using DisasmStudio.Core.Disasm;
using DisasmStudio.Core.Formats;
using DisasmStudio.Debug;

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

    /// <summary>The static analysis the live view is rebased from: the loaded file's, or — when attaching with
    /// no file open — one synthesized from the process's own image on the first stop.</summary>
    private AnalysisResult? BaseStatic => _static ?? _synthStatic;

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

    public event Action? Stopped;
    public event Action? Running;
    public event Action<int>? Exited;
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
        Engine.Running += () => _ui.BeginInvoke(() => { IsStopped = false; Running?.Invoke(); });
        Engine.Exited += code => _ui.BeginInvoke(() => { IsStopped = false; Exited?.Invoke(code); });
        Engine.Detached += () => _ui.BeginInvoke(() => { IsStopped = false; Detached?.Invoke(); });
        Engine.Output += m => _ui.BeginInvoke(() => Output?.Invoke(m));
    }

    public void Launch(string path) => Engine.Launch(path);
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
        CurrentIp = Registers?.Ip ?? s.Address;
        LastReason = s.Reason;
        LastExceptionCode = s.ExceptionCode;
        IsStopped = true;
        if (LiveResult is not null) Deref = new DereferenceResolver(Engine, LiveResult.Names, Engine.Modules);
        Stopped?.Invoke();
    }

    // commands
    public void Go() => Engine.Go();
    public void StepInto() => Engine.StepInto();
    public void StepOver() => Engine.StepOver();
    public void StepOut() => Engine.StepOut();
    public void Pause() => Engine.Pause();
    public void Stop() => Engine.Stop();
    /// <summary>Detach the debugger but keep the debuggee running. Only meaningful while stopped.</summary>
    public void Detach() => Engine.Detach();
    public void RunToCursor(ulong va) => Engine.RunToCursor(va);
    /// <summary>Run until any of <paramref name="targets"/> is reached (used by "Continue to return" with the
    /// current function's ret sites). Stops at the first one hit; the function's calls run at full speed.</summary>
    public void RunToAny(IEnumerable<ulong> targets) => Engine.RunToAny(targets);

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
        if (LiveResult is null || BaseStatic is not { } baseStatic) return null;
        var deref = new DereferenceResolver(Engine, LiveResult.Names, Engine.Modules);
        // Gate breakpoint arming on "this VA is a genuine code instruction start" per the analysis's linear
        // index — so capture never writes a 0xCC into a jump/lookup table that sits in an executable section.
        var linear = LiveResult.Linear;
        bool isCodeStart(ulong va) { long line = linear.IndexOf(va); return linear.VaAt(line) == va && !linear.IsDataAt(line); }
        // Reachability gate (used only when the analysis over-identifies code): a function is "real" if it is
        //   - in the x64 .pdata table (FunctionStarts) — the authoritative function list, which includes
        //     indirect-only functions (vtable methods/callbacks) but never data tables; or
        //   - a direct call target (static xref DB), a named symbol, or the entry point.
        // Data tables / pointer-scan false positives satisfy none of these, so they stay excluded. (A byte-
        // level "looks like code" heuristic was tried and removed: common opcodes are common byte values, so
        // table data decodes to a plausible first instruction and slipped through, re-corrupting the image.)
        ulong slide = LiveResult.Image.ImageBase - baseStatic.Image.ImageBase;
        var xrefs = baseStatic.Xrefs;
        var symVas = new HashSet<ulong>();
        foreach (var s in LiveResult.Image.Symbols) symVas.Add(s.Va);
        var pdata = new HashSet<ulong>(LiveResult.Image.FunctionStarts);
        ulong entryVa = LiveResult.Image.EntryVa;
        bool isReachable(ulong va) => va == entryVa || pdata.Contains(va) || symVas.Contains(va)
            || xrefs.To(va - slide).Any(x => x.Kind == XrefKind.Call);
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

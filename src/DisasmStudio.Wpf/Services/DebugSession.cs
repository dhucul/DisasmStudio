using System.Windows.Threading;
using DisasmStudio.Core.Analysis;
using DisasmStudio.Core.Disasm;
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
    private readonly AnalysisResult _static;

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
    public event Action<string>? Output;

    public DebugSession(Dispatcher ui, AnalysisResult staticResult)
    {
        _ui = ui; _static = staticResult;
        Engine.Stopped += OnStopped;
        Engine.Running += () => _ui.BeginInvoke(() => { IsStopped = false; Running?.Invoke(); });
        Engine.Exited += code => _ui.BeginInvoke(() => { IsStopped = false; Exited?.Invoke(code); });
        Engine.Output += m => _ui.BeginInvoke(() => Output?.Invoke(m));
    }

    public void Launch(string path) => Engine.Launch(path);
    public void Attach(uint pid) => Engine.Attach(pid);

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
            if (cap.ResumeAfter && s.Reason == StopReason.Paused) { Engine.Go(); return; }
        }

        _ui.BeginInvoke(() => OnStoppedUi(s));
    }

    private void OnStoppedUi(StopInfo s)
    {
        LiveResult ??= LiveAnalysis.Build(Engine, _static).Result;
        LiveDecoder ??= new LiveDisassembler(Engine);
        Registers = Engine.GetRegisters();
        CurrentIp = Registers?.Ip ?? s.Address;
        LastReason = s.Reason;
        LastExceptionCode = s.ExceptionCode;
        IsStopped = true;
        Deref = new DereferenceResolver(Engine, LiveResult!.Names, Engine.Modules);
        Stopped?.Invoke();
    }

    // commands
    public void Go() => Engine.Go();
    public void StepInto() => Engine.StepInto();
    public void StepOver() => Engine.StepOver();
    public void StepOut() => Engine.StepOut();
    public void Pause() => Engine.Pause();
    public void Stop() => Engine.Stop();
    public void RunToCursor(ulong va) => Engine.RunToCursor(va);

    public bool HasBreakpoint(ulong va) => Engine.HasBreakpoint(va);
    public void ToggleBreakpoint(ulong va) { if (Engine.HasBreakpoint(va)) Engine.RemoveBreakpoint(va); else Engine.SetBreakpoint(va); }

    // ---- FunCap-style function capture ----

    /// <summary>Start capturing function I/O. <paramref name="funcVa"/> is 0 for "all functions", else a single one.</summary>
    public FunctionCapture? StartCapture(ulong funcVa, string? logPath, bool captureOnce, bool argsOnly, bool annotate)
    {
        if (LiveResult is null) return null;
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
        ulong slide = LiveResult.Image.ImageBase - _static.Image.ImageBase;
        var xrefs = _static.Xrefs;
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

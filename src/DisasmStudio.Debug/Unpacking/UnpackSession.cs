using System.Text;
using DisasmStudio.Core.Unpacking;

namespace DisasmStudio.Debug.Unpacking;

/// <summary>Options for an unpack run. <see cref="StaticImageBase"/> is the file's preferred image base, used
/// to rebase a manual (static-VA) OEP to the runtime load base under ASLR.</summary>
public sealed record UnpackOptions(OepMethod Strategy, ulong? ManualOep, bool Sandbox, string OutputPath, ulong StaticImageBase = 0);

/// <summary>The outcome of an unpack run.</summary>
public sealed record UnpackResult(
    bool Ok, ulong Oep, OepMethod Method, bool OepConfirmed,
    int ImportsResolved, int ImportsUnresolved, string? OutputPath, string? Error, string Log);

/// <summary>
/// Orchestrates a full generic-unpack run: launch the packed target under the debugger (optionally
/// job-contained), drive an <see cref="OepFinder"/> to the OEP, then — while the process is frozen there —
/// dump the image (<see cref="DebuggerEngine.DumpImage"/>), rebuild the IAT (<see cref="ImportRebuilder"/>)
/// against the live module exports (<see cref="ModuleExportResolver"/>), write a clean PE
/// (<see cref="PeBuilder"/>), and terminate the target. All driving happens on the debug-loop thread inside
/// the <see cref="DebuggerEngine.Stopped"/> handler, where the debuggee is provably frozen.
/// </summary>
public sealed class UnpackSession
{
    private readonly string _target;
    private readonly UnpackOptions _opt;
    private readonly DebuggerEngine _eng = new();
    private readonly OepFinder _finder;
    private readonly TaskCompletionSource<UnpackResult> _tcs = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly StringBuilder _log = new();
    private bool _done;
    private bool _first = true;

    /// <summary>Progress lines as the run proceeds (also accumulated into <see cref="UnpackResult.Log"/>).</summary>
    public event Action<string>? Progress;

    public UnpackSession(string targetPath, UnpackOptions options)
    {
        _target = targetPath;
        _opt = options;
        _finder = new OepFinder(options.Strategy, options.ManualOep, options.StaticImageBase);
    }

    public Task<UnpackResult> RunAsync()
    {
        _eng.PassFirstChanceExceptions = true;   // let the stub's own SEH tricks run; only OEP/guard stops matter
        _eng.HideFromDebugger = true;            // packers commonly check for a debugger — hide from them
        _eng.Output += Report;
        _eng.Stopped += OnStopped;
        _eng.Exited += OnExited;
        if (_opt.Sandbox) _eng.EnableJobContainment();
        Report($"Launching {Path.GetFileName(_target)} under the debugger{(_opt.Sandbox ? " (job-contained)" : "")}…");
        try { _eng.Launch(_target); }
        catch (Exception ex) { Fail("Launch failed: " + ex.Message); }
        return _tcs.Task;
    }

    private void OnStopped(StopInfo stop)
    {
        if (_done) return;
        try
        {
            if (_first)
            {
                _first = false;
                Report($"Entry point at {stop.Address:X}; locating OEP (strategy: {_opt.Strategy}).");
                var immediate = _finder.Begin(_eng);
                if (immediate is { } v) CompleteAtOep(v);
                return;
            }
            if (stop.Reason == StopReason.Exception)
            {
                Fail($"Target raised an unhandled exception (0x{stop.ExceptionCode:X8}) at {stop.Address:X} before reaching OEP.");
                return;
            }
            var oep = _finder.OnStop(_eng, stop);
            if (oep is { } oepVa) CompleteAtOep(oepVa);
        }
        catch (Exception ex) { Fail("Unpack error: " + ex.Message); }
    }

    private void CompleteAtOep(ulong oepVa)
    {
        foreach (var line in _finder.Log.Split('\n', StringSplitOptions.RemoveEmptyEntries)) Report(line);
        Report($"OEP reached at {oepVa:X} (method: {_finder.ActiveMethod}).");

        bool confirmed = OepValidator.LooksLikeOep(_eng.ReadMemory(oepVa, 32), _eng.Is32);
        Report(confirmed ? "OEP prologue looks valid." : "OEP prologue not recognised (dumping anyway).");

        var image = _eng.DumpImage(_eng.ImageBase, out uint sizeOfImage);
        if (image.Length == 0 || !PeView.TryParse(image, out var view)) { Fail("Failed to dump or parse the image."); return; }
        Report($"Dumped image: {sizeOfImage:X} bytes from base {_eng.ImageBase:X}.");

        MemReader mem = (va, count) => _eng.ReadMemory(va, count);
        var resolver = new ModuleExportResolver(_eng.Modules, mem);
        Report($"Indexed {resolver.ModuleCount} module(s), {resolver.ExportCount} export(s).");

        uint oepRva = (uint)(oepVa - _eng.ImageBase);
        var iat = ImportRebuilder.Rebuild(mem, resolver, view, _eng.ImageBase, oepVa);
        foreach (var line in iat.Log.Split('\n', StringSplitOptions.RemoveEmptyEntries)) Report(line);

        var outBytes = PeBuilder.Build(image, view, oepRva, iat.Ok ? iat : null, _eng.ImageBase, _opt.StaticImageBase, out var buildLog);
        foreach (var line in buildLog.Split('\n', StringSplitOptions.RemoveEmptyEntries)) Report(line);

        try { File.WriteAllBytes(_opt.OutputPath, outBytes); }
        catch (Exception ex) { Fail("Failed to write output file: " + ex.Message); return; }
        Report($"Wrote {_opt.OutputPath}.");

        _done = true;
        var result = new UnpackResult(true, oepVa, _finder.ActiveMethod, confirmed,
            iat.Resolved, iat.Unresolved, _opt.OutputPath, null, _log.ToString());
        try { _eng.Stop(); } catch { }
        _tcs.TrySetResult(result);
    }

    private void OnExited(int code)
    {
        if (_done) return;
        _done = true;
        _tcs.TrySetResult(new UnpackResult(false, 0, _finder.ActiveMethod, false, 0, 0, null,
            "The target exited before an OEP was reached (possible anti-debug, or the OEP strategy didn't trigger).",
            _log.ToString()));
    }

    private void Fail(string error)
    {
        if (_done) return;
        _done = true;
        Report("FAILED: " + error);
        try { _eng.Stop(); } catch { }
        _tcs.TrySetResult(new UnpackResult(false, 0, _finder.ActiveMethod, false, 0, 0, null, error, _log.ToString()));
    }

    private void Report(string msg) { lock (_log) _log.AppendLine(msg); Progress?.Invoke(msg); }
}

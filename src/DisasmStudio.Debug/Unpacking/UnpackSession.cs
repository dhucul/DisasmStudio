using System.Diagnostics;
using System.Text;
using DisasmStudio.Core.Unpacking;

namespace DisasmStudio.Debug.Unpacking;

/// <summary>Options for an unpack run. <see cref="StaticImageBase"/> is the file's preferred image base, used
/// to rebase a manual (static-VA) OEP to the runtime load base under ASLR.</summary>
public sealed record UnpackOptions(OepMethod Strategy, ulong? ManualOep, bool Sandbox, string OutputPath,
    ulong StaticImageBase = 0, bool UseApiHooks = true, bool InterceptRdtsc = true);

/// <summary>The outcome of an unpack run.</summary>
public sealed record UnpackResult(
    bool Ok, ulong Oep, OepMethod Method, bool OepConfirmed,
    int ImportsResolved, int ImportsUnresolved, string? OutputPath, string? Error, string Log,
    string? FaultDumpPath = null, ulong FaultDumpBase = 0,
    IReadOnlyList<RunFreeProbeSnapshot>? ProbeSnapshots = null,
    string? TraceReportPath = null);

public sealed record RunFreeProbeSnapshot(string Label, string Path, string? HottestExecSection,
    double HottestExecEntropy, double HottestExecNonZeroPercent);

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
    private FaultSnapshot? _lastFault;
    private string? _faultDumpPath;
    private uint _faultDumpSize;
    private int _dumpCount;
    private int _runFreePauseKind; // 0 none, 1 timed probe, 2 final settle dump
    private string _runFreePauseLabel = "";
    private int _runFreeProbeCount;
    private int _runFreeLiveStarted;
    private readonly List<RunFreeProbeSnapshot> _runFreeProbes = [];
    private VmTraceRecovery? _vmTrace;

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
        _eng.HideUseApiHooks = _opt.UseApiHooks;       // off = test ntdll-prologue hook detection
        _eng.HideInterceptRdtsc = _opt.InterceptRdtsc; // off = don't modify the target's code (test self-CRC)
        _eng.Output += Report;
        _eng.Stopped += OnStopped;
        _eng.Resumed += OnResumed;
        _eng.ProcessExiting += OnProcessExiting;
        _eng.Exited += OnExited;
        _eng.ExceptionObserved += OnException;
        if (_opt.Sandbox) _eng.EnableJobContainment();
        Report($"Launching {Path.GetFileName(_target)} under the debugger{(_opt.Sandbox ? " (job-contained)" : "")}…");
        try { _eng.Launch(_target); }
        catch (Exception ex) { Fail("Launch failed: " + ex.Message); }
        return _tcs.Task;
    }

    private void OnResumed()
    {
        if (_opt.Strategy != OepMethod.RunFree) return;
        if (System.Threading.Interlocked.Exchange(ref _runFreeLiveStarted, 1) != 0) return;
        DumpRunFreeProbe("live_resume");
        StartRunFreeLiveProbes();
    }

    private void OnProcessExiting(int code)
    {
        if (_done) return;
        if (_opt.Strategy == OepMethod.TraceVm && _vmTrace is not null)
        {
            _vmTrace.Finish($"process exiting with code 0x{(uint)code:X8}", dumpFinal: false);
            CompleteVmTrace(alreadyExited: true);
            return;
        }
        if (_opt.Strategy == OepMethod.RunFree)
            DumpRunFreeProbe("exit");
    }

    private void OnStopped(StopInfo stop)
    {
        if (_done) return;
        bool runFree = _opt.Strategy == OepMethod.RunFree;
        bool traceVm = _opt.Strategy == OepMethod.TraceVm;
        try
        {
            if (_first)
            {
                _first = false;
                if (runFree)
                {
                    Report($"Entry point at {stop.Address:X}; running free (no OEP trace — no single-step, hardware watchpoint or section guard). Will take an entry snapshot, live memory probes and an early timed-probe burst, then dump on a fault or after it settles.");
                    DumpRunFreeProbe("entry");
                    StartRunFreeTimers();
                    _eng.Go();
                    return;
                }
                if (traceVm)
                {
                    Report($"Entry point at {stop.Address:X}; tracing VM loop/handlers (single-step, bounded).");
                    _vmTrace = new VmTraceRecovery(_eng, _target, _opt.OutputPath);
                    Report($"VM trace report will be written to: {_vmTrace.PlannedReportPath}");
                    _vmTrace.Begin(stop);
                    if (_vmTrace.Done) { CompleteVmTrace(); return; }
                    _eng.StepInto();
                    return;
                }
                Report($"Entry point at {stop.Address:X}; locating OEP (strategy: {_opt.Strategy}).");
                var immediate = _finder.Begin(_eng);
                if (immediate is { } v) CompleteAtOep(v);
                return;
            }
            if (traceVm)
            {
                if (stop.Reason == StopReason.Exception)
                {
                    _vmTrace?.Finish($"exception 0x{stop.ExceptionCode:X8} at {stop.Address:X}");
                    CompleteVmTrace();
                    return;
                }
                if (_vmTrace is null)
                {
                    Fail("VM trace internal error: trace state was not initialized.");
                    return;
                }
                _vmTrace.OnStop(stop, out var resume);
                if (_vmTrace.Done) { CompleteVmTrace(); return; }
                switch (resume.Kind)
                {
                    case VmTraceRecovery.ResumeKind.StepOver:
                        _eng.StepOver();
                        break;
                    case VmTraceRecovery.ResumeKind.StepOut:
                        _eng.StepOut();
                        break;
                    case VmTraceRecovery.ResumeKind.RunTo:
                        _eng.RunToCursor(resume.Target);
                        break;
                    case VmTraceRecovery.ResumeKind.RunToAny:
                        _eng.RunToAny(resume.Targets ?? []);
                        break;
                    default:
                        _eng.StepInto();
                        break;
                }
                return;
            }
            if (runFree)
            {
                if (stop.Reason == StopReason.Paused)
                {
                    int pauseKind = System.Threading.Interlocked.Exchange(ref _runFreePauseKind, 0);
                    string label = _runFreePauseLabel;
                    _runFreePauseLabel = "";
                    if (pauseKind == 1)
                    {
                        DumpRunFreeProbe(label);
                        _eng.Go();
                    }
                    else DumpAndComplete("settled");
                }
                else if (stop.Reason == StopReason.Exception) DumpAndComplete($"faulted (0x{stop.ExceptionCode:X8} at {stop.Address:X})");
                else _eng.Go();   // any other stop while running free: keep going
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

    /// <summary>Run-free: collect an early burst of low-intrusion snapshots, then after a short window for the
    /// stub to clear anti-debug and self-decrypt, pause so we can dump. If it faults first, the exception path
    /// dumps instead. The probes are diagnostic only: they reveal whether section entropy changes over time.</summary>
    private void StartRunFreeTimers() => System.Threading.Tasks.Task.Run(async () =>
    {
        int[] probes = [1, 5, 15, 30, 60, 125, 250, 500, 1000, 2000, 3000];
        int last = 0;
        foreach (int ms in probes)
        {
            await System.Threading.Tasks.Task.Delay(ms - last);
            last = ms;
            RequestRunFreePause(1, $"{ms}ms");
        }
        await System.Threading.Tasks.Task.Delay(Math.Max(0, 4000 - last));
        RequestRunFreePause(2, "settled");
    });

    private void StartRunFreeLiveProbes() => System.Threading.Tasks.Task.Run(async () =>
    {
        var sw = Stopwatch.StartNew();
        int[] probes = [1, 2, 5, 10, 20, 40, 80, 125, 250];
        int last = 0;
        foreach (int ms in probes)
        {
            int wait = ms - last;
            if (wait > 0) await System.Threading.Tasks.Task.Delay(wait);
            else await System.Threading.Tasks.Task.Yield();
            last = ms;
            if (_done) return;
            DumpRunFreeProbe($"live{Math.Max(0, (int)sw.ElapsedMilliseconds)}ms");
        }
    });

    private void RequestRunFreePause(int kind, string label)
    {
        if (_done) return;
        if (kind == 1)
        {
            if (System.Threading.Interlocked.CompareExchange(ref _runFreePauseKind, 1, 0) != 0) return;
            _runFreePauseLabel = label;
            Report($"Run-free probe {label}: pausing briefly to snapshot.");
        }
        else
        {
            System.Threading.Interlocked.Exchange(ref _runFreePauseKind, 2);
            _runFreePauseLabel = label;
            Report("Run-free: settle window elapsed; pausing to dump.");
        }
        try { _eng.Pause(); } catch { }
    }

    private void DumpRunFreeProbe(string label)
    {
        if (_done) return;
        label = string.IsNullOrWhiteSpace(label) ? (++_runFreeProbeCount).ToString("D2") : label;
        try
        {
            var image = _eng.DumpImage(_eng.ImageBase, out uint sizeOfImage);
            if (image.Length == 0 || !PeView.TryParse(image, out var view))
            {
                Report($"Run-free probe {label}: could not dump/parse image.");
                return;
            }
            if (!ProbeImageHasExecutableSection(view, image.Length, out string reason))
            {
                Report($"Run-free probe {label}: ignored unusable image ({reason}).");
                return;
            }

            string dir = Path.GetDirectoryName(_opt.OutputPath) ?? Path.GetDirectoryName(_target) ?? ".";
            string path = Path.Combine(dir, $"{Path.GetFileNameWithoutExtension(_target)}_runfree_{SanitizeLabel(label)}.bin");
            File.WriteAllBytes(path, image);

            var hot = view.Sections
                .Where(s => s.IsExecutable)
                .Select(s =>
                {
                    int len = (int)Math.Min(MaxSectionSpan(s), 1u << 20);
                    len = Math.Min(len, Math.Max(0, image.Length - (int)Math.Min(s.VirtualAddress, (uint)image.Length)));
                    var bytes = len > 0 && s.VirtualAddress < image.Length
                        ? image.AsSpan((int)s.VirtualAddress, len)
                        : ReadOnlySpan<byte>.Empty;
                    double ent = bytes.Length > 0 ? Entropy.Shannon(bytes) : 0;
                    double nz = NonZeroPercent(bytes);
                    return (s.Name, Entropy: ent, NonZero: nz);
                })
                .OrderByDescending(s => s.Entropy)
                .FirstOrDefault();

            string hotText = hot.Name is null
                ? ""
                : $" hottest exec section '{hot.Name}' entropy {hot.Entropy:F2}, nonzero {hot.NonZero:F1}%.";
            lock (_runFreeProbes)
                _runFreeProbes.Add(new RunFreeProbeSnapshot(label, path, hot.Name, hot.Entropy, hot.NonZero));
            Report($"Run-free probe {label}: {sizeOfImage:X} bytes -> {path}.{hotText}");
        }
        catch (Exception ex)
        {
            Report($"Run-free probe {label}: snapshot failed ({ex.Message}).");
        }
    }

    private static bool ProbeImageHasExecutableSection(PeView view, int imageLength, out string reason)
    {
        foreach (var s in view.Sections.Where(s => s.IsExecutable))
        {
            uint span = MaxSectionSpan(s);
            if (span == 0) continue;
            if (s.VirtualAddress >= imageLength) continue;
            reason = "";
            return true;
        }
        reason = "no mapped executable section; the live dump likely raced process teardown";
        return false;
    }

    private static uint MaxSectionSpan(SectionHeader s) => Math.Max(s.VirtualSize, s.SizeOfRawData);

    private static double NonZeroPercent(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length == 0) return 0;
        int count = 0;
        foreach (byte b in bytes)
            if (b != 0) count++;
        return 100.0 * count / bytes.Length;
    }

    private static string SanitizeLabel(string s)
    {
        foreach (char c in Path.GetInvalidFileNameChars()) s = s.Replace(c, '_');
        return s.Replace(' ', '_');
    }

    /// <summary>Run-free completion: dump the live image, report the largest section's entropy (a decryption
    /// indicator), rebuild it into an openable PE rooted at the entry, and finish. Not a clean unpack — a raw
    /// memory image for inspection/devirtualization.</summary>
    private void DumpAndComplete(string reason)
    {
        if (_done) return;
        Report($"Run-free dump: {reason}.");
        if (_lastFault is { } f) ReportFault(f);
        var image = _eng.DumpImage(_eng.ImageBase, out uint sizeOfImage);
        if (image.Length == 0 || !PeView.TryParse(image, out var view))
        {
            _done = true;
            try { _eng.Stop(); } catch { }
            _tcs.TrySetResult(new UnpackResult(false, 0, OepMethod.RunFree, false, 0, 0, null,
                "Run-free: could not dump/parse the image (" + reason + ").", _log.ToString(),
                _faultDumpPath, _eng.ImageBase, ProbeSnapshotArray()));
            return;
        }
        var big = view.Sections.OrderByDescending(s => Math.Max(s.VirtualSize, s.SizeOfRawData)).FirstOrDefault();
        if (big is not null)
        {
            int len = (int)Math.Min(Math.Max(big.VirtualSize, big.SizeOfRawData), 1u << 20);
            double ent = len > 0 ? Entropy.Shannon(_eng.ReadMemory(_eng.ImageBase + big.VirtualAddress, len)) : 0;
            Report($"Largest section '{big.Name}' entropy {ent:F2} — {(ent > 7.0 ? "still packed/encrypted (decryption did not complete)" : "looks decrypted")}.");
        }
        var outBytes = PeBuilder.Build(image, view, view.EntryRva, null, _eng.ImageBase, _opt.StaticImageBase, out var buildLog);
        foreach (var line in buildLog.Split('\n', StringSplitOptions.RemoveEmptyEntries)) Report(line);
        try { File.WriteAllBytes(_opt.OutputPath, outBytes); }
        catch (Exception ex) { Fail("Failed to write output file: " + ex.Message); return; }
        Report($"Wrote memory image to {_opt.OutputPath} (entry-rooted raw dump, not a clean unpack — open it to inspect the decrypted state).");
        _done = true;
        try { _eng.Stop(); } catch { }
        _tcs.TrySetResult(new UnpackResult(true, _eng.EntryPoint, OepMethod.RunFree, false, 0, 0, _opt.OutputPath,
            null, _log.ToString(), _faultDumpPath, _eng.ImageBase, ProbeSnapshotArray()));
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
        if (_opt.Strategy == OepMethod.TraceVm && _vmTrace is not null)
        {
            _vmTrace.Finish($"process exited with code 0x{(uint)code:X8}", dumpFinal: false);
            CompleteVmTrace(alreadyExited: true);
            return;
        }
        _done = true;
        uint uc = (uint)code;
        Report($"Target exited with code 0x{uc:X8}.");
        if (_lastFault is { } f) ReportFault(f);
        string faultHint = _lastFault is { } ff ? $" Last fault: {ff.CodeName} at {ff.Address:X} in {ff.Module}+{ff.ModuleOffset:X}." : "";
        _tcs.TrySetResult(new UnpackResult(false, 0, _finder.ActiveMethod, false, 0, 0, null,
            $"The target exited (code 0x{uc:X8}) before an OEP was reached. {DescribeExit(uc)}{faultHint}",
            _log.ToString(), _faultDumpPath, _eng.ImageBase, ProbeSnapshotArray()));
    }

    // Keep the most recent error-severity (0xCxxxxxxx) or any second-chance exception — the likely crash site.
    // Captured here (not as a stop) because the unpack run passes first-chance exceptions straight to the
    // target, so a protector's anti-debug self-crash would otherwise be lost behind the bare exit code.
    private void OnException(ExceptionEvent e)
    {
        bool fatal = (e.Code & 0xF0000000) == 0xC0000000 || !e.FirstChance;
        if (!fatal) return;
        _lastFault = _eng.CaptureFault(e);
        if (_opt.Strategy == OepMethod.TraceVm && _vmTrace is { Done: false }
            && _lastFault.Module.Equals(Path.GetFileName(_target), StringComparison.OrdinalIgnoreCase))
        {
            if (e.FirstChance && _vmTrace.TryFollowFirstChanceSeh(e, out ulong handler))
                Report($"VM trace: first-chance self-crash at {e.Address:X}; following observed SEH handler {handler:X}.");
            else
                _vmTrace.Finish($"exception observed 0x{e.Code:X8} at {e.Address:X}");
        }
        // The fault is inside the target itself => its (partially) self-decrypted body is in memory right now.
        // Snapshot it so the decrypted code can be analyzed/devirtualized even though anti-debug crashes the run.
        if (_dumpCount < 8 && _lastFault.Module.Equals(Path.GetFileName(_target), StringComparison.OrdinalIgnoreCase))
            DumpAtFault();
    }

    /// <summary>Dump the live image at a fault. The debuggee is frozen at the exception, so what the unpack
    /// stub has decrypted so far (notably the VM body) is committed and readable. Best-effort, last-one-wins.</summary>
    private void DumpAtFault()
    {
        try
        {
            var img = _eng.DumpImage(_eng.ImageBase, out uint size);
            if (img.Length == 0) return;
            string dir = Path.GetDirectoryName(_opt.OutputPath) ?? Path.GetDirectoryName(_target) ?? ".";
            string path = Path.Combine(dir, Path.GetFileNameWithoutExtension(_target) + "_fault_dump.bin");
            File.WriteAllBytes(path, img);
            _faultDumpPath = path; _faultDumpSize = size; _dumpCount++;
        }
        catch { /* best-effort: a dump failure must not mask the fault report */ }
    }

    private void ReportFault(FaultSnapshot f)
    {
        string av = f.AccessDesc.Length > 0 ? $" — {f.AccessDesc} ({f.MemState})" : "";
        Report($"Fault site: {f.CodeName} at {f.Address:X} in {f.Module}+{f.ModuleOffset:X} ({(f.FirstChance ? "first-chance" : "second-chance")}){av}.");
        if (f.Instruction.Length > 0) Report($"  faulting instruction: {f.Instruction}");
        if (f.Registers.Length > 0) Report($"  registers: {f.Registers}");
        bool inTarget = f.Module.Equals(Path.GetFileName(_target), StringComparison.OrdinalIgnoreCase);
        Report(inTarget
            ? "  -> the fault is inside the target's own code — likely the protector's anti-tamper/anti-debug self-crash, or our breakpoints/single-step/guards derailing it."
            : $"  -> the fault is inside {f.Module} — possibly an API or anti-debug-hook detection path.");
        if (_faultDumpPath is not null)
            Report($"  decrypted-state snapshot: {_faultDumpSize:X} bytes -> {_faultDumpPath}. Open it as a raw binary at base {_eng.ImageBase:X} to inspect the decrypted body (the VM may now be visible).");
    }

    /// <summary>Interpret a process exit code for the failure message. When a process is killed by an
    /// unhandled exception Windows sets its exit code to the NTSTATUS, so an exception-shaped code points at a
    /// crash or an anti-debug self-terminate; a clean 0 means it simply ran to completion (expected for a pure
    /// virtualizer, which never transfers control to a separate original-code section to break an OEP on).</summary>
    private static string DescribeExit(uint code)
    {
        string? status = code switch
        {
            0xC0000005 => "STATUS_ACCESS_VIOLATION — a crash, or the protector faulted after detecting the debugger",
            0xC0000409 => "STATUS_STACK_BUFFER_OVERRUN — a /GS or anti-tamper self-terminate (a common protector anti-debug response)",
            0xC000001D => "STATUS_ILLEGAL_INSTRUCTION — execution ran into non-code (a failed unpack/guard) or an anti-debug trap",
            0xC0000025 => "STATUS_NONCONTINUABLE_EXCEPTION",
            0xC0000096 => "STATUS_PRIVILEGED_INSTRUCTION — a guarded/anti-debug instruction faulted",
            0x80000003 => "STATUS_BREAKPOINT — an int3 reached the process (anti-debug, or a planted breakpoint leaked)",
            0xC0000420 => "STATUS_ASSERTION_FAILURE",
            _ => null,
        };
        if (status is not null)
            return $"That exit code is an NTSTATUS exception ({status}) — i.e. anti-debug or a crash, not a normal run. " +
                   "Try the 'Hide debugger' layer (already on for Unpack) and, for a virtualizing protector, expect this.";
        if (code == 0)
            return "Exit code 0 means it ran to completion and exited normally. For a code-virtualizing protector that is " +
                   "expected — the program runs entirely inside its VM and never jumps to a separate original-code " +
                   "section, so there is no classic OEP to break on. Dumping cannot recover virtualized code.";
        return $"That is a normal-looking exit code ({(int)code}); the target most likely ran its course in-VM without " +
               "ever exposing an OEP, or bailed out early via an anti-debug check the hide layer doesn't cover.";
    }

    private void Fail(string error)
    {
        if (_done) return;
        _done = true;
        Report("FAILED: " + error);
        if (_lastFault is { } f) ReportFault(f);
        try { _eng.Stop(); } catch { }
        _tcs.TrySetResult(new UnpackResult(false, 0, _finder.ActiveMethod, false, 0, 0, null, error,
            _log.ToString(), _faultDumpPath, _eng.ImageBase, ProbeSnapshotArray()));
    }

    private RunFreeProbeSnapshot[] ProbeSnapshotArray()
    {
        lock (_runFreeProbes) return [.. _runFreeProbes];
    }

    private void CompleteVmTrace(bool alreadyExited = false)
    {
        if (_done) return;
        _done = true;
        string? report = _vmTrace?.ReportPath;
        if (!string.IsNullOrWhiteSpace(report))
            Report($"VM trace report: {report}");
        else
        {
            Report("VM trace completed without a report.");
            if (!string.IsNullOrWhiteSpace(_vmTrace?.LastReportError))
                Report("VM trace report write failed: " + _vmTrace.LastReportError);
        }
        if (!alreadyExited)
            try { _eng.Stop(); } catch { }
        _tcs.TrySetResult(new UnpackResult(true, 0, OepMethod.TraceVm, false, 0, 0, null, null,
            _log.ToString(), _faultDumpPath, _eng.ImageBase, ProbeSnapshotArray(), report));
    }

    private void Report(string msg) { lock (_log) _log.AppendLine(msg); Progress?.Invoke(msg); }
}

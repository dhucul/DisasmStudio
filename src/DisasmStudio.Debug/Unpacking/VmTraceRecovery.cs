using System.Diagnostics;
using System.Text;
using DisasmStudio.Core.Disasm;
using DisasmStudio.Core.Unpacking;
using Iced.Intel;

namespace DisasmStudio.Debug.Unpacking;

/// <summary>
/// Intrusive fallback for virtualizers whose dispatcher is not statically recognizable. It single-steps a
/// bounded execution window and recovers what the runtime actually did: hot IPs, indirect branch dispatch
/// sites, concrete branch targets and short handler-body samples. This is a discovery report, not a semantic
/// devirtualizer yet.
/// </summary>
internal sealed class VmTraceRecovery
{
    public enum ResumeKind { StepInto, StepOver, StepOut, RunTo, RunToAny }

    private const int MaxSteps = 1_000_000;
    private const int MaxEvents = 200_000;
    private const int HotCallTargetThreshold = 512;
    private const int HotRepThreshold = 512;
    private const int HotLoopThreshold = 512;
    private const int IndirectHelperHotEvidenceThreshold = 128;
    private static readonly TimeSpan MaxDuration = TimeSpan.FromSeconds(60);
    private static readonly int[] SnapshotMilestones = [1_000, 5_000, 10_000, 25_000, 50_000, 100_000, 250_000, 500_000, 1_000_000];

    private readonly DebuggerEngine _eng;
    private readonly string _target;
    private readonly string _reportPath;
    private readonly LiveDisassembler _dis;
    private readonly AsmFormatter _fmt = new();
    private readonly List<(ulong Start, ulong End, string Name)> _execRanges = [];
    private readonly Dictionary<ulong, int> _execCounts = [];
    private readonly Dictionary<ulong, int> _directCallTargets = [];
    private readonly Dictionary<ulong, IndirectSite> _indirect = [];
    private readonly List<TraceEvent> _events = [];
    private readonly List<TraceSnapshot> _snapshots = [];
    private readonly Stopwatch _sw = new();
    private TraceEvent? _last;
    private int _steps;
    private int _nextSnapshot;
    private int _outsideSteps;
    private int _decodeFailures;
    private int _stepOverHotCalls;
    private int _runThroughHotReps;
    private int _runThroughHotLoops;
    private int _runThroughIndirectHelpers;
    private int _stepOverKnownIndirectHelpers;
    private int _generatedStubCalls;
    private ulong _suppressNextIndirectTransitionFrom;
    private ActiveIndirectCall? _activeIndirectCall;
    private ModuleExportResolver? _apiResolver;
    private readonly Dictionary<ulong, SehFollow> _sehFollows = [];
    private string _reason = "";
    private string _lastReportError = "";

    public VmTraceRecovery(DebuggerEngine eng, string targetPath, string outputPath)
    {
        _eng = eng;
        _target = targetPath;
        _reportPath = TraceReportPath(outputPath, targetPath);
        _dis = new LiveDisassembler(eng);
        LoadExecutableRanges();
    }

    public bool Done { get; private set; }
    public string? ReportPath { get; private set; }
    public string PlannedReportPath => _reportPath;
    public string LastReportError => _lastReportError;

    public void Begin(StopInfo stop)
    {
        _sw.Start();
        ObserveStop(stop, out _);
        WriteReport();
    }

    public void OnStop(StopInfo stop, out TraceResume resume)
    {
        resume = new TraceResume(ResumeKind.StepInto, 0);
        if (Done) return;
        ObserveStop(stop, out resume);
    }

    public void Finish(string reason, bool dumpFinal = true)
    {
        if (Done) return;
        if (dumpFinal)
            DumpTraceSnapshot("final", force: true);
        Done = true;
        _reason = reason;
        WriteReport();
    }

    private void ObserveStop(StopInfo stop, out TraceResume resume)
    {
        resume = new TraceResume(ResumeKind.StepInto, 0);
        ulong ip = stop.Address;
        CompleteTransition(ip);
        if (_activeIndirectCall is { } active && ip == active.ReturnVa)
            _activeIndirectCall = null;
        if (_sehFollows.TryGetValue(ip, out var follow))
            _sehFollows[ip] = follow with { Hits = follow.Hits + 1 };

        if (!IsTargetExecutable(ip))
        {
            _outsideSteps++;
            resume = _last is not null ? new TraceResume(ResumeKind.StepOut, 0) : resume;
            _last = null;
            CheckLimits();
            return;
        }

        if (!_dis.TryDecodeAt(ip, out var ins))
        {
            _decodeFailures++;
            _last = null;
            CheckLimits();
            return;
        }

        string text = _fmt.FormatText(ins);
        var regs = _eng.GetRegisters(stop.ThreadId);
        var ev = new TraceEvent(_steps, ip, text, ins, regs?.Sp ?? 0);
        _last = ev;
        _steps++;

        _execCounts[ip] = _execCounts.GetValueOrDefault(ip) + 1;
        if (_events.Count < MaxEvents) _events.Add(ev);
        resume = ChooseResume(ip, ins);
        CaptureMilestoneSnapshots();
        CheckLimits();
    }

    private TraceResume ChooseResume(ulong ip, Instruction ins)
    {
        if (IsKnownIndirectHelperCall(ip, ins))
        {
            _suppressNextIndirectTransitionFrom = ip;
            _stepOverKnownIndirectHelpers++;
            return new TraceResume(ResumeKind.StepOver, 0);
        }

        if (FlowAnalysis.IsDirectCall(ins) && FlowAnalysis.DirectBranchTarget(ins) is { } target
            && IsTargetExecutable(target))
        {
            _directCallTargets[target] = _directCallTargets.GetValueOrDefault(target) + 1;
            if (IsActiveIndirectHelperEvidence(ip, ins))
                return RunThroughActiveIndirectHelper();
            if (_execCounts.GetValueOrDefault(target) >= HotCallTargetThreshold)
            {
                _stepOverHotCalls++;
                return new TraceResume(ResumeKind.StepOver, 0);
            }
        }

        if (IsRepStringInstruction(ins) && _execCounts.GetValueOrDefault(ip) >= HotRepThreshold)
        {
            if (IsActiveIndirectHelperEvidence(ip, ins))
                return RunThroughActiveIndirectHelper();
            _runThroughHotReps++;
            return new TraceResume(ResumeKind.RunTo, ip + (ulong)ins.Length);
        }

        if (IsHotBackwardConditionalLoop(ip, ins, out var exitVas))
        {
            if (IsActiveIndirectHelperEvidence(ip, ins))
                return RunThroughActiveIndirectHelper();
            _runThroughHotLoops++;
            return exitVas.Length == 1
                ? new TraceResume(ResumeKind.RunTo, exitVas[0])
                : new TraceResume(ResumeKind.RunToAny, 0, exitVas);
        }

        return new TraceResume(ResumeKind.StepInto, 0);
    }

    public bool TryFollowFirstChanceSeh(ExceptionEvent e, out ulong handlerVa)
    {
        handlerVa = 0;
        if (Done || !e.FirstChance || e.Code != Native.EXCEPTION_ACCESS_VIOLATION) return false;
        if (FindSelfCrashSites().All(s => s.Va != e.Address)) return false;
        var regs = _eng.GetRegisters(e.ThreadId);
        if (regs is null || !TryFindRecentSehHandler(regs, out handlerVa)) return false;
        if (!IsTargetExecutable(handlerVa)) return false;
        if (!_eng.SetTemporaryBreakpoint(handlerVa)) return false;

        _sehFollows.TryGetValue(handlerVa, out var current);
        current ??= new SehFollow(handlerVa, e.Address, 0, 0);
        _sehFollows[handlerVa] = current with
        {
            HandlerVa = handlerVa,
            Armed = current.Armed + 1,
            FaultVa = e.Address,
        };
        DumpTraceSnapshot("seh_fault", force: true);
        return true;
    }

    private bool TryFindRecentSehHandler(RegisterSet regs, out ulong handlerVa)
    {
        handlerVa = 0;
        int start = Math.Max(0, _events.Count - 32);
        for (int i = _events.Count - 1; i >= start; i--)
        {
            var ins = _events[i].Ins;
            if (ins.Mnemonic != Mnemonic.Lea || ins.Op0Kind != OpKind.Register || ins.Op1Kind != OpKind.Memory)
                continue;
            var targetReg = ins.Op0Register;
            if (targetReg == Register.None) continue;
            if (!WasRegisterPushedBeforeFsInstall(i, targetReg)) continue;

            ulong baseValue = RegisterValue(regs, ins.MemoryBase);
            ulong indexValue = RegisterValue(regs, ins.MemoryIndex);
            ulong scale = ins.MemoryIndex == Register.None ? 0 : (ulong)ins.MemoryIndexScale;
            handlerVa = baseValue + (scale == 0 ? 0 : indexValue * scale) + ins.MemoryDisplacement64;
            return handlerVa != 0;
        }
        return false;
    }

    private bool WasRegisterPushedBeforeFsInstall(int leaIndex, Register reg)
    {
        int end = Math.Min(_events.Count, leaIndex + 12);
        bool pushedHandler = false;
        bool pushedOldSeh = false;
        bool installed = false;
        for (int i = leaIndex + 1; i < end; i++)
        {
            var ins = _events[i].Ins;
            if (ins.Mnemonic == Mnemonic.Push && ins.Op0Kind == OpKind.Register && ins.Op0Register == reg)
                pushedHandler = true;
            if (ins.Mnemonic == Mnemonic.Push && ins.Op0Kind == OpKind.Memory && IsFsZeroMemory(ins))
                pushedOldSeh = true;
            if (ins.Mnemonic == Mnemonic.Mov && ins.Op0Kind == OpKind.Memory && IsFsZeroMemory(ins))
                installed = true;
        }
        return pushedHandler && pushedOldSeh && installed;
    }

    private static bool IsFsZeroMemory(in Instruction ins) =>
        ins.MemorySegment == Register.FS && ins.MemoryBase == Register.None
        && ins.MemoryIndex == Register.None && ins.MemoryDisplacement64 == 0;

    private static ulong RegisterValue(RegisterSet regs, Register reg) =>
        reg switch
        {
            Register.EAX or Register.RAX => regs[regs.Is32 ? "eax" : "rax"],
            Register.EBX or Register.RBX => regs[regs.Is32 ? "ebx" : "rbx"],
            Register.ECX or Register.RCX => regs[regs.Is32 ? "ecx" : "rcx"],
            Register.EDX or Register.RDX => regs[regs.Is32 ? "edx" : "rdx"],
            Register.ESI or Register.RSI => regs[regs.Is32 ? "esi" : "rsi"],
            Register.EDI or Register.RDI => regs[regs.Is32 ? "edi" : "rdi"],
            Register.EBP or Register.RBP => regs[regs.Is32 ? "ebp" : "rbp"],
            Register.ESP or Register.RSP => regs[regs.Is32 ? "esp" : "rsp"],
            Register.R8 => regs["r8"],
            Register.R9 => regs["r9"],
            Register.R10 => regs["r10"],
            Register.R11 => regs["r11"],
            Register.R12 => regs["r12"],
            Register.R13 => regs["r13"],
            Register.R14 => regs["r14"],
            Register.R15 => regs["r15"],
            Register.None => 0,
            _ => 0,
        };

    private bool IsKnownIndirectHelperCall(ulong ip, in Instruction ins) =>
        ins.FlowControl == FlowControl.IndirectCall
        && _indirect.TryGetValue(ip, out var site)
        && site.HelperTargets.Count > 0
        && site.Targets.Count == 0;

    private bool IsActiveIndirectHelperEvidence(ulong ip, in Instruction ins)
    {
        if (_activeIndirectCall is not { } active) return false;
        if (_steps - active.EnterStep < 16) return false;
        if (_execCounts.GetValueOrDefault(ip) < IndirectHelperHotEvidenceThreshold) return false;

        if (IsStringInstruction(ins)) return true;
        if (ins.FlowControl == FlowControl.ConditionalBranch
            && FlowAnalysis.DirectBranchTarget(ins) is { } branchTarget
            && branchTarget < ip)
            return true;
        if (FlowAnalysis.IsDirectCall(ins)
            && FlowAnalysis.DirectBranchTarget(ins) is { } callTarget
            && _execCounts.GetValueOrDefault(callTarget) >= HotCallTargetThreshold)
            return true;
        return false;
    }

    private TraceResume RunThroughActiveIndirectHelper()
    {
        if (_activeIndirectCall is not { } active)
            return new TraceResume(ResumeKind.StepInto, 0);

        if (_indirect.TryGetValue(active.SiteVa, out var site))
        {
            site.HelperSkips++;
            site.HelperTargets[active.TargetVa] = site.HelperTargets.GetValueOrDefault(active.TargetVa) + 1;
            if (site.Targets.TryGetValue(active.TargetVa, out int hits))
            {
                if (hits <= 1) site.Targets.Remove(active.TargetVa);
                else site.Targets[active.TargetVa] = hits - 1;
            }
        }

        _activeIndirectCall = null;
        _runThroughIndirectHelpers++;
        return new TraceResume(ResumeKind.RunTo, active.ReturnVa);
    }

    private void CompleteTransition(ulong nextIp)
    {
        if (_last is not { } prev) return;
        if (!IsIndirectControl(prev.Ins)) return;

        if (_suppressNextIndirectTransitionFrom == prev.Va)
        {
            _suppressNextIndirectTransitionFrom = 0;
            return;
        }

        if (!_indirect.TryGetValue(prev.Va, out var site))
        {
            site = new IndirectSite(prev.Va, prev.Text, BranchShape(prev.Ins));
            _indirect[prev.Va] = site;
        }
        site.Hits++;
        if (IsTargetExecutable(nextIp))
        {
            site.Targets[nextIp] = site.Targets.GetValueOrDefault(nextIp) + 1;
            if (prev.Ins.FlowControl == FlowControl.IndirectCall)
                _activeIndirectCall = new ActiveIndirectCall(prev.Va, nextIp, prev.Va + (ulong)prev.Ins.Length, _steps);
        }
        else
        {
            site.OutsideTargets++;
            site.OutsideTargetSamples[nextIp] = site.OutsideTargetSamples.GetValueOrDefault(nextIp) + 1;
        }
    }

    private void CheckLimits()
    {
        if (Done) return;
        if (_steps >= MaxSteps)
            Finish($"step cap reached ({MaxSteps:N0})");
        else if (_sw.Elapsed >= MaxDuration)
            Finish($"time cap reached ({MaxDuration.TotalSeconds:N0}s)");
    }

    private void CaptureMilestoneSnapshots()
    {
        while (_nextSnapshot < SnapshotMilestones.Length && _steps >= SnapshotMilestones[_nextSnapshot])
        {
            DumpTraceSnapshot(SnapshotMilestones[_nextSnapshot].ToString("D6"));
            _nextSnapshot++;
        }
    }

    private void DumpTraceSnapshot(string label, bool force = false)
    {
        if (!force && _snapshots.Any(s => s.Label == label)) return;
        try
        {
            var image = _eng.DumpImage(_eng.ImageBase, out _);
            if (image.Length == 0 || !PeView.TryParse(image, out var view))
            {
                _snapshots.Add(new TraceSnapshot(label, _steps, "", "", 0, 0, 0, "could not dump/parse image"));
                return;
            }

            if (!TryScoreHottestExecutable(view, image, out var score))
            {
                _snapshots.Add(new TraceSnapshot(label, _steps, "", "", 0, 0, image.Length, "no mapped executable section"));
                return;
            }

            string path = TraceSnapshotPath(label);
            Directory.CreateDirectory(Path.GetDirectoryName(path) ?? ".");
            File.WriteAllBytes(path, image);
            _snapshots.Add(new TraceSnapshot(label, _steps, path, score.Section, score.Entropy,
                score.NonZeroPercent, image.Length, ""));
            WriteReport();
        }
        catch (Exception ex)
        {
            _snapshots.Add(new TraceSnapshot(label, _steps, "", "", 0, 0, 0, ex.Message));
            WriteReport();
        }
    }

    private static bool TryScoreHottestExecutable(PeView view, byte[] image, out (string Section, double Entropy, double NonZeroPercent) score)
    {
        score = default;
        bool any = false;
        foreach (var s in view.Sections.Where(s => s.IsExecutable))
        {
            int len = (int)Math.Min(Math.Max(s.VirtualSize, s.SizeOfRawData), 1u << 20);
            if (s.VirtualAddress >= image.Length) continue;
            len = Math.Min(len, image.Length - (int)s.VirtualAddress);
            if (len <= 0) continue;
            var bytes = image.AsSpan((int)s.VirtualAddress, len);
            double entropy = Entropy.Shannon(bytes);
            double nonZero = NonZeroPercent(bytes);
            if (!any || entropy > score.Entropy)
            {
                score = (s.Name, entropy, nonZero);
                any = true;
            }
        }
        return any;
    }

    private static double NonZeroPercent(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length == 0) return 0;
        int count = 0;
        foreach (byte b in bytes)
            if (b != 0) count++;
        return 100.0 * count / bytes.Length;
    }

    private void LoadExecutableRanges()
    {
        var hdr = _eng.ReadMemory(_eng.ImageBase, 0x1000);
        if (!PeView.TryParse(hdr, out var view))
        {
            if (_eng.EntryPoint != 0)
                _execRanges.Add((_eng.EntryPoint, _eng.EntryPoint + 1, "entry"));
            return;
        }

        foreach (var s in view.Sections)
        {
            if (!s.IsExecutable) continue;
            uint span = Math.Max(s.VirtualSize, s.SizeOfRawData);
            if (span == 0) continue;
            ulong start = _eng.ImageBase + s.VirtualAddress;
            _execRanges.Add((start, start + span, s.Name));
        }
    }

    private bool IsTargetExecutable(ulong va) => _execRanges.Any(r => va >= r.Start && va < r.End);

    private void WriteReport()
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(_reportPath) ?? ".");
            File.WriteAllText(_reportPath, BuildReport(), Encoding.UTF8);
            ReportPath = _reportPath;
            _lastReportError = "";
        }
        catch (Exception ex)
        {
            ReportPath = null;
            _lastReportError = ex.Message;
        }
    }

    private string BuildReport()
    {
        ClassifyGeneratedStubCalls();

        var sb = new StringBuilder();
        sb.AppendLine("Experimental trace-based VM recovery report");
        sb.AppendLine();
        sb.AppendLine($"Target:       {_target}");
        sb.AppendLine($"Base:         0x{_eng.ImageBase:X}");
        sb.AppendLine($"Entry:        0x{_eng.EntryPoint:X}");
        sb.AppendLine($"Status:       {(string.IsNullOrWhiteSpace(_reason) ? "running - report updates at milestones and completion" : _reason)}");
        sb.AppendLine($"Steps:        {_steps:N0}");
        sb.AppendLine($"Duration:     {_sw.Elapsed.TotalSeconds:F2}s");
        sb.AppendLine($"Outside:      {_outsideSteps:N0} stop(s)");
        sb.AppendLine($"Decode fails: {_decodeFailures:N0}");
        sb.AppendLine($"Fast-forward: {_stepOverHotCalls:N0} hot direct call(s), {_runThroughHotReps:N0} hot REP string op(s), {_runThroughHotLoops:N0} hot loop exit run(s), {_runThroughIndirectHelpers:N0} indirect helper run-through(s), {_stepOverKnownIndirectHelpers:N0} known indirect helper step-over(s), {_generatedStubCalls:N0} generated stub call(s)");
        sb.AppendLine();

        if (_execRanges.Count > 0)
        {
            sb.AppendLine("Executable Ranges");
            foreach (var r in _execRanges)
                sb.AppendLine($"  {r.Name,-8}  0x{r.Start:X}-0x{r.End:X}");
            sb.AppendLine();
        }

        AppendInterpretation(sb);
        AppendTraceSnapshots(sb);
        AppendSelfCrashSites(sb);
        AppendSehFollows(sb);
        AppendIndirectSites(sb);
        AppendGeneratedStubCalls(sb);
        AppendHotDirectCalls(sb);
        AppendHotIps(sb);
        AppendTailEvents(sb);
        AppendHandlerSamples(sb);
        return sb.ToString();
    }

    private void AppendInterpretation(StringBuilder sb)
    {
        var best = RankedDispatchSites().FirstOrDefault();
        sb.AppendLine("Interpretation");
        if (best is { Targets.Count: >= 3 })
        {
            sb.AppendLine($"  Strong dispatch candidate at 0x{best.Va:X}: {best.Hits:N0} hit(s), {best.Targets.Count:N0} concrete handler target(s).");
            sb.AppendLine("  The handler targets below are runtime-observed entry points; classify them next with handler-body slicing.");
        }
        else if (best is not null)
        {
            sb.AppendLine($"  Weak dispatch candidate at 0x{best.Va:X}: {best.Hits:N0} hit(s), {best.Targets.Count:N0} target(s).");
            sb.AppendLine("  Trace did not run long enough, or the VM uses direct-threaded/tail-dispatch forms that need a wider model.");
        }
        else
        {
            sb.AppendLine("  No indirect VM dispatch candidate executed in the traced window.");
            sb.AppendLine(_sehFollows.Values.Any(f => f.Hits > 0)
                ? "  The deliberate first-chance null-write SEH handler was followed and returned without reaching a VM dispatcher."
                : FindSelfCrashSites().Count > 0
                ? "  The trace ends in a deliberate null-write under freshly-installed SEH, consistent with an anti-debug/anti-tamper self-crash path."
                : _runThroughIndirectHelpers > 0
                ? "  The observed indirect target behaved like an unpacker helper and was skipped; keep tracing to see what runs after it returns."
                : "  If the process exited quickly, the protector likely self-crashed before the VM loop became traceable.");
        }
        sb.AppendLine();
    }

    private void AppendTraceSnapshots(StringBuilder sb)
    {
        sb.AppendLine("Trace Snapshots");
        if (_snapshots.Count == 0)
        {
            sb.AppendLine("  none");
            sb.AppendLine();
            return;
        }

        foreach (var s in _snapshots)
        {
            if (!string.IsNullOrWhiteSpace(s.Error))
            {
                sb.AppendLine($"  {s.Label,-8} step={s.Step:N0}  {s.Error}");
                continue;
            }
            sb.AppendLine($"  {s.Label,-8} step={s.Step:N0}  {s.Section} entropy={s.Entropy:F2} nonzero={s.NonZeroPercent:F1}% size=0x{s.Size:X}");
            sb.AppendLine($"      {s.Path}");
        }
        var best = _snapshots
            .Where(s => string.IsNullOrWhiteSpace(s.Error))
            .OrderBy(s => s.Entropy)
            .FirstOrDefault();
        if (best is not null)
            sb.AppendLine($"  Best snapshot by executable-section entropy: {Path.GetFileName(best.Path)} ({best.Entropy:F2}).");
        sb.AppendLine();
    }

    private void AppendHotDirectCalls(StringBuilder sb)
    {
        sb.AppendLine("Hot Direct Call Targets");
        var hot = _directCallTargets
            .OrderByDescending(kv => kv.Value)
            .ThenBy(kv => kv.Key)
            .Take(16)
            .ToArray();
        if (hot.Length == 0)
        {
            sb.AppendLine("  none");
            sb.AppendLine();
            return;
        }

        foreach (var (target, calls) in hot)
        {
            string text = _events.FirstOrDefault(e => e.Va == target)?.Text ?? "";
            string skipped = _execCounts.GetValueOrDefault(target) >= HotCallTargetThreshold ? " hot-skip" : "";
            sb.AppendLine($"  0x{target:X}  direct-calls={calls:N0} exec-hits={_execCounts.GetValueOrDefault(target):N0}{skipped}  {text}");
        }
        sb.AppendLine();
    }

    private static bool IsRepStringInstruction(in Instruction ins) =>
        ins.HasRepPrefix && ins.Mnemonic is Mnemonic.Movsb or Mnemonic.Movsd or Mnemonic.Movsw
            or Mnemonic.Stosb or Mnemonic.Stosd or Mnemonic.Stosw
            or Mnemonic.Lodsb or Mnemonic.Lodsd or Mnemonic.Lodsw
            or Mnemonic.Cmpsb or Mnemonic.Cmpsd or Mnemonic.Cmpsw
            or Mnemonic.Scasb or Mnemonic.Scasd or Mnemonic.Scasw;

    private static bool IsStringInstruction(in Instruction ins) =>
        ins.Mnemonic is Mnemonic.Movsb or Mnemonic.Movsd or Mnemonic.Movsw
            or Mnemonic.Stosb or Mnemonic.Stosd or Mnemonic.Stosw
            or Mnemonic.Lodsb or Mnemonic.Lodsd or Mnemonic.Lodsw
            or Mnemonic.Cmpsb or Mnemonic.Cmpsd or Mnemonic.Cmpsw
            or Mnemonic.Scasb or Mnemonic.Scasd or Mnemonic.Scasw;

    private bool IsHotBackwardConditionalLoop(ulong ip, in Instruction ins, out ulong[] exitVas)
    {
        exitVas = [];
        if (ins.FlowControl != FlowControl.ConditionalBranch) return false;
        if (FlowAnalysis.DirectBranchTarget(ins) is not { } target || target >= ip) return false;
        if (!IsTargetExecutable(target)) return false;
        if (_execCounts.GetValueOrDefault(ip) < HotLoopThreshold) return false;

        var exits = new SortedSet<ulong>();
        foreach (var ev in _events)
        {
            if (ev.Va < target || ev.Va > ip) continue;
            if (ev.Ins.FlowControl != FlowControl.ConditionalBranch) continue;

            ulong fallthrough = ev.Va + (ulong)ev.Ins.Length;
            if (!IsInRange(fallthrough, target, ip) && IsTargetExecutable(fallthrough))
                exits.Add(fallthrough);

            if (FlowAnalysis.DirectBranchTarget(ev.Ins) is { } branchTarget
                && !IsInRange(branchTarget, target, ip)
                && IsTargetExecutable(branchTarget))
                exits.Add(branchTarget);
        }

        exitVas = exits.Take(8).ToArray();
        return exitVas.Length > 0;
    }

    private static bool IsInRange(ulong va, ulong start, ulong end) => va >= start && va <= end;

    private void ClassifyGeneratedStubCalls()
    {
        foreach (var site in _indirect.Values)
        {
            foreach (var (target, hits) in site.Targets.ToArray())
            {
                if (!IsGeneratedStubTarget(site.Va, target)) continue;
                site.Targets.Remove(target);
                site.GeneratedStubTargets[target] = site.GeneratedStubTargets.GetValueOrDefault(target) + hits;
            }
        }
        _generatedStubCalls = _indirect.Values.Sum(s => s.GeneratedStubTargets.Values.Sum());
    }

    private bool IsGeneratedStubTarget(ulong siteVa, ulong target)
    {
        int targetIdx = _events.FindIndex(e => e.Va == target);
        if (targetIdx < 0) return false;

        bool tinyReturnStub =
            IsZeroingInstruction(_events[targetIdx].Ins, out _)
            && targetIdx + 2 < _events.Count
            && _events[targetIdx + 1].Ins.Mnemonic == Mnemonic.Nop
            && _events[targetIdx + 2].Ins.FlowControl == FlowControl.Return;
        if (tinyReturnStub) return true;

        int siteIdx = _events.FindIndex(e => e.Va == siteVa);
        if (siteIdx < 0) return false;
        int start = Math.Max(0, siteIdx - 8);
        for (int i = start; i < siteIdx; i++)
        {
            var ins = _events[i].Ins;
            if (ins.Mnemonic == Mnemonic.Mov
                && ins.Op0Kind == OpKind.Memory
                && ins.Op1Kind == OpKind.Immediate32
                && ins.Immediate32 == 0xC390C033)
                return true;
        }
        return false;
    }

    private void AppendSelfCrashSites(StringBuilder sb)
    {
        var sites = FindSelfCrashSites();
        sb.AppendLine("Null-write Self-crash Sites");
        if (sites.Count == 0)
        {
            sb.AppendLine("  none");
            sb.AppendLine();
            return;
        }

        foreach (var site in sites.Take(8))
            sb.AppendLine($"  step={site.Step:N0}  0x{site.Va:X}  zero={site.ZeroRegister.ToString().ToLowerInvariant()}  SEH-near={site.SehNearby}  {site.Text}");
        sb.AppendLine();
    }

    private void AppendSehFollows(StringBuilder sb)
    {
        sb.AppendLine("SEH Follow Probes");
        if (_sehFollows.Count == 0)
        {
            sb.AppendLine("  none");
            sb.AppendLine();
            return;
        }

        foreach (var follow in _sehFollows.Values.OrderBy(f => f.HandlerVa))
            sb.AppendLine($"  handler=0x{follow.HandlerVa:X}  fault=0x{follow.FaultVa:X}  armed={follow.Armed:N0}  hits={follow.Hits:N0}");
        sb.AppendLine();
    }

    private List<SelfCrashSite> FindSelfCrashSites()
    {
        var sites = new List<SelfCrashSite>();
        for (int i = 1; i < _events.Count; i++)
        {
            var ev = _events[i];
            if (!IsMemoryWriteThroughRegister(ev.Ins, out var baseReg)) continue;
            if (!IsZeroingInstruction(_events[i - 1].Ins, out var zeroReg)) continue;
            if (baseReg != zeroReg) continue;

            bool sehNearby = _events
                .Skip(Math.Max(0, i - 12))
                .Take(i - Math.Max(0, i - 12))
                .Any(e => e.Text.Contains("fs:[0]", StringComparison.OrdinalIgnoreCase));
            sites.Add(new SelfCrashSite(ev.Step, ev.Va, ev.Text, zeroReg, sehNearby));
        }
        return sites;
    }

    private static bool IsMemoryWriteThroughRegister(in Instruction ins, out Register baseReg)
    {
        baseReg = Register.None;
        if (ins.Op0Kind != OpKind.Memory) return false;
        if (ins.MemoryBase == Register.None) return false;
        if (ins.Mnemonic is not (Mnemonic.Mov or Mnemonic.Xchg or Mnemonic.Add or Mnemonic.Sub or Mnemonic.And
            or Mnemonic.Or or Mnemonic.Xor or Mnemonic.Inc or Mnemonic.Dec)) return false;
        baseReg = ins.MemoryBase;
        return true;
    }

    private static bool IsZeroingInstruction(in Instruction ins, out Register reg)
    {
        reg = Register.None;
        if (ins.Op0Kind != OpKind.Register) return false;

        if (ins.Mnemonic is Mnemonic.Xor or Mnemonic.Sub
            && ins.Op1Kind == OpKind.Register
            && ins.Op0Register == ins.Op1Register)
        {
            reg = ins.Op0Register;
            return true;
        }

        if (ins.Mnemonic == Mnemonic.Mov
            && ins.Op1Kind is OpKind.Immediate8to16 or OpKind.Immediate8to32 or OpKind.Immediate8to64
                or OpKind.Immediate16 or OpKind.Immediate32 or OpKind.Immediate64
            && ins.Immediate64 == 0)
        {
            reg = ins.Op0Register;
            return true;
        }

        return false;
    }

    private void AppendIndirectSites(StringBuilder sb)
    {
        var ranked = RankedSites().Take(12).ToArray();
        sb.AppendLine("Indirect Dispatch Candidates");
        if (ranked.Length == 0)
        {
            sb.AppendLine("  none");
            sb.AppendLine();
            return;
        }

        foreach (var site in ranked)
        {
            sb.AppendLine($"  0x{site.Va:X}  {site.Shape,-14} hits={site.Hits:N0} targets={site.Targets.Count:N0} outside={site.OutsideTargets:N0} helpers={site.HelperSkips:N0}  {site.Text}");
            foreach (var (target, hits) in site.Targets.OrderByDescending(kv => kv.Value).ThenBy(kv => kv.Key).Take(24))
                sb.AppendLine($"      -> 0x{target:X}  hits={hits:N0}{ApiSuffix(target)}");
            foreach (var (target, hits) in site.OutsideTargetSamples.OrderByDescending(kv => kv.Value).ThenBy(kv => kv.Key).Take(8))
                sb.AppendLine($"      -> outside 0x{target:X}  hits={hits:N0}{ApiSuffix(target)}");
            foreach (var (target, hits) in site.HelperTargets.OrderByDescending(kv => kv.Value).ThenBy(kv => kv.Key).Take(8))
                sb.AppendLine($"      -> helper 0x{target:X}  skipped={hits:N0}");
            foreach (var (target, hits) in site.GeneratedStubTargets.OrderByDescending(kv => kv.Value).ThenBy(kv => kv.Key).Take(8))
                sb.AppendLine($"      -> generated-stub 0x{target:X}  hits={hits:N0}");
        }
        sb.AppendLine();
    }

    private void AppendGeneratedStubCalls(StringBuilder sb)
    {
        var generated = _indirect.Values
            .Where(s => s.GeneratedStubTargets.Count > 0)
            .OrderBy(s => s.Va)
            .ToArray();
        sb.AppendLine("Generated Stub Calls");
        if (generated.Length == 0)
        {
            sb.AppendLine("  none");
            sb.AppendLine();
            return;
        }

        foreach (var site in generated)
        {
            foreach (var (target, hits) in site.GeneratedStubTargets.OrderByDescending(kv => kv.Value).ThenBy(kv => kv.Key))
                sb.AppendLine($"  0x{site.Va:X}  {site.Text} -> 0x{target:X}  hits={hits:N0}  ; tiny generated return stub");
        }
        sb.AppendLine();
    }


    private void AppendHotIps(StringBuilder sb)
    {
        sb.AppendLine("Hot Executed Addresses");
        foreach (var (va, hits) in _execCounts.OrderByDescending(kv => kv.Value).ThenBy(kv => kv.Key).Take(24))
        {
            string text = _events.FirstOrDefault(e => e.Va == va)?.Text ?? "";
            sb.AppendLine($"  0x{va:X}  hits={hits:N0}  {text}");
        }
        sb.AppendLine();
    }

    private void AppendTailEvents(StringBuilder sb)
    {
        sb.AppendLine("Tail Executed Instructions");
        if (_events.Count == 0)
        {
            sb.AppendLine("  none");
            sb.AppendLine();
            return;
        }

        foreach (var ev in _events.TakeLast(48))
            sb.AppendLine($"  {ev.Step,8:N0}  0x{ev.Va:X}  {ev.Text}");
        sb.AppendLine();
    }

    private void AppendHandlerSamples(StringBuilder sb)
    {
        var best = RankedDispatchSites().FirstOrDefault();
        if (best is null || best.Targets.Count == 0) return;

        sb.AppendLine("Handler Body Samples");
        foreach (ulong target in best.Targets.OrderByDescending(kv => kv.Value).ThenBy(kv => kv.Key).Take(16).Select(kv => kv.Key))
        {
            int idx = _events.FindIndex(e => e.Va == target);
            if (idx < 0) continue;
            sb.AppendLine($"  Handler 0x{target:X}");
            for (int i = idx; i < _events.Count && i < idx + 16; i++)
            {
                var ev = _events[i];
                sb.AppendLine($"    {ev.Va:X}: {ev.Text}");
                if (i > idx && IsIndirectControl(ev.Ins)) break;
            }
        }
        sb.AppendLine();
    }

    private IEnumerable<IndirectSite> RankedSites() =>
        _indirect.Values
            .Where(s => s.Hits > 0)
            .OrderByDescending(s => s.Targets.Count)
            .ThenByDescending(s => s.Hits)
            .ThenBy(s => s.Va);

    private IEnumerable<IndirectSite> RankedDispatchSites() =>
        _indirect.Values
            .Where(s => s.Targets.Count > 0)
            .OrderByDescending(s => s.Targets.Count)
            .ThenByDescending(s => s.Hits)
            .ThenBy(s => s.Va);

    private static bool IsIndirectControl(in Instruction ins) =>
        ins.FlowControl is FlowControl.IndirectBranch or FlowControl.IndirectCall;

    private static string BranchShape(in Instruction ins) =>
        ins.Op0Kind switch
        {
            OpKind.Register => "jmp/call-reg",
            OpKind.Memory when ins.MemoryIndex != Register.None => "indexed-mem",
            OpKind.Memory => "mem",
            _ => "indirect",
        };

    private string ApiSuffix(ulong va)
    {
        try
        {
            _apiResolver ??= new ModuleExportResolver(_eng.Modules, _eng.ReadMemory);
            if (_apiResolver.Resolve(va) is { } exact)
                return $"  ; {exact.Display}";
            var nearest = _apiResolver.ResolveNearest(va, out uint delta);
            if (nearest is not null && delta <= 0x40)
                return $"  ; {nearest.Display}+0x{delta:X}";
        }
        catch { }

        var mod = _eng.ModuleContaining(va);
        return mod is null ? "" : $"  ; {mod.Name}+0x{va - mod.Base:X}";
    }

    private static string TraceReportPath(string outputPath, string targetPath)
    {
        string path = string.IsNullOrWhiteSpace(outputPath) ? targetPath : outputPath;
        string dir = Path.GetDirectoryName(path) ?? ".";
        string stem = Path.GetFileNameWithoutExtension(path);
        if (string.IsNullOrWhiteSpace(stem))
            stem = Path.GetFileNameWithoutExtension(targetPath);
        return Path.Combine(dir, stem + ".vmtrace.txt");
    }

    private string TraceSnapshotPath(string label)
    {
        string dir = Path.GetDirectoryName(_reportPath) ?? ".";
        string stem = Path.GetFileNameWithoutExtension(_reportPath);
        return Path.Combine(dir, $"{stem}_{label}.bin");
    }

    private sealed record TraceEvent(int Step, ulong Va, string Text, Instruction Ins, ulong Sp);

    private sealed record ActiveIndirectCall(ulong SiteVa, ulong TargetVa, ulong ReturnVa, int EnterStep);

    private sealed record SelfCrashSite(int Step, ulong Va, string Text, Register ZeroRegister, bool SehNearby);

    private sealed record SehFollow(ulong HandlerVa, ulong FaultVa, int Armed, int Hits);

    public readonly record struct TraceResume(ResumeKind Kind, ulong Target, IReadOnlyList<ulong>? Targets = null);

    private sealed record TraceSnapshot(string Label, int Step, string Path, string Section, double Entropy,
        double NonZeroPercent, int Size, string Error);

    private sealed class IndirectSite(ulong va, string text, string shape)
    {
        public ulong Va { get; } = va;
        public string Text { get; } = text;
        public string Shape { get; } = shape;
        public int Hits { get; set; }
        public int OutsideTargets { get; set; }
        public int HelperSkips { get; set; }
        public Dictionary<ulong, int> Targets { get; } = [];
        public Dictionary<ulong, int> OutsideTargetSamples { get; } = [];
        public Dictionary<ulong, int> HelperTargets { get; } = [];
        public Dictionary<ulong, int> GeneratedStubTargets { get; } = [];
    }
}

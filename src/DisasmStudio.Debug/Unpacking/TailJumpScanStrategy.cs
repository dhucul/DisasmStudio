using System.Text;
using DisasmStudio.Core.Unpacking;

namespace DisasmStudio.Debug.Unpacking;

/// <summary>
/// Dynamic OEP detection via instruction-level stub scanning. Reads the stub bytecode from the live
/// process, runs <see cref="StubInstructionTracker"/> to find every far control transfer, validates
/// each candidate against the live section layout and prologue check, then sets a breakpoint at the
/// best candidate and runs to it.
/// <para>
/// This is the dynamic counterpart to <see cref="OepScanner.FindOep"/> — same logic, but operating on
/// live process memory instead of a static dump. Works on any packer whose stub ends with a
/// recognizable control transfer (jmp, push+ret, call), regardless of section layout.
/// </para>
/// </summary>
public sealed class TailJumpScanStrategy : IOepStrategy
{
    private const int StubScanBytes = 0x4000;
    private const ulong FarThreshold = 0x1000;

    private enum Phase { Init, WaitBreakpoint, Done }

    private readonly StringBuilder _log = new();
    private Phase _phase = Phase.Init;
    private ulong _bpVa;
    private bool _wasUserBp;

    public OepMethod Method => OepMethod.TailJumpScan;
    public string Log => _log.ToString();
    public bool IsDone => _phase == Phase.Done;

    public ulong? Begin(DebuggerEngine eng)
    {
        _log.Append("Tail-jump scan: reading stub bytecode and tracking control transfers…\n");

        var code = eng.ReadMemory(eng.EntryPoint, StubScanBytes);
        if (code.Length < 2)
        {
            _log.Append("  Could not read stub memory.\n");
            _phase = Phase.Done;
            return null;
        }

        var hdr = eng.ReadMemory(eng.ImageBase, 0x1000);
        PeView? view = null;
        if (PeView.TryParse(hdr, out var v)) view = v;

        var transfers = StubInstructionTracker.Track(
            (va, n) => eng.ReadMemory(va, n),
            code, eng.EntryPoint, eng.Is64);

        _log.Append($"  Found {transfers.Count} far transfer(s) in the stub.\n");

        // Validate each candidate: must be in an executable section, far from the stub, and prologue-looking.
        foreach (var t in transfers)
        {
            ulong delta = t.Target > eng.EntryPoint ? t.Target - eng.EntryPoint : eng.EntryPoint - t.Target;
            bool far = delta >= FarThreshold;
            bool exec = view is null || OepScanner.IsExecutableVa(view, eng.ImageBase, t.Target);
            var head = eng.ReadMemory(t.Target, 32);
            bool prologue = head.Length >= 2 && OepValidator.LooksLikeOep(head, eng.Is64);

            _log.Append($"    {t.Kind} → {t.Target:X} (delta 0x{delta:X}) — far={far}, exec={exec}, prologue={prologue}\n");

            if (far && exec && prologue)
            {
                _bpVa = t.Target;
                break;
            }
        }

        if (_bpVa == 0)
        {
            _log.Append("  No valid OEP candidate found in stub transfers.\n");
            _phase = Phase.Done;
            return null;
        }

        _wasUserBp = eng.HasBreakpoint(_bpVa);
        if (!eng.TrySetBreakpoint(_bpVa))
        {
            _log.Append($"  Could not set breakpoint at candidate OEP {_bpVa:X}.\n");
            _phase = Phase.Done;
            return null;
        }

        _log.Append($"  Armed breakpoint at candidate OEP {_bpVa:X}; running.\n");
        _phase = Phase.WaitBreakpoint;
        eng.Go();
        return null;
    }

    public ulong? OnStop(DebuggerEngine eng, StopInfo stop)
    {
        // Armed but not yet at the candidate: keep running. Returning without a resume would freeze the
        // ungated host (UnpackSession forwards every stop); once done, returning null is right — IsDone is
        // what tells the host the hunt is over.
        if (_phase != Phase.WaitBreakpoint)
        {
            if (!IsDone) eng.Go();
            return null;
        }

        if (stop.Reason == StopReason.Breakpoint && stop.Address == _bpVa)
        {
            Disarm(eng);
            _log.Append($"OEP candidate (tail-jump scan) at {stop.Address:X}.\n");
            return stop.Address;
        }

        // Unrelated stop — keep running toward the candidate.
        eng.Go();
        return null;
    }

    public bool Owns(DebuggerEngine eng, StopInfo stop) =>
        _phase == Phase.WaitBreakpoint && stop.Reason == StopReason.Breakpoint && stop.Address == _bpVa;

    public void Abort(DebuggerEngine eng)
    {
        Disarm(eng);
        _log.Append("Tail-jump scan aborted.\n");
    }

    private void Disarm(DebuggerEngine eng)
    {
        _phase = Phase.Done;
        if (_bpVa != 0 && !_wasUserBp)
        {
            eng.RemoveBreakpoint(_bpVa);
            _bpVa = 0;
        }
    }
}
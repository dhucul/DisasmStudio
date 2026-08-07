using System.Text;
using DisasmStudio.Core.Unpacking;

namespace DisasmStudio.Debug.Unpacking;

/// <summary>
/// OEP detection via stack-pointer transition. Records the stack pointer at the entry point,
/// then watches for it to return near its original value after the stub deallocates its workspace.
/// When SP returns to entry-SP ± a small delta and the instruction at the current address looks
/// like a prologue, that's the OEP. Works on packers that use a stub stack frame and then
/// tail-call/return to the OEP.
/// </summary>
public sealed class StackTransitionStrategy : IOepStrategy
{
    private const int MaxSteps = 5000;           // safety limit on single-steps
    private const ulong SpDeltaThreshold = 0x100; // SP within this many bytes of entry SP = "returned"

    private enum Phase { Init, Stepping, WaitBreakpoint, Done }

    private readonly StringBuilder _log = new();
    private Phase _phase = Phase.Init;
    private ulong _entrySp;
    private int _stepCount;
    private ulong _bpVa;
    private bool _wasUserBp;

    public OepMethod Method => OepMethod.StackTransition;
    public string Log => _log.ToString();
    public bool IsDone => _phase == Phase.Done;

    public ulong? Begin(DebuggerEngine eng)
    {
        _entrySp = eng.GetRegisters()?.Sp ?? 0;
        if (_entrySp == 0)
        {
            _log.Append("  Could not read stack pointer.\n");
            _phase = Phase.Done;
            return null;
        }

        _log.Append($"Stack transition: entry SP = {_entrySp:X}. Single-stepping (max {MaxSteps} steps)…\n");
        _phase = Phase.Stepping;
        eng.StepInto();
        return null;
    }

    public ulong? OnStop(DebuggerEngine eng, StopInfo stop)
    {
        switch (_phase)
        {
            case Phase.Stepping:
            {
                if (stop.Reason != StopReason.Step)
                {
                    eng.Go();
                    return null;
                }

                _stepCount++;
                ulong sp = eng.GetRegisters()?.Sp ?? 0;

                // Check if SP has returned near the entry value.
                ulong delta = sp > _entrySp ? sp - _entrySp : _entrySp - sp;
                bool spReturned = delta <= SpDeltaThreshold && sp != 0;

                if (spReturned)
                {
                    // SP is back near entry — check if we're at a prologue.
                    var head = eng.ReadMemory(stop.Address, 32);
                    if (head.Length >= 2 && OepValidator.LooksLikeOep(head, eng.Is64))
                    {
                        _log.Append($"  Step {_stepCount}: SP returned to {sp:X} (delta {delta:X}) at {stop.Address:X} — prologue found.\n");
                        _bpVa = stop.Address;
                        _wasUserBp = eng.HasBreakpoint(_bpVa);
                        if (eng.TrySetBreakpoint(_bpVa))
                        {
                            _log.Append($"  Armed breakpoint at {_bpVa:X}; running to confirm.\n");
                            _phase = Phase.WaitBreakpoint;
                            eng.Go();
                            return null;
                        }
                    }
                }

                // Also check for far jumps — if the stub does a jmp to a prologue, catch it.
                if (_stepCount % 100 == 0)
                {
                    var head = eng.ReadMemory(stop.Address, 32);
                    if (head.Length >= 2 && OepValidator.LooksLikeOep(head, eng.Is64))
                    {
                        _log.Append($"  Step {_stepCount}: at {stop.Address:X} — prologue found (SP delta {delta:X}).\n");
                        _bpVa = stop.Address;
                        _wasUserBp = eng.HasBreakpoint(_bpVa);
                        if (eng.TrySetBreakpoint(_bpVa))
                        {
                            _log.Append($"  Armed breakpoint at {_bpVa:X}; running to confirm.\n");
                            _phase = Phase.WaitBreakpoint;
                            eng.Go();
                            return null;
                        }
                    }
                }

                if (_stepCount >= MaxSteps)
                {
                    _log.Append($"  Step limit ({MaxSteps}) reached; no OEP found.\n");
                    _phase = Phase.Done;
                    return null;
                }

                eng.StepInto();
                return null;
            }

            case Phase.WaitBreakpoint:
            {
                if (stop.Reason == StopReason.Breakpoint && stop.Address == _bpVa)
                {
                    _log.Append($"OEP candidate (stack transition) at {stop.Address:X}.\n");
                    _phase = Phase.Done;
                    return stop.Address;
                }
                eng.Go();
                return null;
            }

            default:
                eng.Go();
                return null;
        }
    }

    public bool Owns(DebuggerEngine eng, StopInfo stop) =>
        // Only claim single-step stops that this strategy itself issued (via StepInto).
        // A user-initiated Step or a breakpoint-step from the engine would also report
        // StopReason.Step, but those are not ours — the caller (OepStopRouting) must
        // distinguish them. Since this strategy is the only one single-stepping during
        // its Stepping phase, and UnpackSession runs in a dedicated process with no
        // user breakpoints, claiming all Step stops here is safe in that context.
        (_phase == Phase.Stepping && stop.Reason == StopReason.Step)
        || (_phase == Phase.WaitBreakpoint && stop.Reason == StopReason.Breakpoint && stop.Address == _bpVa);

    public void Abort(DebuggerEngine eng)
    {
        if (_bpVa != 0 && !_wasUserBp) eng.RemoveBreakpoint(_bpVa);
        _phase = Phase.Done;
        _log.Append("Stack transition aborted.\n");
    }
}
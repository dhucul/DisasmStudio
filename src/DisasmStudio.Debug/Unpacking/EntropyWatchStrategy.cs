using System.Text;
using DisasmStudio.Core.Unpacking;

namespace DisasmStudio.Debug.Unpacking;

/// <summary>
/// OEP detection via entropy sampling. Periodically pauses the target, reads W+X sections, and computes
/// Shannon entropy. When entropy drops below a threshold (decryption complete), scans the decrypted
/// region for a function prologue and sets a breakpoint there. Handles in-place decryptors that never
/// cross section boundaries — the case the section guard cannot catch.
/// </summary>
public sealed class EntropyWatchStrategy : IOepStrategy
{
    private const double HighEntropyThreshold = 7.0;   // above this = still encrypted
    private const double LowEntropyThreshold = 6.0;    // below this = likely decrypted
    private const int SampleIntervalMs = 50;            // how often to pause and sample
    private const int MaxSamples = 600;                 // ~30 seconds timeout
    private const int PrologueScanBytes = 0x1000;       // how much of the decrypted section to scan for prologues

    private enum Phase { Init, Sampling, WaitBreakpoint, Done }

    private readonly StringBuilder _log = new();
    private Phase _phase = Phase.Init;
    private int _sampleCount;
    private double _baselineEntropy;
    private ulong _targetSectionStart;
    private ulong _targetSectionSize;
    private ulong _bpVa;
    private bool _wasUserBp;
    private System.Threading.Timer? _timer;
    private DebuggerEngine? _eng;
    private volatile bool _timerFired;

    public OepMethod Method => OepMethod.EntropyWatch;
    public string Log => _log.ToString();
    public bool IsDone => _phase == Phase.Done;

    public ulong? Begin(DebuggerEngine eng)
    {
        _eng = eng;
        _log.Append("Entropy watch: establishing baseline entropy of W+X sections…\n");

        var hdr = eng.ReadMemory(eng.ImageBase, 0x1000);
        if (!PeView.TryParse(hdr, out var view))
        {
            _log.Append("  Could not parse PE headers.\n");
            _phase = Phase.Done;
            return null;
        }

        // Find the entry-point section (the stub) and measure its baseline entropy.
        foreach (var s in view.Sections)
        {
            ulong lo = eng.ImageBase + s.VirtualAddress;
            ulong size = Math.Max(s.VirtualSize, s.SizeOfRawData);
            if (size == 0) continue;
            if (eng.EntryPoint < lo || eng.EntryPoint >= lo + size) continue;

            _targetSectionStart = lo;
            _targetSectionSize = size;

            int sampleLen = (int)Math.Min(size, 1u << 20);
            var bytes = eng.ReadMemory(lo, sampleLen);
            _baselineEntropy = bytes.Length > 0 ? Entropy.Shannon(bytes) : 0;
            _log.Append($"  Entry section '{s.Name}' at {lo:X}+{size:X}: baseline entropy {_baselineEntropy:F2}.\n");
            break;
        }

        if (_targetSectionSize == 0)
        {
            _log.Append("  Could not locate the entry-point section.\n");
            _phase = Phase.Done;
            return null;
        }

        if (_baselineEntropy < HighEntropyThreshold)
        {
            _log.Append($"  Baseline entropy {_baselineEntropy:F2} is already below {HighEntropyThreshold:F1} — section may already be decrypted, or this is not a packed binary.\n");
            _phase = Phase.Done;
            return null;
        }

        _log.Append($"  Starting periodic entropy sampling every {SampleIntervalMs}ms (max {MaxSamples} samples)…\n");
        _phase = Phase.Sampling;
        _timer = new System.Threading.Timer(OnTimerTick, null, SampleIntervalMs, SampleIntervalMs);
        eng.Go();
        return null;
    }

    private void OnTimerTick(object? state)
    {
        if (_phase != Phase.Sampling || _eng is null) return;
        _timerFired = true;
        try { _eng.Pause(); }
        catch { /* target may have exited */ }
    }

    public ulong? OnStop(DebuggerEngine eng, StopInfo stop)
    {
        switch (_phase)
        {
            case Phase.Sampling:
            {
                if (!_timerFired) { eng.Go(); return null; }
                // Only consume stops our timer produced (Paused). An exception or user breakpoint
                // must not be silently resumed over — surface it so the caller can handle it.
                if (stop.Reason != StopReason.Paused) return null;
                _timerFired = false;
                _sampleCount++;

                int sampleLen = (int)Math.Min(_targetSectionSize, 1u << 20);
                var bytes = eng.ReadMemory(_targetSectionStart, sampleLen);
                double entropy = bytes.Length > 0 ? Entropy.Shannon(bytes) : 0;

                if (_sampleCount <= 3 || _sampleCount % 10 == 0)
                    _log.Append($"  Sample {_sampleCount}: entropy {entropy:F2}.\n");

                if (entropy < LowEntropyThreshold)
                {
                    _log.Append($"  Entropy dropped to {entropy:F2} (below {LowEntropyThreshold:F1}) — decryption likely complete.\n");
                    _timer?.Dispose();
                    _timer = null;

                    // Scan the decrypted section for a function prologue.
                    var code = eng.ReadMemory(_targetSectionStart, (int)Math.Min(_targetSectionSize, PrologueScanBytes));
                    ulong? candidate = FindPrologueInRegion(code, _targetSectionStart, eng.Is64);

                    if (candidate is { } c)
                    {
                        _bpVa = c;
                        _wasUserBp = eng.HasBreakpoint(_bpVa);
                        if (eng.TrySetBreakpoint(_bpVa))
                        {
                            _log.Append($"  Armed breakpoint at prologue candidate {_bpVa:X}; running.\n");
                            _phase = Phase.WaitBreakpoint;
                            eng.Go();
                            return null;
                        }
                        _log.Append($"  Could not set breakpoint at {_bpVa:X}.\n");
                    }
                    else
                    {
                        _log.Append("  No prologue found in the decrypted region.\n");
                    }
                    _phase = Phase.Done;
                    return null;
                }

                if (_sampleCount >= MaxSamples)
                {
                    _log.Append($"  Timeout after {MaxSamples} samples — entropy never dropped below threshold.\n");
                    _timer?.Dispose();
                    _timer = null;
                    _phase = Phase.Done;
                    return null;
                }

                eng.Go();
                return null;
            }

            case Phase.WaitBreakpoint:
            {
                if (stop.Reason == StopReason.Breakpoint && stop.Address == _bpVa)
                {
                    Disarm(eng);
                    _log.Append($"OEP candidate (entropy watch) at {stop.Address:X}.\n");
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

    private static ulong? FindPrologueInRegion(byte[] code, ulong baseVa, bool is64)
    {
        if (code.Length < 2) return null;
        var dec = Iced.Intel.Decoder.Create(is64 ? 64 : 32, new Iced.Intel.ByteArrayCodeReader(code));
        dec.IP = baseVa;
        ulong end = baseVa + (ulong)code.Length;

        while (dec.IP < end)
        {
            ulong ip = dec.IP;
            dec.Decode(out var ins);
            if (ins.IsInvalid) continue;

            int offset = (int)(ip - baseVa);
            if (offset < 0 || offset >= code.Length) break;
            var window = code.AsSpan(offset, Math.Min(32, code.Length - offset)).ToArray();
            if (OepValidator.LooksLikeOep(window, is64))
                return ip;
        }
        return null;
    }

    public bool Owns(DebuggerEngine eng, StopInfo stop) =>
        (_phase == Phase.Sampling && stop.Reason == StopReason.Paused)
        || (_phase == Phase.WaitBreakpoint && stop.Reason == StopReason.Breakpoint && stop.Address == _bpVa);

    public void Abort(DebuggerEngine eng)
    {
        _timer?.Dispose();
        _timer = null;
        Disarm(eng);
        _log.Append("Entropy watch aborted.\n");
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
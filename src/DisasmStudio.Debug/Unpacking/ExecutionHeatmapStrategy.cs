using System.Text;
using DisasmStudio.Core.Unpacking;

namespace DisasmStudio.Debug.Unpacking;

/// <summary>
/// OEP detection via execution heatmap. Arms execute memory-breakpoints on ALL executable pages,
/// tracks which pages get hit and how many times. The stub pages get hit early and often; the OEP
/// page is hit once, late, after all stub activity. When a page that hasn't been hit before gets
/// its first execute and contains a prologue, that's the OEP.
/// No prior knowledge of section layout needed — works on packers that decrypt into the same section.
/// </summary>
public sealed class ExecutionHeatmapStrategy : IOepStrategy
{
    private const int MaxHits = 2000;          // total execute faults before giving up

    private enum Phase { Init, Tracking, WaitBreakpoint, Done }

    private readonly StringBuilder _log = new();
    private Phase _phase = Phase.Init;
    private readonly Dictionary<ulong, int> _pageHits = [];   // page VA -> hit count
    private readonly List<(ulong Lo, ulong Hi)> _armedRanges = [];
    private int _totalHits;
    private ulong _bpVa;
    private bool _wasUserBp;

    public OepMethod Method => OepMethod.ExecutionHeatmap;
    public string Log => _log.ToString();
    public bool IsDone => _phase == Phase.Done;

    public ulong? Begin(DebuggerEngine eng)
    {
        _log.Append("Execution heatmap: arming execute breakpoints on all executable pages…\n");

        var hdr = eng.ReadMemory(eng.ImageBase, 0x1000);
        if (!PeView.TryParse(hdr, out var view))
        {
            _log.Append("  Could not parse PE headers.\n");
            _phase = Phase.Done;
            return null;
        }

        int armed = 0;
        foreach (var s in view.Sections)
        {
            if (!s.IsExecutable) continue;
            ulong lo = eng.ImageBase + s.VirtualAddress;
            ulong size = Math.Max(s.VirtualSize, s.SizeOfRawData);
            if (size == 0) continue;

            if (eng.TrySetMemoryBreakpoint(lo, size, MemAccess.Execute))
            {
                _armedRanges.Add((lo, lo + size));
                armed++;
                _log.Append($"  {s.Name,-8} {lo:X}+{size:X} — execute breakpoint armed.\n");
            }
        }

        if (armed == 0)
        {
            _log.Append("  No executable pages could be armed.\n");
            _phase = Phase.Done;
            return null;
        }

        _log.Append($"  Armed {armed} section(s); tracking page hits (max {MaxHits} total)…\n");
        _phase = Phase.Tracking;
        eng.Go();
        return null;
    }

    public ulong? OnStop(DebuggerEngine eng, StopInfo stop)
    {
        switch (_phase)
        {
            case Phase.Tracking:
            {
                if (stop.Reason != StopReason.MemoryBreakpoint)
                {
                    eng.Go();
                    return null;
                }

                ulong hitVa = eng.LastMemoryHitVa;
                ulong page = hitVa & ~0xFFFUL;
                _pageHits[page] = _pageHits.GetValueOrDefault(page) + 1;
                _totalHits++;

                if (_totalHits <= 5 || _totalHits % 50 == 0)
                    _log.Append($"  Hit {_totalHits}: page {page:X} (hit {_pageHits[page]}x).\n");

                // Check if this is a first-hit page that contains a prologue.
                if (_pageHits[page] == 1)
                {
                    var head = eng.ReadMemory(hitVa, 32);
                    if (head.Length >= 2 && OepValidator.LooksLikeOep(head, eng.Is64))
                    {
                        _log.Append($"  First hit on page {page:X} at {hitVa:X} looks like a prologue — OEP candidate.\n");
                        DisarmMemoryBps(eng);
                        _bpVa = hitVa;
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

                // After enough hits, analyze the heatmap for late-appearing pages.
                if (_totalHits >= 100 && _totalHits % 100 == 0)
                {
                    var latePages = _pageHits
                        .Where(kv => kv.Value <= 2)
                        .OrderBy(kv => kv.Value)
                        .Select(kv => kv.Key)
                        .ToList();

                    foreach (var latePage in latePages)
                    {
                        var head = eng.ReadMemory(latePage, 32);
                        if (head.Length >= 2 && OepValidator.LooksLikeOep(head, eng.Is64))
                        {
                            _log.Append($"  Late-appearing page {latePage:X} (hit {_pageHits[latePage]}x) contains a prologue — OEP candidate.\n");
                            DisarmMemoryBps(eng);
                            _bpVa = latePage;
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
                }

                if (_totalHits >= MaxHits)
                {
                    _log.Append($"  Hit limit ({MaxHits}) reached; no OEP found.\n");
                    DisarmMemoryBps(eng);
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
                    _log.Append($"OEP candidate (execution heatmap) at {stop.Address:X}.\n");
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
        (_phase == Phase.Tracking && stop.Reason == StopReason.MemoryBreakpoint && OwnsArmedRange(eng.LastMemoryHitVa))
        || (_phase == Phase.WaitBreakpoint && stop.Reason == StopReason.Breakpoint && stop.Address == _bpVa);

    private bool OwnsArmedRange(ulong va)
    {
        foreach (var (lo, hi) in _armedRanges) if (va >= lo && va < hi) return true;
        return false;
    }

    public void Abort(DebuggerEngine eng)
    {
        DisarmMemoryBps(eng);
        if (_bpVa != 0 && !_wasUserBp) eng.RemoveBreakpoint(_bpVa);
        _phase = Phase.Done;
        _log.Append("Execution heatmap aborted.\n");
    }

    private void DisarmMemoryBps(DebuggerEngine eng)
    {
        foreach (var (lo, _) in _armedRanges)
            eng.RemoveMemoryBreakpoint(lo);
        _armedRanges.Clear();
    }
}
using System.Text;
using DisasmStudio.Core.Unpacking;

namespace DisasmStudio.Debug.Unpacking;

/// <summary>How to locate the Original Entry Point.</summary>
public enum OepMethod
{
    /// <summary>x86: ESP-trick then section guard; x64: section guard.</summary>
    Auto,
    /// <summary>pushad/popad stack-watch, then break when execution leaves the stub (x86 only).</summary>
    EspTrick,
    /// <summary>Guard every non-stub section; break when execution first enters one.</summary>
    SectionGuard,
    /// <summary>Like <see cref="SectionGuard"/>, but arms a whole-section <b>execute memory breakpoint</b>
    /// (<see cref="MemAccess.Execute"/>) on each non-stub section — the same engine path the Memory Map's
    /// "Break on execute (section)" uses — and breaks (<see cref="StopReason.MemoryBreakpoint"/>) the first time
    /// code runs in one. Functionally a twin of the section guard, but it reuses the re-armable memory-breakpoint
    /// machinery (which single-steps the faulting fetch through, so the stop lands one instruction into the OEP).</summary>
    SectionExecBp,
    /// <summary>Break at a user-supplied OEP address.</summary>
    Manual,
    /// <summary>No OEP trace at all: run the target freely (no single-step, no hardware watchpoint, no
    /// section guard) so an aggressive protector isn't tripped by trap-flag / Dr-register detection. Dump
    /// when it faults (anti-tamper self-crash) or after it settles. For VM protectors, where there is no OEP
    /// to find and the intrusive strategies are the very thing that gets detected.</summary>
    RunFree,
    /// <summary>Intrusive VM diagnostics: single-step a bounded window and recover runtime dispatch sites,
    /// concrete handler targets and short handler-body samples. Produces a trace report, not an unpacked PE.</summary>
    TraceVm,
}

/// <summary>
/// Drives the debugger to the Original Entry Point. Strategies build on existing engine primitives — the
/// ESP-trick uses a hardware ReadWrite watchpoint on the pushad-saved registers; the section-guard uses
/// <see cref="DebuggerEngine.GuardRegion"/> to break (<see cref="StopReason.GuardExec"/>) the moment
/// execution transfers into an originally-non-stub section. State machine: callers invoke <see cref="Begin"/>
/// on the entry-point stop, then <see cref="OnStop"/> on each subsequent stop until it returns the OEP.
/// </summary>
public sealed class OepFinder
{
    private enum Phase { Init, StepPushad, WaitPopad, WaitGuard, WaitMemBp, WaitManual, Done }

    private readonly OepMethod _requested;
    private ulong? _manualOep;
    private readonly ulong _staticImageBase;
    private readonly StringBuilder _log = new();
    private Phase _phase = Phase.Init;
    private ulong _entrySp, _espWatch;
    private ulong _entrySectionLo;
    private readonly List<ulong> _execBpStarts = [];   // section execute mem-bp starts armed by SectionExecBp

    public string Log => _log.ToString();
    public OepMethod ActiveMethod { get; private set; }

    public OepFinder(OepMethod method, ulong? manualOep, ulong staticImageBase = 0)
    {
        _requested = method;
        _manualOep = manualOep;
        _staticImageBase = staticImageBase;
    }

    /// <summary>Arm the chosen strategy and issue the first resume. Call on the entry-point stop. Returns a
    /// non-null OEP if it is already reached (e.g. a manual OEP equal to the entry point); otherwise null.</summary>
    public ulong? Begin(DebuggerEngine eng)
    {
        _entrySectionLo = SectionLoContaining(eng, eng.EntryPoint);

        if (_requested == OepMethod.Manual && _manualOep is { } moep)
        {
            // The user types a static VA (file image base); rebase it to the runtime load base for ASLR.
            if (_staticImageBase != 0 && eng.ImageBase != 0 && moep >= _staticImageBase)
                moep = moep - _staticImageBase + eng.ImageBase;
            _manualOep = moep;
            ActiveMethod = OepMethod.Manual;
            if (moep == eng.EntryPoint)   // already at the requested OEP — no breakpoint needed
            {
                _phase = Phase.Done;
                _log.Append($"Manual OEP {moep:X} is the entry point — already there.\n");
                return moep;
            }
            eng.SetBreakpoint(moep);
            _phase = Phase.WaitManual;
            _log.Append($"Manual OEP: breakpoint at {moep:X}.\n");
            eng.Go();
            return null;
        }

        // The ESP-trick relies on pushad, which is x86-only.
        if ((_requested is OepMethod.Auto or OepMethod.EspTrick) && eng.Is32)
        {
            ActiveMethod = OepMethod.EspTrick;
            _entrySp = eng.GetRegisters()?.Sp ?? 0;
            _phase = Phase.StepPushad;
            _log.Append("ESP-trick: single-stepping the stub's first instruction.\n");
            eng.StepInto();
            return null;
        }

        if (_requested == OepMethod.SectionExecBp)
        {
            ActiveMethod = OepMethod.SectionExecBp;
            StartSectionExecBp(eng);
            return null;
        }

        ActiveMethod = OepMethod.SectionGuard;
        StartSectionGuard(eng);
        return null;
    }

    /// <summary>Process a stop. Returns the OEP VA once found, or null when it has issued the next resume.</summary>
    public ulong? OnStop(DebuggerEngine eng, StopInfo stop)
    {
        switch (_phase)
        {
            case Phase.StepPushad:
            {
                ulong sp = eng.GetRegisters()?.Sp ?? 0;
                if (sp != 0 && sp < _entrySp)
                {
                    _espWatch = sp;
                    eng.SetHardwareBreakpoint(sp, HwKind.ReadWrite, eng.Is32 ? 4 : 8);
                    _phase = Phase.WaitPopad;
                    _log.Append($"ESP-trick: armed ReadWrite watch at {sp:X}; running to popad.\n");
                    eng.Go();
                }
                else
                {
                    _log.Append("ESP-trick: stack didn't grow on the first instruction; using section guard.\n");
                    ActiveMethod = OepMethod.SectionGuard;
                    StartSectionGuard(eng);
                }
                return null;
            }
            case Phase.WaitPopad:
            {
                if (stop.Reason == StopReason.Watchpoint)
                {
                    if (_espWatch != 0) eng.RemoveBreakpoint(_espWatch);
                    _log.Append("ESP-trick: popad watch hit; guarding non-stub sections.\n");
                    StartSectionGuard(eng);   // keep ActiveMethod = EspTrick for reporting
                }
                else eng.Go();                // unrelated stop — keep running toward popad
                return null;
            }
            case Phase.WaitGuard:
            {
                if (stop.Reason == StopReason.GuardExec)
                {
                    _phase = Phase.Done;
                    _log.Append($"OEP candidate (guard-exec) at {stop.Address:X}.\n");
                    return stop.Address;
                }
                eng.Go();
                return null;
            }
            case Phase.WaitMemBp:
            {
                if (stop.Reason == StopReason.MemoryBreakpoint)
                {
                    _phase = Phase.Done;
                    foreach (ulong s in _execBpStarts) eng.RemoveMemoryBreakpoint(s);
                    _execBpStarts.Clear();
                    _log.Append($"OEP candidate (section execute-bp) at {stop.Address:X}.\n");
                    return stop.Address;
                }
                eng.Go();
                return null;
            }
            case Phase.WaitManual:
            {
                if (stop.Reason == StopReason.Breakpoint && _manualOep is { } m && stop.Address == m)
                {
                    _phase = Phase.Done;
                    _log.Append($"OEP (manual breakpoint) at {stop.Address:X}.\n");
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

    private void StartSectionGuard(DebuggerEngine eng)
    {
        var hdr = eng.ReadMemory(eng.ImageBase, 0x1000);
        if (PeView.TryParse(hdr, out var view))
        {
            int guarded = 0;
            foreach (var s in view.Sections)
            {
                ulong lo = eng.ImageBase + s.VirtualAddress;
                ulong size = Math.Max(s.VirtualSize, s.SizeOfRawData);
                if (size == 0 || lo == _entrySectionLo) continue;   // never guard the stub's own section
                eng.GuardRegion(lo, size);
                guarded++;
            }
            _log.Append($"Section guard: guarded {guarded} non-stub section(s).\n");
        }
        else _log.Append("Section guard: could not parse the image headers.\n");
        _phase = Phase.WaitGuard;
        eng.Go();
    }

    /// <summary>Arm a whole-section <see cref="MemAccess.Execute"/> memory breakpoint on every non-stub section
    /// (the same engine path as the Memory Map's "Break on execute (section)"), then run. Execution into any of
    /// them faults on the instruction fetch and surfaces a <see cref="StopReason.MemoryBreakpoint"/> — the OEP.</summary>
    private void StartSectionExecBp(DebuggerEngine eng)
    {
        _execBpStarts.Clear();
        var hdr = eng.ReadMemory(eng.ImageBase, 0x1000);
        if (PeView.TryParse(hdr, out var view))
        {
            foreach (var s in view.Sections)
            {
                ulong lo = eng.ImageBase + s.VirtualAddress;
                ulong size = Math.Max(s.VirtualSize, s.SizeOfRawData);
                if (size == 0 || lo == _entrySectionLo) continue;   // never break on the stub's own section
                eng.SetMemoryBreakpoint(lo, size, MemAccess.Execute);
                _execBpStarts.Add(lo);
            }
            _log.Append($"Section execute-bp: armed execute memory breakpoints on {_execBpStarts.Count} non-stub section(s).\n");
        }
        else _log.Append("Section execute-bp: could not parse the image headers.\n");
        _phase = Phase.WaitMemBp;
        eng.Go();
    }

    private static ulong SectionLoContaining(DebuggerEngine eng, ulong va)
    {
        var hdr = eng.ReadMemory(eng.ImageBase, 0x1000);
        if (PeView.TryParse(hdr, out var view))
            foreach (var s in view.Sections)
            {
                ulong lo = eng.ImageBase + s.VirtualAddress;
                ulong hi = lo + Math.Max(s.VirtualSize, s.SizeOfRawData);
                if (va >= lo && va < hi) return lo;
            }
        return 0;
    }
}

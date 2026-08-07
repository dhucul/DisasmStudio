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
    /// <summary>Section spans covered by the execute memory breakpoints armed by <see cref="StartSectionExecBp"/>.
    /// Kept as ranges (not just starts) so <see cref="Owns"/> can tell our own section execute-breakpoint apart
    /// from a user memory breakpoint, which reports the same <see cref="StopReason.MemoryBreakpoint"/>.</summary>
    private readonly List<(ulong Lo, ulong Hi)> _execBps = [];
    /// <summary>The user already had a breakpoint at the manual OEP, so <see cref="Abort"/> must leave it alone.</summary>
    private bool _manualWasUserBp;
    /// <summary>Sections the section-guard strategy actually stripped execute from, so a hunt that ends without
    /// faulting can re-query them and tell "the target undid our guard" from "it never reached the OEP".</summary>
    private readonly List<(string Name, ulong Lo, ulong Size)> _guardedSections = [];

    public string Log => _log.ToString();
    public OepMethod ActiveMethod { get; private set; }
    /// <summary>The hunt has finished (found the OEP, or was aborted) and holds no armed state.</summary>
    public bool IsDone => _phase == Phase.Done;

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
            _manualWasUserBp = eng.HasBreakpoint(moep);   // don't delete the user's own breakpoint on abort
            if (!eng.TrySetBreakpoint(moep))
                throw new InvalidOperationException($"Could not arm manual OEP breakpoint at {moep:X}.");
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
                    // A hardware watchpoint stop carries no indication of which register fired it, so a user's
                    // own watchpoint landing here is indistinguishable from the popad hit and is consumed as
                    // one. Recorded rather than hidden: if the guard then reports a surprising OEP, the log says
                    // this is where the state machine could have been misled.
                    if (_espWatch != 0) { eng.RemoveBreakpoint(_espWatch); _espWatch = 0; }
                    _log.Append($"ESP-trick: watchpoint at {stop.Address:X} taken as the popad hit (a user watchpoint "
                              + "would be indistinguishable here); guarding non-stub sections.\n");
                    StartSectionGuard(eng);   // keep ActiveMethod = EspTrick for reporting
                }
                else eng.Go();                // unrelated stop — keep running toward popad
                return null;
            }
            case Phase.WaitGuard:
            {
                if (stop.Reason == StopReason.GuardExec)
                {
                    Disarm(eng);
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
                    Disarm(eng);
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
                    Disarm(eng);
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
            _guardedSections.Clear();
            foreach (var s in view.Sections)
            {
                ulong lo = eng.ImageBase + s.VirtualAddress;
                ulong size = Math.Max(s.VirtualSize, s.SizeOfRawData);
                bool containsEntry = eng.EntryPoint >= lo && eng.EntryPoint - lo < size;
                if (size == 0 || containsEntry)
                {
                    _log.Append($"  {s.Name,-8} {lo:X}+{size:X} — skipped ({(size == 0 ? "empty" : "holds the entry point")}).\n");
                    continue;
                }
                // Only executable sections can be an OEP: reaching it is an instruction fetch, and the loader
                // only permits that where it mapped the section executable. Walking the rest is not merely
                // useless, it is ruinous — guarding is per 4 KB page, so a resource section (routinely hundreds
                // of megabytes) costs hundreds of thousands of VirtualQueryEx/VirtualProtectEx calls and
                // shatters the target's VA descriptor tree. Cost aside, a non-executable section already faults
                // on a fetch without our help; the only case skipped here is a packer that re-protects a data
                // section to executable at runtime, which by definition would no longer fault anyway.
                if (!s.IsExecutable)
                {
                    _log.Append($"  {s.Name,-8} {lo:X}+{size:X} — skipped (not executable; an OEP cannot be fetched from it).\n");
                    continue;
                }
                if (eng.TryGuardRegion(lo, size))
                {
                    guarded++;
                    _guardedSections.Add((s.Name, lo, size));
                    _log.Append($"  {s.Name,-8} {lo:X}+{size:X} — guarded.\n");
                }
                else _log.Append($"  {s.Name,-8} {lo:X}+{size:X} — could NOT be guarded (uncommitted or already no-access).\n");
            }
            if (guarded == 0)
                throw new InvalidOperationException(
                    "No executable section outside the entry point's own could be guarded — this image's code all "
                  + "lives in the section the entry point is in, so execution never crosses a boundary the guard "
                  + "can catch and the OEP cannot be found this way. Use \"Break at address…\" with a known OEP, "
                  + "or the ESP-trick on a 32-bit target.");
            _log.Append($"Section guard: guarded {guarded} non-stub section(s), {eng.GuardedPageCount} page(s) total.\n");
        }
        else throw new InvalidOperationException("Section guard could not parse the image headers.");
        _phase = Phase.WaitGuard;
        eng.Go();
    }

    /// <summary>Explain why a guard-based hunt ended without ever faulting. The common cause is a stub that
    /// calls <c>VirtualProtect</c> on its own target section after decompressing, which restores the execute bit
    /// we stripped — from the debugger's side that is indistinguishable from "the program never reached the
    /// OEP" unless the page protections are re-queried, which is what this does. Call while the process is
    /// still alive; returns null when nothing conclusive can be said.</summary>
    public string? DiagnoseMissedGuard(DebuggerEngine eng)
    {
        if (_phase != Phase.WaitGuard || _guardedSections.Count == 0) return null;
        var restored = new List<string>();
        foreach (var (name, lo, _) in _guardedSections)
            if (!eng.IsPageNonExecutable(lo)) restored.Add(name);
        if (restored.Count == 0) return null;
        return $"The guard on {string.Join(", ", restored)} is no longer in place — the target re-protected its "
             + "own section(s) (a stub calling VirtualProtect after decompressing), so the code fetch at the OEP "
             + "never faulted. Try the Section execute breakpoint strategy, which re-arms itself, or the "
             + "ESP-trick on a 32-bit target.";
    }

    /// <summary>Arm a whole-section <see cref="MemAccess.Execute"/> memory breakpoint on every non-stub section
    /// (the same engine path as the Memory Map's "Break on execute (section)"), then run. Execution into any of
    /// them faults on the instruction fetch and surfaces a <see cref="StopReason.MemoryBreakpoint"/> — the OEP.</summary>
    private void StartSectionExecBp(DebuggerEngine eng)
    {
        _execBps.Clear();
        var hdr = eng.ReadMemory(eng.ImageBase, 0x1000);
        if (PeView.TryParse(hdr, out var view))
        {
            foreach (var s in view.Sections)
            {
                ulong lo = eng.ImageBase + s.VirtualAddress;
                ulong size = Math.Max(s.VirtualSize, s.SizeOfRawData);
                bool containsEntry = eng.EntryPoint >= lo && eng.EntryPoint - lo < size;
                // Executable sections only, for the same reason as the section guard: an OEP is an instruction
                // fetch, and arming a whole resource/reloc section costs a page-granular walk over hundreds of
                // megabytes for something that can never be the answer.
                if (size == 0 || containsEntry || !s.IsExecutable) continue;
                if (eng.TrySetMemoryBreakpoint(lo, size, MemAccess.Execute))
                    _execBps.Add((lo, lo + size));
            }
            if (_execBps.Count == 0)
                throw new InvalidOperationException(
                    "No executable section outside the entry point's own could be armed — this image's code all "
                  + "lives in the section the entry point is in. Use \"Break at address…\" with a known OEP.");
            _log.Append($"Section execute-bp: armed execute memory breakpoints on {_execBps.Count} non-stub section(s).\n");
        }
        else throw new InvalidOperationException("Section execute breakpoint could not parse the image headers.");
        _phase = Phase.WaitMemBp;
        eng.Go();
    }

    /// <summary>Whether <paramref name="stop"/> is one this finder's current phase produced itself — its own
    /// single-step, ESP watch, section guard, section execute-breakpoint or manual OEP breakpoint.
    /// <para>
    /// An interactive host needs this because <see cref="StopReason"/> is ambiguous: a section execute-breakpoint
    /// and a user memory breakpoint both report <see cref="StopReason.MemoryBreakpoint"/>, and the ESP-trick watch
    /// and a user hardware watchpoint both report <see cref="StopReason.Watchpoint"/>. Only the phase (and, for the
    /// memory breakpoint, which range was hit) can tell them apart. <see cref="UnpackSession"/> drives its own
    /// dedicated process where nothing else plants breakpoints, so it does not need this.
    /// </para></summary>
    public bool Owns(DebuggerEngine eng, StopInfo stop) => _phase switch
    {
        Phase.StepPushad => stop.Reason == StopReason.Step,
        Phase.WaitPopad => stop.Reason == StopReason.Watchpoint,
        Phase.WaitGuard => stop.Reason == StopReason.GuardExec,
        Phase.WaitMemBp => stop.Reason == StopReason.MemoryBreakpoint && OwnsExecBp(eng.LastMemoryHitVa),
        Phase.WaitManual => stop.Reason == StopReason.Breakpoint && _manualOep is { } m && stop.Address == m,
        _ => false,
    };

    private bool OwnsExecBp(ulong va)
    {
        foreach (var (lo, hi) in _execBps) if (va >= lo && va < hi) return true;
        return false;
    }

    /// <summary>Disarm everything this finder planted and park it in the finished phase, without resuming.
    /// Call while the debuggee is stopped. Idempotent, and safe to call after the OEP was already found.
    /// <para>
    /// An interactive host must call this when the user cancels, because the section guards and execute
    /// breakpoints outlive the finder otherwise — a later Continue would then produce a bare
    /// <see cref="StopReason.GuardExec"/> stop that nothing interprets.
    /// </para></summary>
    public void Abort(DebuggerEngine eng)
    {
        Disarm(eng);
        _log.Append("Hunt aborted; guards and breakpoints disarmed.\n");
    }

    /// <summary>Remove the guards, execute breakpoints, ESP watch and manual breakpoint this finder armed.</summary>
    private void Disarm(DebuggerEngine eng)
    {
        _phase = Phase.Done;
        // Guards are only ever armed by this class, so clearing them all is safe.
        if (eng.HasGuards) eng.ClearGuards();
        foreach (var (lo, _) in _execBps) eng.RemoveMemoryBreakpoint(lo);
        _execBps.Clear();
        if (_espWatch != 0) { eng.RemoveBreakpoint(_espWatch); _espWatch = 0; }
        // Leave a breakpoint the user had already set at the manual OEP alone.
        if (_manualOep is { } m && !_manualWasUserBp) { eng.RemoveBreakpoint(m); _manualOep = null; }
    }
}

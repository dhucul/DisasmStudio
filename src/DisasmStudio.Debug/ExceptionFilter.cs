namespace DisasmStudio.Debug;

/// <summary>One row of the exception filter: how to treat one exception code (or an inclusive range).</summary>
public sealed class ExceptionRule
{
    public uint CodeLow { get; set; }
    public uint CodeHigh { get; set; }                 // inclusive; equal to CodeLow for a single code
    public string Name { get; set; } = "";
    public bool BreakFirstChance { get; set; } = true; // stop the UI when this is a first-chance exception
    public bool BreakSecondChance { get; set; } = true;// stop the UI when it comes back unhandled (last chance)
    public bool PassToProgram { get; set; } = true;    // true: the program's own handler runs (DBG_EXCEPTION_NOT_HANDLED);
                                                       // false: the debugger swallows it (DBG_CONTINUE)
}

/// <summary>
/// x64dbg / IDA-style exception policy. For every exception the debugger receives it decides whether to
/// break (stop and surface to the UI) and whether to pass the exception to the debuggee's own handler.
/// The narrowest matching <see cref="Rules"/> entry wins; codes with no entry fall to <see cref="Default"/>.
/// Editable in the UI and persisted across sessions. The out-of-the-box policy reproduces the old
/// behaviour (break on everything, pass to the program) apart from a few noisy codes seeded to not break.
/// </summary>
public sealed class ExceptionFilter
{
    public List<ExceptionRule> Rules { get; set; } = [];
    public ExceptionRule Default { get; set; } = new()
    {
        CodeLow = 0, CodeHigh = uint.MaxValue, Name = "(any other exception)",
        BreakFirstChance = true, BreakSecondChance = true, PassToProgram = true,
    };

    /// <summary>Decide handling for <paramref name="code"/> on this chance. Returns whether to break and
    /// whether to pass the exception to the program.</summary>
    public (bool Break, bool Pass) Decide(uint code, bool firstChance)
    {
        ExceptionRule? best = null;
        ulong bestWidth = ulong.MaxValue;
        foreach (var r in Rules)
        {
            if (code < r.CodeLow || code > r.CodeHigh) continue;
            ulong w = (ulong)r.CodeHigh - r.CodeLow;          // narrowest (most specific) range wins
            if (w < bestWidth) { best = r; bestWidth = w; }
        }
        var rule = best ?? Default;
        return (firstChance ? rule.BreakFirstChance : rule.BreakSecondChance, rule.PassToProgram);
    }

    /// <summary>Add or replace the single-code rule for <paramref name="code"/> (used by "ignore this exception").</summary>
    public void SetCode(uint code, string name, bool breakFirst, bool breakSecond, bool pass)
    {
        var existing = Rules.FirstOrDefault(r => r.CodeLow == code && r.CodeHigh == code);
        if (existing is null) Rules.Add(existing = new ExceptionRule { CodeLow = code, CodeHigh = code });
        existing.Name = name;
        existing.BreakFirstChance = breakFirst;
        existing.BreakSecondChance = breakSecond;
        existing.PassToProgram = pass;
    }

    /// <summary>Common starter policy: break on everything by default, but don't break on the noisy
    /// informational/throw codes debuggers normally let through (debug-print, set-thread-name, C++ EH).</summary>
    public static ExceptionFilter CreateDefault()
    {
        var f = new ExceptionFilter();
        f.Rules.Add(new ExceptionRule { CodeLow = 0x40010006, CodeHigh = 0x40010006, Name = "DBG_PRINTEXCEPTION_C (OutputDebugStringA)", BreakFirstChance = false, BreakSecondChance = false });
        f.Rules.Add(new ExceptionRule { CodeLow = 0x4001000A, CodeHigh = 0x4001000A, Name = "DBG_PRINTEXCEPTION_WIDE_C (OutputDebugStringW)", BreakFirstChance = false, BreakSecondChance = false });
        f.Rules.Add(new ExceptionRule { CodeLow = 0x406D1388, CodeHigh = 0x406D1388, Name = "MS C++ set thread name", BreakFirstChance = false, BreakSecondChance = false });
        f.Rules.Add(new ExceptionRule { CodeLow = 0xE06D7363, CodeHigh = 0xE06D7363, Name = "MS C++ exception (throw)", BreakFirstChance = false, BreakSecondChance = true });
        // A .NET managed exception behaves like a C++ throw: usually handled inside the CLR, so don't break on
        // first chance (a running .NET app raises these routinely), only when it comes back unhandled.
        f.Rules.Add(new ExceptionRule { CodeLow = 0xE0434352, CodeHigh = 0xE0434352, Name = "CLR/.NET exception", BreakFirstChance = false, BreakSecondChance = true });
        // CLR debugger-notification exception: pure noise a .NET process raises under a debugger. The engine
        // swallows it before consulting the filter (DebuggerEngine.HandleException); this row is here so it also
        // shows in the exceptions dialog as a known, never-break code.
        f.Rules.Add(new ExceptionRule { CodeLow = 0x04242420, CodeHigh = 0x04242420, Name = "CLR debugger notification", BreakFirstChance = false, BreakSecondChance = false });
        return f;
    }
}

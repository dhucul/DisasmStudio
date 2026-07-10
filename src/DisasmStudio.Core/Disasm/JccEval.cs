using Iced.Intel;

namespace DisasmStudio.Core.Disasm;

/// <summary>
/// Evaluates whether an x86/x64 conditional jump (Jcc) is taken given a raw EFLAGS/RFLAGS value, and
/// computes the minimal flag change that inverts that outcome. Backs the debugger half of "Toggle jump"
/// (flip the deciding flag so the current Jcc goes the other way) and the live taken/not-taken colouring.
/// Flag-register conditions only — jcxz/jecxz/loop* test CX/ECX, so they report
/// <see cref="ConditionCode.None"/> and cannot be evaluated/toggled here.
/// </summary>
public static class JccEval
{
    // EFLAGS bit positions (match DebugPanel.Flags).
    private const int CF = 0, PF = 2, ZF = 6, SF = 7, OF = 11;

    private static bool Bit(ulong f, int b) => ((f >> b) & 1) != 0;
    private static ulong Set(ulong f, int b, bool on) => on ? f | (1UL << b) : f & ~(1UL << b);

    /// <summary>true = jump taken, false = falls through, null = not a flag-based Jcc (can't evaluate).</summary>
    public static bool? Evaluate(ConditionCode cc, ulong flags)
    {
        bool cf = Bit(flags, CF), pf = Bit(flags, PF), zf = Bit(flags, ZF), sf = Bit(flags, SF), of = Bit(flags, OF);
        return cc switch
        {
            ConditionCode.o => of,
            ConditionCode.no => !of,
            ConditionCode.b => cf,
            ConditionCode.ae => !cf,
            ConditionCode.e => zf,
            ConditionCode.ne => !zf,
            ConditionCode.be => cf || zf,
            ConditionCode.a => !cf && !zf,
            ConditionCode.s => sf,
            ConditionCode.ns => !sf,
            ConditionCode.p => pf,
            ConditionCode.np => !pf,
            ConditionCode.l => sf != of,
            ConditionCode.ge => sf == of,
            ConditionCode.le => zf || (sf != of),
            ConditionCode.g => !zf && (sf == of),
            _ => (bool?)null,
        };
    }

    /// <summary>Whether this condition is decided by flags and can be toggled (false for None/jcxz/loop).</summary>
    public static bool CanToggle(ConditionCode cc) => Evaluate(cc, 0) is not null;

    /// <summary>
    /// Returns <paramref name="flags"/> with the minimal change that inverts <see cref="Evaluate"/>.
    /// Single-flag conditions flip their one bit; compound conditions set the smallest set of bits that
    /// flips the result. Returns the flags unchanged when the condition isn't flag-based.
    /// </summary>
    public static ulong FlipToInvert(ConditionCode cc, ulong flags)
    {
        if (Evaluate(cc, flags) is not bool cur) return flags;
        bool want = !cur;               // the outcome we want after the flip
        bool of = Bit(flags, OF);
        switch (cc)
        {
            case ConditionCode.o: case ConditionCode.no: return Set(flags, OF, !of);
            case ConditionCode.b: case ConditionCode.ae: return Set(flags, CF, !Bit(flags, CF));
            case ConditionCode.e: case ConditionCode.ne: return Set(flags, ZF, !Bit(flags, ZF));
            case ConditionCode.s: case ConditionCode.ns: return Set(flags, SF, !Bit(flags, SF));
            case ConditionCode.p: case ConditionCode.np: return Set(flags, PF, !Bit(flags, PF));

            case ConditionCode.be:      // taken ⇔ CF|ZF
            case ConditionCode.a:       // taken ⇔ !(CF|ZF)
            {
                bool orTrue = cc == ConditionCode.be ? want : !want;    // desired value of (CF|ZF)
                return orTrue ? Set(flags, ZF, true) : Set(Set(flags, CF, false), ZF, false);
            }
            case ConditionCode.l:       // taken ⇔ SF!=OF
            case ConditionCode.ge:      // taken ⇔ SF==OF
            {
                bool neTrue = cc == ConditionCode.l ? want : !want;     // desired value of (SF!=OF)
                return Set(flags, SF, neTrue ? !of : of);
            }
            case ConditionCode.le:      // taken ⇔ ZF | (SF!=OF)
            case ConditionCode.g:       // taken ⇔ !ZF & (SF==OF)
            {
                bool orTrue = cc == ConditionCode.le ? want : !want;    // desired value of (ZF | (SF!=OF))
                return orTrue ? Set(flags, ZF, true)
                              : Set(Set(flags, ZF, false), SF, of);     // ZF=0 and SF==OF ⇒ expression false
            }
            default: return flags;
        }
    }

    /// <summary>Short label of which flag(s) a toggle flips, for a status message (e.g. "ZF", "CF/ZF").</summary>
    public static string FlipDescription(ConditionCode cc) => cc switch
    {
        ConditionCode.o or ConditionCode.no => "OF",
        ConditionCode.b or ConditionCode.ae => "CF",
        ConditionCode.e or ConditionCode.ne => "ZF",
        ConditionCode.s or ConditionCode.ns => "SF",
        ConditionCode.p or ConditionCode.np => "PF",
        ConditionCode.be or ConditionCode.a => "CF/ZF",
        ConditionCode.l or ConditionCode.ge => "SF/OF",
        ConditionCode.le or ConditionCode.g => "ZF/SF/OF",
        _ => "",
    };
}

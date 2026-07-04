using DisasmStudio.Core.Formats;
using Iced.Intel;

namespace DisasmStudio.Core.IL;

/// <summary>
/// The one place the decompiler's medium-level transforms and emitters get their architecture-specific
/// register roles and calling convention. Everything else in the IL back-end (structuring, emission,
/// propagation/DCE framework) is arch-neutral and drives off this. <see cref="X86Model"/> reproduces the
/// original hard-coded x86/x64 + Win64 behaviour exactly; the ARM models add AAPCS / AAPCS64.
/// </summary>
public abstract class ArchModel
{
    /// <summary>Collapse a register to the canonical identity its sub-registers share (x86: eax→rax;
    /// AArch64: w0→x0). Register liveness, slot keys and the propagation environment key on this.</summary>
    public abstract RegId Canon(RegId canonOrSub);

    /// <summary>The stack pointer (rsp / sp).</summary>
    public abstract bool IsStackPtr(RegId canon);

    /// <summary>A register that anchors a <c>[base + disp]</c> stack slot (stack pointer or frame pointer).</summary>
    public abstract bool IsFrameBase(RegId canon);

    /// <summary>A callee-saved register whose prologue/epilogue save-restore is frame bookkeeping.</summary>
    public abstract bool IsCalleeSaved(RegId canon);

    /// <summary>Does writing <paramref name="dest"/> wholly overwrite the location (so a dead one can be
    /// dropped)? A sub-register write that preserves the rest is read-modify, not a kill.</summary>
    public abstract bool IsFullDef(Expr dest);

    /// <summary>Integer argument registers in order (for call-argument recovery). Empty ⇒ no recovery.</summary>
    public abstract IReadOnlyList<RegId> ArgRegs { get; }

    /// <summary>The integer return register (rax / x0 / r0).</summary>
    public abstract RegId ReturnReg { get; }

    /// <summary>Is a <c>[base + disp]</c> slot an incoming stack argument (vs. a local)? x86: <c>rbp</c>
    /// with a positive displacement.</summary>
    public abstract bool IsArgSlot(RegId baseCanon, long disp);

    public static ArchModel For(IBinaryImage image) => image.Arch switch
    {
        Architecture.Arm64 => new Arm64Model(),
        Architecture.Arm or Architecture.Thumb => new Arm32Model(),
        _ => new X86Model(image.Bitness == 64),
    };

    /// <summary>A safe default (x86-64) for code paths that build an <c>IlWriter</c> without a specific
    /// model (e.g. error notes) and never emit register/return tokens through it.</summary>
    public static readonly ArchModel Default = new X86Model(true);
}

/// <summary>The x86/x64 model — a behaviour-preserving wrapper over the values that used to be hard-coded
/// in <c>MediumLifter</c>/<c>IlEmit</c>. Register identity delegates to Iced via the tag carried in
/// <see cref="RegId"/>, so canonicalization is provably the same as before.</summary>
public sealed class X86Model : ArchModel
{
    private readonly bool _is64;
    public X86Model(bool is64) => _is64 = is64;

    /// <summary>The single Iced→neutral bridge: name (lowercased, as the emitter used to print),
    /// byte width, and the Iced enum value as the opaque tag.</summary>
    public static RegId FromIced(Register r) => new(r.ToString().ToLowerInvariant(), r.GetSize(), (int)r);
    private static Register Iced(RegId r) => (Register)r.Tag;

    public override RegId Canon(RegId r)
    {
        var ir = Iced(r);
        return FromIced(ir.IsGPR() ? ir.GetFullRegister() : ir);
    }

    public override bool IsStackPtr(RegId canon) => Iced(canon) == Register.RSP;

    public override bool IsFrameBase(RegId canon) => Iced(canon) is Register.RSP or Register.RBP;

    public override bool IsCalleeSaved(RegId canon) => Iced(canon) is
        Register.RBX or Register.RBP or Register.RSI or Register.RDI or Register.RSP
        or Register.R12 or Register.R13 or Register.R14 or Register.R15;

    public override bool IsFullDef(Expr dest) => dest is VarExpr || (dest is RegExpr re && re.Reg.Width >= 4);

    private static readonly RegId[] _args =
        [FromIced(Register.RCX), FromIced(Register.RDX), FromIced(Register.R8), FromIced(Register.R9)];
    public override IReadOnlyList<RegId> ArgRegs => _args;

    public override RegId ReturnReg => FromIced(Register.RAX);

    public override bool IsArgSlot(RegId baseCanon, long disp) => Iced(baseCanon) == Register.RBP && disp > 0;
}

/// <summary>The AArch64 (ARM64) model — AAPCS64. Registers are identified by name (no Iced tag). A 32-bit
/// <c>w&lt;N&gt;</c> view is the low half of <c>x&lt;N&gt;</c> and a write to it zero-extends the whole
/// register, so both canonicalize to <c>x&lt;N&gt;</c> and any GP write is a full definition.</summary>
public sealed class Arm64Model : ArchModel
{
    public override RegId Canon(RegId r)
    {
        string n = r.Name;
        if (n.Length >= 2 && n[0] == 'w' && char.IsDigit(n[1])) return new RegId("x" + n[1..], 8);
        return n switch
        {
            "wzr" => new RegId("xzr", 8),
            "wsp" => new RegId("sp", 8),
            _ => r.Width == 8 ? r : new RegId(n, r.Width),
        };
    }

    public override bool IsStackPtr(RegId canon) => canon.Name == "sp";

    public override bool IsFrameBase(RegId canon) => canon.Name is "sp" or "x29";

    public override bool IsCalleeSaved(RegId canon) => canon.Name is
        "x19" or "x20" or "x21" or "x22" or "x23" or "x24" or "x25" or "x26" or "x27" or "x28"
        or "x29" or "x30" or "sp";

    // Any GP register write on AArch64 fully defines its 64-bit register (a w-write zero-extends x).
    public override bool IsFullDef(Expr dest) => dest is VarExpr or RegExpr;

    private static readonly RegId[] _args =
    [
        new("x0", 8), new("x1", 8), new("x2", 8), new("x3", 8),
        new("x4", 8), new("x5", 8), new("x6", 8), new("x7", 8),
    ];
    public override IReadOnlyList<RegId> ArgRegs => _args;

    public override RegId ReturnReg => new("x0", 8);

    // Conservative for the first slice: recover register args (x0–x7); leave stack slots as locals.
    public override bool IsArgSlot(RegId baseCanon, long disp) => false;
}

/// <summary>The 32-bit ARM / Thumb model — AAPCS. Registers are 32-bit with no sub-register aliasing;
/// <c>fp</c>/<c>ip</c>/<c>sp</c>/<c>lr</c>/<c>pc</c> are the ABI names Capstone emits.</summary>
public sealed class Arm32Model : ArchModel
{
    public override RegId Canon(RegId r) => r;   // no partial-register views on A32

    public override bool IsStackPtr(RegId canon) => canon.Name == "sp";

    public override bool IsFrameBase(RegId canon) => canon.Name is "sp" or "fp" or "r11" or "r7";

    public override bool IsCalleeSaved(RegId canon) => canon.Name is
        "r4" or "r5" or "r6" or "r7" or "r8" or "r9" or "r10" or "r11" or "fp" or "sp" or "lr";

    public override bool IsFullDef(Expr dest) => dest is VarExpr or RegExpr;

    private static readonly RegId[] _args = [new("r0", 4), new("r1", 4), new("r2", 4), new("r3", 4)];
    public override IReadOnlyList<RegId> ArgRegs => _args;

    public override RegId ReturnReg => new("r0", 4);

    public override bool IsArgSlot(RegId baseCanon, long disp) => false;
}

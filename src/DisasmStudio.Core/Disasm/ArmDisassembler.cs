using System.Text;
using DisasmStudio.Core.Formats;
using Gee.External.Capstone;
using Gee.External.Capstone.Arm;
using Gee.External.Capstone.Arm64;

namespace DisasmStudio.Core.Disasm;

/// <summary>
/// The ARM-family <see cref="INeutralDisassembler"/> — Capstone-backed decode + formatting for 32-bit ARM,
/// Thumb/Thumb-2, and AArch64. Decodes a ≤4-byte window at a VA and takes the first instruction (every ARM
/// instruction is ≤4 bytes), which fits the views' on-demand "decode only the visible rows" model. Flow is
/// mapped from Capstone's instruction groups + condition code + operand shape; the <see cref="Format"/> path
/// tokenises Capstone's mnemonic/operand text into coloured runs and substitutes a known symbol name for a
/// direct branch/call target. Not thread-safe — one instance per view/analysis thread (matches the Iced path).
/// </summary>
public sealed class ArmDisassembler : INeutralDisassembler, IDisposable
{
    private static readonly AsmToken[] Empty = [];

    private readonly IBinaryImage _image;
    private readonly IReadOnlyDictionary<ulong, string>? _names;
    private readonly bool _is64;
    private readonly CapstoneArmDisassembler? _arm;      // ARM + Thumb
    private readonly CapstoneArm64Disassembler? _a64;    // AArch64

    public ArmDisassembler(IBinaryImage image, Architecture arch, IReadOnlyDictionary<ulong, string>? names)
    {
        _image = image;
        _names = names;
        _is64 = arch == Architecture.Arm64;
        if (_is64)
        {
            _a64 = CapstoneDisassembler.CreateArm64Disassembler(Arm64DisassembleMode.Arm | Arm64DisassembleMode.LittleEndian);
            _a64.EnableInstructionDetails = true;
        }
        else
        {
            var mode = (arch == Architecture.Thumb ? ArmDisassembleMode.Thumb : ArmDisassembleMode.Arm)
                       | ArmDisassembleMode.LittleEndian;
            _arm = CapstoneDisassembler.CreateArmDisassembler(mode);
            _arm.EnableInstructionDetails = true;
        }
    }

    public void Dispose() { _arm?.Dispose(); _a64?.Dispose(); }

    public bool TryDecode(ulong va, out NeutralInsn insn)
    {
        insn = Decode(va)?.Insn ?? default;
        return insn.Length > 0;
    }

    public IReadOnlyList<AsmToken> Format(ulong va)
    {
        var d = Decode(va);
        return d is null ? Empty : Tokenize(d.Value.Mnemonic, d.Value.Operand, d.Value.Insn.DirectTarget);
    }

    private readonly record struct Decoded(string Mnemonic, string Operand, NeutralInsn Insn);

    private Decoded? Decode(ulong va)
    {
        byte[] buf = _image.ReadBytesAtVa(va, 4);
        if (buf.Length == 0) return null;
        if (_is64)
        {
            var a = _a64!.Disassemble(buf, (long)va);
            if (a.Length == 0) return null;
            var i = a[0];
            return new Decoded(i.Mnemonic, i.Operand, MapA64(i));
        }
        var arr = _arm!.Disassemble(buf, (long)va);
        if (arr.Length == 0) return null;
        var ins = arr[0];
        return new Decoded(ins.Mnemonic, ins.Operand, MapArm(ins));
    }

    // ---- flow mapping ----

    private static NeutralInsn MapArm(ArmInstruction i)
    {
        bool call = false, jump = false;
        foreach (var g in i.Details.Groups)
        {
            if (g.Name == "call") call = true;
            else if (g.Name == "jump") jump = true;
        }

        ulong? imm = null;
        foreach (var op in i.Details.Operands)
            if (op.Type == ArmOperandType.Immediate) imm = (ulong)(uint)op.Immediate;   // last immediate = the branch target

        string m = i.Mnemonic;
        bool firstRegPc = FirstRegIs(i, "pc");

        FlowKind k;
        // Return: pop {…,pc}, bx lr, mov pc,lr. Capstone has no ARM "ret" group, so detect by shape.
        if ((m == "pop" && HasReg(i, "pc")) || (m == "bx" && FirstRegIs(i, "lr")) || (m == "mov" && firstRegPc && HasReg(i, "lr")))
            k = FlowKind.Ret;
        else if (call)
            k = imm is not null ? FlowKind.Call : FlowKind.IndirectCall;      // bl #imm vs blx reg
        else if (jump)
            // cbz/cbnz are compare-and-branch: conditional, but carry no ARM condition code (would read as AL).
            k = imm is not null
                ? (IsUnconditional(i.Details.ConditionCode) && m is not ("cbz" or "cbnz") ? FlowKind.Jump : FlowKind.CondJump)
                : FlowKind.IndirectJump;                                      // bx/blx reg, tbb/tbh
        else if (firstRegPc)
            k = FlowKind.IndirectJump;                                        // ldr/add/mov pc,… (pc-write not grouped as jump)
        else
            k = FlowKind.Seq;

        ulong? target = k is FlowKind.Jump or FlowKind.CondJump or FlowKind.Call ? imm : null;
        return new NeutralInsn(i.Bytes.Length, k, target);
    }

    private static bool IsUnconditional(ArmConditionCode cc) =>
        cc is ArmConditionCode.ARM_CC_AL or ArmConditionCode.Invalid;

    private static bool HasReg(ArmInstruction i, string name) =>
        i.Details.Operands.Any(o => o.Type == ArmOperandType.Register && o.Register.Name == name);

    private static bool FirstRegIs(ArmInstruction i, string name)
    {
        var ops = i.Details.Operands;
        return ops.Length > 0 && ops[0].Type == ArmOperandType.Register && ops[0].Register.Name == name;
    }

    // AArch64 has real ret/br/blr/bl/b(.cond); classify by mnemonic (robust without leaning on group names).
    private static NeutralInsn MapA64(Arm64Instruction i)
    {
        ulong? imm = null;
        foreach (var op in i.Details.Operands)
            if (op.Type == Arm64OperandType.Immediate) imm = (ulong)op.Immediate;   // last immediate (tbz/tbnz target follows the bit index)

        string m = i.Mnemonic;
        FlowKind k = m switch
        {
            "ret" => FlowKind.Ret,
            "bl" => FlowKind.Call,
            "blr" => FlowKind.IndirectCall,
            "br" => FlowKind.IndirectJump,
            "b" => FlowKind.Jump,
            "cbz" or "cbnz" or "tbz" or "tbnz" => FlowKind.CondJump,
            _ when m.StartsWith("b.", StringComparison.Ordinal) => FlowKind.CondJump,
            _ => FlowKind.Seq,
        };
        ulong? target = k is FlowKind.Jump or FlowKind.CondJump or FlowKind.Call ? imm : null;
        return new NeutralInsn(i.Bytes.Length, k, target);
    }

    // ---- formatting ----

    /// <summary>Tokenise Capstone's mnemonic + operand text into coloured runs. For a direct branch/call whose
    /// target has a known name, the operand is replaced by that symbol so the listing reads <c>bl sub_1234</c>.</summary>
    private IReadOnlyList<AsmToken> Tokenize(string mnemonic, string operand, ulong? directTarget)
    {
        var toks = new List<AsmToken>(8) { new(mnemonic, AsmTokenKind.Mnemonic) };
        if (directTarget is ulong t && _names is not null && _names.TryGetValue(t, out var name))
        {
            toks.Add(new(" ", AsmTokenKind.Text));
            toks.Add(new(name, AsmTokenKind.Symbol));
            return toks;
        }
        if (string.IsNullOrEmpty(operand)) return toks;
        toks.Add(new(" ", AsmTokenKind.Text));

        int n = operand.Length;
        for (int p = 0; p < n;)
        {
            char c = operand[p];
            if (IsWordChar(c))
            {
                int s = p;
                while (p < n && IsWordChar(operand[p])) p++;
                string w = operand[s..p];
                toks.Add(new(w, ClassifyWord(w)));
            }
            else
            {
                toks.Add(new(c.ToString(), c == ' ' ? AsmTokenKind.Text : AsmTokenKind.Punctuation));
                p++;
            }
        }
        return toks;
    }

    private static bool IsWordChar(char c) => char.IsLetterOrDigit(c) || c == '_' || c == '.';

    private static readonly HashSet<string> RegAliases =
        ["sp", "lr", "pc", "ip", "fp", "sb", "sl", "xzr", "wzr", "wsp"];
    private static readonly HashSet<string> ShiftKeywords =
        ["lsl", "lsr", "asr", "ror", "rrx", "uxtb", "uxth", "sxtb", "sxth", "uxtw", "sxtw", "uxtx", "sxtx"];

    private static AsmTokenKind ClassifyWord(string w)
    {
        if (RegAliases.Contains(w)) return AsmTokenKind.Register;
        if (ShiftKeywords.Contains(w)) return AsmTokenKind.Keyword;
        char c0 = w[0];
        // rN / xN / wN / dN / qN / sN / vN / bN / hN → a core or SIMD register.
        if (w.Length >= 2 && c0 is 'r' or 'x' or 'w' or 'd' or 'q' or 's' or 'v' or 'b' or 'h'
            && char.IsDigit(w[1])) return AsmTokenKind.Register;
        if (char.IsDigit(c0)) return AsmTokenKind.Number;   // 0x…, decimal
        return AsmTokenKind.Text;
    }
}

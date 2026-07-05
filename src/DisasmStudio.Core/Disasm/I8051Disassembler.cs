using System.Text;
using DisasmStudio.Core.Formats;

namespace DisasmStudio.Core.Disasm;

/// <summary>
/// The Intel 8051 / MCS-51 <see cref="INeutralDisassembler"/> — a hand-written decoder for the 8-bit
/// microcontroller core used by MediaTek/PLDS optical-drive firmware (and countless embedded ROMs).
/// Neither Iced (x86-only) nor Capstone (no 8051) covers it, so this is a self-contained decoder over the
/// full 256-opcode map: 1–3-byte instructions, a 16-bit code space, and branch targets that are absolute
/// (LJMP/LCALL), 11-bit page-relative (AJMP/ACALL), or PC-relative (SJMP and the conditional jumps).
/// Addresses are treated as VAs so a raw image loaded at base 0 resolves branch targets directly. Not
/// thread-safe — one instance per view/analysis thread (matches the Iced/ARM paths).
/// </summary>
public sealed class I8051Disassembler : INeutralDisassembler
{
    private static readonly AsmToken[] Empty = [];
    private readonly IBinaryImage _image;
    private readonly IReadOnlyDictionary<ulong, string>? _names;
    private readonly HashSet<string> _nameSet;

    public I8051Disassembler(IBinaryImage image, IReadOnlyDictionary<ulong, string>? names)
    {
        _image = image;
        _names = names;
        _nameSet = names is null ? [] : [.. names.Values];
    }

    public bool TryDecode(ulong va, out NeutralInsn insn)
    {
        var d = Decode(va);
        insn = d?.Insn ?? default;
        return insn.Length > 0;
    }

    public IReadOnlyList<AsmToken> Format(ulong va)
    {
        var d = Decode(va);
        return d is null ? Empty : Tokenize(d.Value);
    }

    // ---- standard SFR + bit naming -------------------------------------------------------------
    private static readonly Dictionary<int, string> Sfr = new()
    {
        [0x80] = "P0", [0x81] = "SP", [0x82] = "DPL", [0x83] = "DPH", [0x87] = "PCON",
        [0x88] = "TCON", [0x89] = "TMOD", [0x8A] = "TL0", [0x8B] = "TL1", [0x8C] = "TH0",
        [0x8D] = "TH1", [0x90] = "P1", [0x98] = "SCON", [0x99] = "SBUF", [0xA0] = "P2",
        [0xA8] = "IE", [0xB0] = "P3", [0xB8] = "IP", [0xD0] = "PSW", [0xE0] = "ACC", [0xF0] = "B",
    };

    private static string Hex(int v)
    {
        string h = v.ToString("X");
        return (h[0] >= 'A' ? "0" + h : h) + "h";     // keep a leading digit so it tokenises as a Number
    }

    private static string Dir(int a) => Sfr.TryGetValue(a, out var n) ? n : Hex(a);

    private static string Bit(int b)
    {
        if (b < 0x80) return $"{Hex(0x20 + (b >> 3))}.{b & 7}";
        int baseAddr = b & 0xF8;
        return $"{(Sfr.TryGetValue(baseAddr, out var n) ? n : Hex(baseAddr))}.{b & 7}";
    }

    // ---- instruction lengths (full 256-opcode map) --------------------------------------------
    private static int OpLen(byte op)
    {
        switch (op)
        {
            case 0x02: case 0x12: case 0x90: case 0x75: case 0x85: case 0x43: case 0x53:
            case 0x63: case 0xB4: case 0xB5: case 0xB6: case 0xB7: case 0x10: case 0x20:
            case 0x30: case 0xD5:
                return 3;
        }
        if (op is 0x00 or 0x03 or 0x04 or 0x06 or 0x07 or 0x13 or 0x14 or 0x16 or 0x17 or 0x22
            or 0x23 or 0x32 or 0x33 or 0x73 or 0x83 or 0x84 or 0x93 or 0xA3 or 0xA4 or 0xA5
            or 0xB3 or 0xC3 or 0xC4 or 0xC6 or 0xC7 or 0xD3 or 0xD4 or 0xD6 or 0xD7 or 0xE0
            or 0xE2 or 0xE3 or 0xE4 or 0xE6 or 0xE7 or 0xF0 or 0xF2 or 0xF3 or 0xF4 or 0xF6 or 0xF7)
            return 1;
        int hi = op & 0xF0, lo = op & 0x0F;
        if (lo >= 0x08 && hi is 0x00 or 0x10 or 0x20 or 0x30 or 0x40 or 0x50 or 0x60
            or 0x90 or 0xC0 or 0xE0 or 0xF0) return 1;   // Rn one-byte families
        if (op is >= 0xB8 and <= 0xBF) return 3;          // CJNE Rn,#imm,rel
        if (op is >= 0xD8 and <= 0xDF) return 2;          // DJNZ Rn,rel
        return 2;
    }

    private readonly record struct Decoded(string Mnemonic, string Operand, NeutralInsn Insn, ulong? Target);

    private Decoded? Decode(ulong va)
    {
        byte[] b = _image.ReadBytesAtVa(va, 3);
        if (b.Length == 0) return null;
        byte op = b[0];
        int len = OpLen(op);
        byte b1 = b.Length > 1 ? b[1] : (byte)0;
        byte b2 = b.Length > 2 ? b[2] : (byte)0;
        int r = op & 7;

        string m, oper = "";
        FlowKind flow = FlowKind.Seq;
        ulong? target = null;

        // PC-relative target = next-VA + signed disp (a true VA — resolves at any load base).
        ulong Rel(byte rb) => va + (ulong)len + (ulong)(long)(sbyte)rb;
        // Absolute (LJMP/LCALL) and 11-bit page (AJMP/ACALL) targets are 16-bit CPU code addresses;
        // they resolve directly when the image is loaded at its natural base (16-bit code space, base 0).
        ulong Abs() => (uint)((b1 << 8) | b2);
        ulong A11() => ((va + 2) & 0xF800) | (uint)(((op & 0xE0) << 3) | b1);

        switch (op)
        {
            case 0x00: m = "NOP"; break;
            case 0x02: m = "LJMP"; target = Abs(); flow = FlowKind.Jump; oper = Tgt(target.Value); break;
            case 0x12: m = "LCALL"; target = Abs(); flow = FlowKind.Call; oper = Tgt(target.Value); break;
            case 0x22: m = "RET"; flow = FlowKind.Ret; break;
            case 0x32: m = "RETI"; flow = FlowKind.Ret; break;
            case 0x03: m = "RR"; oper = "A"; break;
            case 0x13: m = "RRC"; oper = "A"; break;
            case 0x23: m = "RL"; oper = "A"; break;
            case 0x33: m = "RLC"; oper = "A"; break;
            case 0x04: m = "INC"; oper = "A"; break;
            case 0x05: m = "INC"; oper = Dir(b1); break;
            case 0x06: m = "INC"; oper = "@R0"; break;
            case 0x07: m = "INC"; oper = "@R1"; break;
            case 0x14: m = "DEC"; oper = "A"; break;
            case 0x15: m = "DEC"; oper = Dir(b1); break;
            case 0x16: m = "DEC"; oper = "@R0"; break;
            case 0x17: m = "DEC"; oper = "@R1"; break;
            case 0x84: m = "DIV"; oper = "AB"; break;
            case 0xA4: m = "MUL"; oper = "AB"; break;
            case 0xD4: m = "DA"; oper = "A"; break;
            case 0xC4: m = "SWAP"; oper = "A"; break;
            case 0xE4: m = "CLR"; oper = "A"; break;
            case 0xF4: m = "CPL"; oper = "A"; break;
            case 0xC3: m = "CLR"; oper = "C"; break;
            case 0xD3: m = "SETB"; oper = "C"; break;
            case 0xB3: m = "CPL"; oper = "C"; break;
            case 0xA3: m = "INC"; oper = "DPTR"; break;
            case 0x93: m = "MOVC"; oper = "A,@A+DPTR"; break;
            case 0x83: m = "MOVC"; oper = "A,@A+PC"; break;
            case 0x73: m = "JMP"; oper = "@A+DPTR"; flow = FlowKind.IndirectJump; break;
            case 0xE0: m = "MOVX"; oper = "A,@DPTR"; break;
            case 0xF0: m = "MOVX"; oper = "@DPTR,A"; break;
            case 0xE2: m = "MOVX"; oper = "A,@R0"; break;
            case 0xE3: m = "MOVX"; oper = "A,@R1"; break;
            case 0xF2: m = "MOVX"; oper = "@R0,A"; break;
            case 0xF3: m = "MOVX"; oper = "@R1,A"; break;
            case 0x90: m = "MOV"; oper = $"DPTR,#{Hex((b1 << 8) | b2)}"; break;
            case 0x74: m = "MOV"; oper = $"A,#{Hex(b1)}"; break;
            case 0x75: m = "MOV"; oper = $"{Dir(b1)},#{Hex(b2)}"; break;
            case 0x76: m = "MOV"; oper = $"@R0,#{Hex(b1)}"; break;
            case 0x77: m = "MOV"; oper = $"@R1,#{Hex(b1)}"; break;
            case 0x85: m = "MOV"; oper = $"{Dir(b2)},{Dir(b1)}"; break;
            case 0x86: m = "MOV"; oper = $"{Dir(b1)},@R0"; break;
            case 0x87: m = "MOV"; oper = $"{Dir(b1)},@R1"; break;
            case 0xE5: m = "MOV"; oper = $"A,{Dir(b1)}"; break;
            case 0xE6: m = "MOV"; oper = "A,@R0"; break;
            case 0xE7: m = "MOV"; oper = "A,@R1"; break;
            case 0xF5: m = "MOV"; oper = $"{Dir(b1)},A"; break;
            case 0xF6: m = "MOV"; oper = "@R0,A"; break;
            case 0xF7: m = "MOV"; oper = "@R1,A"; break;
            case 0xA6: m = "MOV"; oper = $"@R0,{Dir(b1)}"; break;
            case 0xA7: m = "MOV"; oper = $"@R1,{Dir(b1)}"; break;
            case 0x24: m = "ADD"; oper = $"A,#{Hex(b1)}"; break;
            case 0x25: m = "ADD"; oper = $"A,{Dir(b1)}"; break;
            case 0x26: m = "ADD"; oper = "A,@R0"; break;
            case 0x27: m = "ADD"; oper = "A,@R1"; break;
            case 0x34: m = "ADDC"; oper = $"A,#{Hex(b1)}"; break;
            case 0x35: m = "ADDC"; oper = $"A,{Dir(b1)}"; break;
            case 0x36: m = "ADDC"; oper = "A,@R0"; break;
            case 0x37: m = "ADDC"; oper = "A,@R1"; break;
            case 0x94: m = "SUBB"; oper = $"A,#{Hex(b1)}"; break;
            case 0x95: m = "SUBB"; oper = $"A,{Dir(b1)}"; break;
            case 0x96: m = "SUBB"; oper = "A,@R0"; break;
            case 0x97: m = "SUBB"; oper = "A,@R1"; break;
            case 0x44: m = "ORL"; oper = $"A,#{Hex(b1)}"; break;
            case 0x45: m = "ORL"; oper = $"A,{Dir(b1)}"; break;
            case 0x46: m = "ORL"; oper = "A,@R0"; break;
            case 0x47: m = "ORL"; oper = "A,@R1"; break;
            case 0x42: m = "ORL"; oper = $"{Dir(b1)},A"; break;
            case 0x43: m = "ORL"; oper = $"{Dir(b1)},#{Hex(b2)}"; break;
            case 0x54: m = "ANL"; oper = $"A,#{Hex(b1)}"; break;
            case 0x55: m = "ANL"; oper = $"A,{Dir(b1)}"; break;
            case 0x56: m = "ANL"; oper = "A,@R0"; break;
            case 0x57: m = "ANL"; oper = "A,@R1"; break;
            case 0x52: m = "ANL"; oper = $"{Dir(b1)},A"; break;
            case 0x53: m = "ANL"; oper = $"{Dir(b1)},#{Hex(b2)}"; break;
            case 0x64: m = "XRL"; oper = $"A,#{Hex(b1)}"; break;
            case 0x65: m = "XRL"; oper = $"A,{Dir(b1)}"; break;
            case 0x66: m = "XRL"; oper = "A,@R0"; break;
            case 0x67: m = "XRL"; oper = "A,@R1"; break;
            case 0x62: m = "XRL"; oper = $"{Dir(b1)},A"; break;
            case 0x63: m = "XRL"; oper = $"{Dir(b1)},#{Hex(b2)}"; break;
            case 0xC0: m = "PUSH"; oper = Dir(b1); break;
            case 0xD0: m = "POP"; oper = Dir(b1); break;
            case 0xC5: m = "XCH"; oper = $"A,{Dir(b1)}"; break;
            case 0xC6: m = "XCH"; oper = "A,@R0"; break;
            case 0xC7: m = "XCH"; oper = "A,@R1"; break;
            case 0xD6: m = "XCHD"; oper = "A,@R0"; break;
            case 0xD7: m = "XCHD"; oper = "A,@R1"; break;
            case 0x72: m = "ORL"; oper = $"C,{Bit(b1)}"; break;
            case 0x82: m = "ANL"; oper = $"C,{Bit(b1)}"; break;
            case 0xA0: m = "ORL"; oper = $"C,/{Bit(b1)}"; break;
            case 0xB0: m = "ANL"; oper = $"C,/{Bit(b1)}"; break;
            case 0xA2: m = "MOV"; oper = $"C,{Bit(b1)}"; break;
            case 0x92: m = "MOV"; oper = $"{Bit(b1)},C"; break;
            case 0xC2: m = "CLR"; oper = Bit(b1); break;
            case 0xD2: m = "SETB"; oper = Bit(b1); break;
            case 0xB2: m = "CPL"; oper = Bit(b1); break;
            case 0x40: m = "JC"; target = Rel(b1); flow = FlowKind.CondJump; oper = Tgt(target.Value); break;
            case 0x50: m = "JNC"; target = Rel(b1); flow = FlowKind.CondJump; oper = Tgt(target.Value); break;
            case 0x60: m = "JZ"; target = Rel(b1); flow = FlowKind.CondJump; oper = Tgt(target.Value); break;
            case 0x70: m = "JNZ"; target = Rel(b1); flow = FlowKind.CondJump; oper = Tgt(target.Value); break;
            case 0x80: m = "SJMP"; target = Rel(b1); flow = FlowKind.Jump; oper = Tgt(target.Value); break;
            case 0x10: m = "JBC"; target = Rel(b2); flow = FlowKind.CondJump; oper = $"{Bit(b1)},{Tgt(target.Value)}"; break;
            case 0x20: m = "JB"; target = Rel(b2); flow = FlowKind.CondJump; oper = $"{Bit(b1)},{Tgt(target.Value)}"; break;
            case 0x30: m = "JNB"; target = Rel(b2); flow = FlowKind.CondJump; oper = $"{Bit(b1)},{Tgt(target.Value)}"; break;
            case 0xB4: m = "CJNE"; target = Rel(b2); flow = FlowKind.CondJump; oper = $"A,#{Hex(b1)},{Tgt(target.Value)}"; break;
            case 0xB5: m = "CJNE"; target = Rel(b2); flow = FlowKind.CondJump; oper = $"A,{Dir(b1)},{Tgt(target.Value)}"; break;
            case 0xB6: m = "CJNE"; target = Rel(b2); flow = FlowKind.CondJump; oper = $"@R0,#{Hex(b1)},{Tgt(target.Value)}"; break;
            case 0xB7: m = "CJNE"; target = Rel(b2); flow = FlowKind.CondJump; oper = $"@R1,#{Hex(b1)},{Tgt(target.Value)}"; break;
            case 0xD5: m = "DJNZ"; target = Rel(b2); flow = FlowKind.CondJump; oper = $"{Dir(b1)},{Tgt(target.Value)}"; break;
            default:
                if (op is >= 0x08 and <= 0x0F) { m = "INC"; oper = $"R{r}"; }
                else if (op is >= 0x18 and <= 0x1F) { m = "DEC"; oper = $"R{r}"; }
                else if (op is >= 0x28 and <= 0x2F) { m = "ADD"; oper = $"A,R{r}"; }
                else if (op is >= 0x38 and <= 0x3F) { m = "ADDC"; oper = $"A,R{r}"; }
                else if (op is >= 0x48 and <= 0x4F) { m = "ORL"; oper = $"A,R{r}"; }
                else if (op is >= 0x58 and <= 0x5F) { m = "ANL"; oper = $"A,R{r}"; }
                else if (op is >= 0x68 and <= 0x6F) { m = "XRL"; oper = $"A,R{r}"; }
                else if (op is >= 0x78 and <= 0x7F) { m = "MOV"; oper = $"R{r},#{Hex(b1)}"; }
                else if (op is >= 0x88 and <= 0x8F) { m = "MOV"; oper = $"{Dir(b1)},R{r}"; }
                else if (op is >= 0x98 and <= 0x9F) { m = "SUBB"; oper = $"A,R{r}"; }
                else if (op is >= 0xA8 and <= 0xAF) { m = "MOV"; oper = $"R{r},{Dir(b1)}"; }
                else if (op is >= 0xB8 and <= 0xBF) { m = "CJNE"; target = Rel(b2); flow = FlowKind.CondJump; oper = $"R{r},#{Hex(b1)},{Tgt(target.Value)}"; }
                else if (op is >= 0xC8 and <= 0xCF) { m = "XCH"; oper = $"A,R{r}"; }
                else if (op is >= 0xD8 and <= 0xDF) { m = "DJNZ"; target = Rel(b1); flow = FlowKind.CondJump; oper = $"R{r},{Tgt(target.Value)}"; }
                else if (op is >= 0xE8 and <= 0xEF) { m = "MOV"; oper = $"A,R{r}"; }
                else if (op is >= 0xF8 and <= 0xFF) { m = "MOV"; oper = $"R{r},A"; }
                else if ((op & 0x1F) == 0x01)      // AJMP / ACALL (addr11)
                {
                    target = A11();
                    if ((op & 0x10) != 0) { m = "ACALL"; flow = FlowKind.Call; }
                    else { m = "AJMP"; flow = FlowKind.Jump; }
                    oper = Tgt(target.Value);
                }
                else { m = ".db"; oper = Hex(op); len = 1; }
                break;
        }

        return new Decoded(m, oper, new NeutralInsn(len, flow, target), target);
    }

    /// <summary>Render a branch/call target as its known symbol name, else its full-VA hex address.</summary>
    private string Tgt(ulong va)
    {
        if (_names is not null && _names.TryGetValue(va, out var n)) return n;
        string h = va.ToString("X");
        return (h[0] >= 'A' ? "0" + h : h) + "h";
    }

    // ---- formatting -----------------------------------------------------------------------------
    private static readonly HashSet<string> Registers =
        ["A", "AB", "C", "DPTR", "R0", "R1", "R2", "R3", "R4", "R5", "R6", "R7",
         "P0", "P1", "P2", "P3", "SP", "DPL", "DPH", "PCON", "TCON", "TMOD",
         "TL0", "TL1", "TH0", "TH1", "SCON", "SBUF", "IE", "IP", "PSW", "ACC", "B"];

    private IReadOnlyList<AsmToken> Tokenize(Decoded d)
    {
        var toks = new List<AsmToken>(8) { new(d.Mnemonic, AsmTokenKind.Mnemonic) };
        if (d.Operand.Length == 0) return toks;
        toks.Add(new(" ", AsmTokenKind.Text));

        string s = d.Operand;
        for (int p = 0; p < s.Length;)
        {
            char c = s[p];
            if (char.IsLetterOrDigit(c) || c == '_' || c == '.')
            {
                int st = p;
                while (p < s.Length && (char.IsLetterOrDigit(s[p]) || s[p] == '_' || s[p] == '.')) p++;
                toks.Add(new(s[st..p], Classify(s[st..p])));
            }
            else
            {
                toks.Add(new(c.ToString(), c == ' ' ? AsmTokenKind.Text : AsmTokenKind.Punctuation));
                p++;
            }
        }
        return toks;
    }

    private AsmTokenKind Classify(string w)
    {
        if (Registers.Contains(w)) return AsmTokenKind.Register;
        char c0 = w[0];
        if (char.IsDigit(c0)) return AsmTokenKind.Number;                 // 05h, 474Dh, 20h.1 (bit)
        if (_nameSet.Contains(w) || w.StartsWith("loc_") || w.StartsWith("sub_")) return AsmTokenKind.Symbol;
        return AsmTokenKind.Text;
    }
}

using System.Globalization;
using Iced.Intel;
using static Iced.Intel.AssemblerRegisters;

namespace DisasmStudio.Core.Analysis;

/// <summary>
/// Assembles x86/x64 instructions to machine code for patching, via Iced's encoder. Covers the common
/// reverse-engineering patch set (nops, returns, branches to an address, and simple reg/imm ALU/mov
/// ops); anything outside it returns an error so the caller can fall back to raw-byte editing.
/// </summary>
public static class Patcher
{
    public readonly record struct AsmResult(byte[]? Bytes, string? Error)
    {
        public bool Ok => Bytes is not null;
    }

    /// <summary>A run of NOPs (0x90), e.g. to blank out an instruction.</summary>
    public static byte[] Nop(int length)
    {
        var b = new byte[Math.Max(0, length)];
        Array.Fill(b, (byte)0x90);
        return b;
    }

    /// <summary>Right-pad assembled code with NOPs so it exactly fills <paramref name="targetLen"/> bytes.</summary>
    public static byte[] PadNop(byte[] code, int targetLen)
    {
        if (code.Length >= targetLen) return code;
        var r = new byte[targetLen];
        Array.Copy(code, r, code.Length);
        for (int i = code.Length; i < targetLen; i++) r[i] = 0x90;
        return r;
    }

    /// <summary>Assemble one or more instructions (separated by ';' or newlines) encoded at <paramref name="rip"/>.</summary>
    public static AsmResult Assemble(int bitness, ulong rip, string text)
    {
        if (bitness != 16 && bitness != 32 && bitness != 64) bitness = 64;
        var asm = new Assembler(bitness);
        foreach (var line in text.Split([';', '\n', '\r'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            string? err = EmitOne(asm, line);
            if (err is not null) return new AsmResult(null, err);
        }
        try
        {
            var ms = new MemoryStream();
            asm.Assemble(new StreamCodeWriter(ms), rip);
            return new AsmResult(ms.ToArray(), null);
        }
        catch (Exception ex) { return new AsmResult(null, ex.Message); }
    }

    private static string? EmitOne(Assembler a, string line)
    {
        var sp = line.Split([' ', '\t'], 2, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        string mn = sp[0].ToLowerInvariant();
        string[] ops = sp.Length > 1 ? sp[1].Split(',', StringSplitOptions.TrimEntries) : [];

        // no operands
        if (ops.Length == 0)
        {
            switch (mn)
            {
                case "nop": a.nop(); return null;
                case "ret": case "retn": a.ret(); return null;
                case "int3": case "cc": a.int3(); return null;
                case "leave": a.leave(); return null;
                case "cdq": a.cdq(); return null;
                case "cqo": a.cqo(); return null;
                case "pause": a.pause(); return null;
                case "hlt": a.hlt(); return null;
                case "ud2": a.ud2(); return null;
                case "stc": a.stc(); return null;
                case "clc": a.clc(); return null;
                case "cld": a.cld(); return null;
                case "std": a.std(); return null;
                case "cmc": a.cmc(); return null;
                default: return $"unsupported: {mn}";
            }
        }

        // branch to an address
        if (ops.Length == 1 && TryAddr(ops[0], out ulong t))
        {
            switch (mn)
            {
                case "jmp": a.jmp(t); return null;
                case "call": a.call(t); return null;
                case "je": case "jz": a.je(t); return null;
                case "jne": case "jnz": a.jne(t); return null;
                case "ja": case "jnbe": a.ja(t); return null;
                case "jae": case "jnb": case "jnc": a.jae(t); return null;
                case "jb": case "jc": case "jnae": a.jb(t); return null;
                case "jbe": case "jna": a.jbe(t); return null;
                case "jg": case "jnle": a.jg(t); return null;
                case "jge": case "jnl": a.jge(t); return null;
                case "jl": case "jnge": a.jl(t); return null;
                case "jle": case "jng": a.jle(t); return null;
                case "jo": a.jo(t); return null;
                case "jno": a.jno(t); return null;
                case "js": a.js(t); return null;
                case "jns": a.jns(t); return null;
                case "jp": case "jpe": a.jp(t); return null;
                case "jnp": case "jpo": a.jnp(t); return null;
            }
        }

        // unary register
        if (ops.Length == 1)
        {
            bool r64 = TryReg64(ops[0], out var u64);
            bool r32 = TryReg32(ops[0], out var u32);
            switch (mn)
            {
                case "push": if (r64) { a.push(u64); return null; } if (r32) { a.push(u32); return null; } break;
                case "pop": if (r64) { a.pop(u64); return null; } if (r32) { a.pop(u32); return null; } break;
                case "inc": if (r64) { a.inc(u64); return null; } if (r32) { a.inc(u32); return null; } break;
                case "dec": if (r64) { a.dec(u64); return null; } if (r32) { a.dec(u32); return null; } break;
                case "neg": if (r64) { a.neg(u64); return null; } if (r32) { a.neg(u32); return null; } break;
                case "not": if (r64) { a.not(u64); return null; } if (r32) { a.not(u32); return null; } break;
            }
        }

        // two operands: reg, reg | reg, imm
        if (ops.Length == 2)
        {
            string d = ops[0], s = ops[1];
            if (TryReg64(d, out var d64))
            {
                if (TryReg64(s, out var s64)) return Bin64(a, mn, d64, s64);
                if (TryImm(s, out long imm)) return Bin64i(a, mn, d64, imm);
            }
            else if (TryReg32(d, out var d32))
            {
                if (TryReg32(s, out var s32)) return Bin32(a, mn, d32, s32);
                if (TryImm(s, out long imm)) return Bin32i(a, mn, d32, imm);
            }
        }
        return $"can't assemble: {line}";
    }

    private static string? Bin64(Assembler a, string mn, AssemblerRegister64 d, AssemblerRegister64 s)
    {
        switch (mn)
        {
            case "mov": a.mov(d, s); return null;
            case "add": a.add(d, s); return null;
            case "sub": a.sub(d, s); return null;
            case "xor": a.xor(d, s); return null;
            case "and": a.and(d, s); return null;
            case "or": a.or(d, s); return null;
            case "cmp": a.cmp(d, s); return null;
            case "test": a.test(d, s); return null;
            default: return $"unsupported: {mn}";
        }
    }
    private static string? Bin64i(Assembler a, string mn, AssemblerRegister64 d, long imm)
    {
        if (mn != "mov" && (imm < int.MinValue || imm > int.MaxValue))
            return "immediate does not fit a sign-extended 32-bit operand";

        int i32 = unchecked((int)imm);   // ALU ops on r64 take a sign-extended imm32; mov takes the full imm64
        switch (mn)
        {
            case "mov": a.mov(d, imm); return null;
            case "add": a.add(d, i32); return null;
            case "sub": a.sub(d, i32); return null;
            case "xor": a.xor(d, i32); return null;
            case "and": a.and(d, i32); return null;
            case "or": a.or(d, i32); return null;
            case "cmp": a.cmp(d, i32); return null;
            case "test": a.test(d, i32); return null;
            default: return $"unsupported: {mn}";
        }
    }
    private static string? Bin32(Assembler a, string mn, AssemblerRegister32 d, AssemblerRegister32 s)
    {
        switch (mn)
        {
            case "mov": a.mov(d, s); return null;
            case "add": a.add(d, s); return null;
            case "sub": a.sub(d, s); return null;
            case "xor": a.xor(d, s); return null;
            case "and": a.and(d, s); return null;
            case "or": a.or(d, s); return null;
            case "cmp": a.cmp(d, s); return null;
            case "test": a.test(d, s); return null;
            default: return $"unsupported: {mn}";
        }
    }
    private static string? Bin32i(Assembler a, string mn, AssemblerRegister32 d, long imm)
    {
        if (imm < int.MinValue || imm > uint.MaxValue)
            return "immediate does not fit a 32-bit operand";

        int bits = unchecked((int)imm);
        switch (mn)
        {
            case "mov": a.mov(d, bits); return null;
            case "add": a.add(d, bits); return null;
            case "sub": a.sub(d, bits); return null;
            case "xor": a.xor(d, bits); return null;
            case "and": a.and(d, bits); return null;
            case "or": a.or(d, bits); return null;
            case "cmp": a.cmp(d, bits); return null;
            case "test": a.test(d, bits); return null;
            default: return $"unsupported: {mn}";
        }
    }

    private static bool TryImm(string s, out long v)
    {
        s = s.Trim();
        bool neg = s.StartsWith('-');
        if (neg) s = s[1..].Trim();
        bool ok;
        if (s.EndsWith("h", StringComparison.OrdinalIgnoreCase))             // MASM hex suffix: 1Fh
            ok = long.TryParse(s.AsSpan(0, s.Length - 1), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out v);
        else if (s.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            ok = long.TryParse(s.AsSpan(2), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out v);
        else
            ok = long.TryParse(s, NumberStyles.Integer, CultureInfo.InvariantCulture, out v);
        if (neg) v = -v;
        return ok;
    }

    private static bool TryAddr(string s, out ulong v)
    {
        s = s.Trim();
        if (s.EndsWith("h", StringComparison.OrdinalIgnoreCase)) s = s[..^1];   // MASM hex suffix: 140001000h
        else if (s.StartsWith("0x", StringComparison.OrdinalIgnoreCase)) s = s[2..];
        return ulong.TryParse(s, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out v);
    }

    private static bool TryReg64(string s, out AssemblerRegister64 r) => R64.TryGetValue(s.Trim().ToLowerInvariant(), out r);
    private static bool TryReg32(string s, out AssemblerRegister32 r) => R32.TryGetValue(s.Trim().ToLowerInvariant(), out r);

    private static readonly Dictionary<string, AssemblerRegister64> R64 = new()
    {
        ["rax"] = rax, ["rbx"] = rbx, ["rcx"] = rcx, ["rdx"] = rdx, ["rsi"] = rsi, ["rdi"] = rdi, ["rbp"] = rbp, ["rsp"] = rsp,
        ["r8"] = r8, ["r9"] = r9, ["r10"] = r10, ["r11"] = r11, ["r12"] = r12, ["r13"] = r13, ["r14"] = r14, ["r15"] = r15,
    };
    private static readonly Dictionary<string, AssemblerRegister32> R32 = new()
    {
        ["eax"] = eax, ["ebx"] = ebx, ["ecx"] = ecx, ["edx"] = edx, ["esi"] = esi, ["edi"] = edi, ["ebp"] = ebp, ["esp"] = esp,
        ["r8d"] = r8d, ["r9d"] = r9d, ["r10d"] = r10d, ["r11d"] = r11d, ["r12d"] = r12d, ["r13d"] = r13d, ["r14d"] = r14d, ["r15d"] = r15d,
    };
}

using System.Text;
using DisasmStudio.Core.Disasm;
using DisasmStudio.Core.Formats;
using Iced.Intel;

namespace DisasmStudio.Core.Analysis;

/// <summary>
/// Annotates Windows API call sites with the called function's parameters and — IDA/BN-style — the
/// argument values it can recover by a short backward scan over the instructions that set them up
/// (x64 register args rcx/rdx/r8/r9; x86 stack pushes). Resolved immediates become strings, symbol
/// names, or hex; anything it can't prove is shown as the parameter name. Annotations are written into
/// the shared comment map, so they render inline like every other comment.
/// </summary>
public static class ApiAnnotator
{
    private const int MaxAnnotationLen = 140;

    public static void Annotate(
        IBinaryImage image, LinearIndex linear,
        IReadOnlyList<(ulong CallVa, string Import)> callSites,
        IReadOnlyDictionary<ulong, string> names,
        IReadOnlyDictionary<ulong, FoundString> stringByVa,
        Dictionary<ulong, string> comments)
    {
        var dis = new Disassembler(image);
        foreach (var (callVa, import) in callSites)
        {
            var sig = ApiDatabase.Lookup(import);
            if (sig is null) continue;
            comments[callVa] = Build(image, linear, dis, callVa, sig, names, stringByVa);
        }
    }

    private static string Build(IBinaryImage image, LinearIndex linear, Disassembler dis, ulong callVa,
        ApiSignature sig, IReadOnlyDictionary<ulong, string> names, IReadOnlyDictionary<ulong, FoundString> stringByVa)
    {
        var values = ResolveArgs(image, linear, dis, callVa, sig.Params, names, stringByVa);
        var sb = new StringBuilder();
        sb.Append(sig.Name).Append('(');
        for (int i = 0; i < sig.Params.Count; i++)
        {
            if (i > 0) sb.Append(", ");
            sb.Append(values[i] is { } v ? $"{sig.Params[i].Name}={v}" : sig.Params[i].Name);
            if (sb.Length > MaxAnnotationLen) { sb.Append(", …"); break; }
        }
        sb.Append(')');
        return sb.ToString();
    }

    private static string?[] ResolveArgs(IBinaryImage image, LinearIndex linear, Disassembler dis, ulong callVa,
        IReadOnlyList<ApiParam> ps, IReadOnlyDictionary<ulong, string> names, IReadOnlyDictionary<ulong, FoundString> stringByVa)
    {
        var res = new string?[ps.Count];
        if (ps.Count == 0) return res;
        long idx = linear.IndexOf(callVa);
        if (linear.VaAt(idx) != callVa) return res;

        return image.Bitness == 64
            ? ResolveX64(image, linear, dis, idx, ps, names, stringByVa, res)
            : ResolveX86(image, linear, dis, idx, ps, names, stringByVa, res);
    }

    // x64: args 0..3 come from rcx/rdx/r8/r9; args 4+ are stored on the stack at [rsp+0x20], [rsp+0x28], …
    // (past the 32-byte shadow space). Walk back, taking the last writer of each.
    private static string?[] ResolveX64(IBinaryImage image, LinearIndex linear, Disassembler dis, long idx,
        IReadOnlyList<ApiParam> ps, IReadOnlyDictionary<ulong, string> names, IReadOnlyDictionary<ulong, FoundString> stringByVa, string?[] res)
    {
        int count = ps.Count;
        var done = new bool[count];
        int doneCount = 0;
        for (long k = idx - 1; k >= 0 && idx - k <= 28 && doneCount < count; k--)
        {
            if (!dis.TryDecodeAt(linear.VaAt(k), out var ins)) break;
            if (StopsScan(ins)) break;

            if (ins.Op0Kind == OpKind.Register)
            {
                int ai = ArgReg(ins.Op0Register);
                if (ai < 0 || ai >= count || done[ai]) continue;
                res[ai] = DescribeWrite(image, ins, names, stringByVa, FlagDecoder.For(ps[ai].Decode));
                done[ai] = true;
                doneCount++;
            }
            else if (ins.Mnemonic == Mnemonic.Mov && ins.Op0Kind == OpKind.Memory
                     && ins.MemoryBase == Register.RSP && ins.MemoryIndex == Register.None && IsImm(ins.Op1Kind))
            {
                // mov [rsp+0x20 + 8*(i-4)], imm — a stack-passed argument set to a constant.
                long off = (long)ins.MemoryDisplacement64;
                if (off < 0x20 || (off - 0x20) % 8 != 0) continue;
                int ai = 4 + (int)((off - 0x20) / 8);
                if (ai >= count || done[ai]) continue;
                res[ai] = DescribeValue(image, ins.GetImmediate(1), names, stringByVa, FlagDecoder.For(ps[ai].Decode));
                done[ai] = true;
                doneCount++;
            }
        }
        return res;
    }

    // x86 stdcall/cdecl: args are pushed right-to-left, so the first push seen scanning back is arg 0.
    private static string?[] ResolveX86(IBinaryImage image, LinearIndex linear, Disassembler dis, long idx,
        IReadOnlyList<ApiParam> ps, IReadOnlyDictionary<ulong, string> names, IReadOnlyDictionary<ulong, FoundString> stringByVa, string?[] res)
    {
        int found = 0;
        for (long k = idx - 1; k >= 0 && idx - k <= 48 && found < ps.Count; k--)
        {
            if (!dis.TryDecodeAt(linear.VaAt(k), out var ins)) break;
            if (StopsScan(ins)) break;
            if (ins.Mnemonic != Mnemonic.Push) continue;
            res[found] = DescribePush(image, ins, names, stringByVa, FlagDecoder.For(ps[found].Decode));
            found++;
        }
        return res;
    }

    /// <summary>Stop the backward scan at anything that ends the call's argument set-up region.</summary>
    private static bool StopsScan(in Instruction ins) => ins.FlowControl is
        FlowControl.Call or FlowControl.IndirectCall or FlowControl.UnconditionalBranch
        or FlowControl.ConditionalBranch or FlowControl.IndirectBranch or FlowControl.Return;

    /// <summary>rcx/rdx/r8/r9 family → arg index 0..3, else -1.</summary>
    private static int ArgReg(Register r) => r switch
    {
        Register.RCX or Register.ECX or Register.CX or Register.CL => 0,
        Register.RDX or Register.EDX or Register.DX or Register.DL => 1,
        Register.R8 or Register.R8D or Register.R8W or Register.R8L => 2,
        Register.R9 or Register.R9D or Register.R9W or Register.R9L => 3,
        _ => -1,
    };

    private static string? DescribeWrite(IBinaryImage image, in Instruction ins,
        IReadOnlyDictionary<ulong, string> names, IReadOnlyDictionary<ulong, FoundString> stringByVa, FlagSet? flags)
    {
        // lea reg, [rip+x] — an address (very often a string).
        if (ins.Mnemonic == Mnemonic.Lea && ins.IsIPRelativeMemoryOperand)
            return DescribeAddr(image, ins.IPRelativeMemoryAddress, names, stringByVa);

        // xor/sub reg, same-reg — zero.
        if ((ins.Mnemonic is Mnemonic.Xor or Mnemonic.Sub) && ins.Op1Kind == OpKind.Register && ins.Op0Register == ins.Op1Register)
            return "0";

        if (ins.Mnemonic is Mnemonic.Mov or Mnemonic.Movzx or Mnemonic.Movsx or Mnemonic.Movsxd)
        {
            if (IsImm(ins.Op1Kind)) return DescribeValue(image, ins.GetImmediate(1), names, stringByVa, flags);
            if (ins.Op1Kind == OpKind.Memory && ins.IsIPRelativeMemoryOperand
                && DescribeAddr(image, ins.IPRelativeMemoryAddress, names, stringByVa) is { } d)
                return $"[{d}]";
        }
        return null;
    }

    private static string? DescribePush(IBinaryImage image, in Instruction ins,
        IReadOnlyDictionary<ulong, string> names, IReadOnlyDictionary<ulong, FoundString> stringByVa, FlagSet? flags)
    {
        if (IsImm(ins.Op0Kind)) return DescribeValue(image, ins.GetImmediate(0), names, stringByVa, flags);
        return null;
    }

    private static string DescribeValue(IBinaryImage image, ulong v,
        IReadOnlyDictionary<ulong, string> names, IReadOnlyDictionary<ulong, FoundString> stringByVa, FlagSet? flags)
    {
        if (flags is not null) return flags.Decode(v);   // access mask / flag set → symbolic constants
        if (v == 0) return "0";
        if (stringByVa.TryGetValue(v, out var fs)) return QuoteString(fs);
        if (names.TryGetValue(v, out var name)) return name;
        return $"0x{v:X}";
    }

    private static string? DescribeAddr(IBinaryImage image, ulong addr,
        IReadOnlyDictionary<ulong, string> names, IReadOnlyDictionary<ulong, FoundString> stringByVa)
    {
        if (stringByVa.TryGetValue(addr, out var fs)) return QuoteString(fs);
        if (names.TryGetValue(addr, out var name)) return name;
        if (image.IsMappedVa(addr)) return $"0x{addr:X}";
        return null;
    }

    private static string QuoteString(FoundString fs)
    {
        const int max = 28;
        string t = fs.Text.Length > max ? fs.Text[..max] + "…" : fs.Text;
        var sb = new StringBuilder(t.Length + 4);
        if (fs.Wide) sb.Append('L');
        sb.Append('"');
        foreach (char c in t) sb.Append(c is '\t' ? ' ' : c < 0x20 ? '.' : c);
        sb.Append('"');
        return sb.ToString();
    }

    private static bool IsImm(OpKind kind) => kind is
        OpKind.Immediate8 or OpKind.Immediate8_2nd or OpKind.Immediate16 or OpKind.Immediate32 or OpKind.Immediate64
        or OpKind.Immediate8to16 or OpKind.Immediate8to32 or OpKind.Immediate8to64 or OpKind.Immediate32to64;
}

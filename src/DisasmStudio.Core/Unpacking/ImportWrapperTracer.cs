using Iced.Intel;

namespace DisasmStudio.Core.Unpacking;

/// <summary>
/// Resolves a protector's <b>import wrapper stub</b> back to the real API it forwards to, for IAT
/// reconstruction. Themida/VMProtect "Type 1/2" import protection replaces each IAT pointer with a pointer to
/// a small stub <i>inside</i> the protected image; the stub runs a little (often obfuscated) code and then
/// jumps/calls the genuine API. This follows that stub statically — bounded straight-line walks across
/// unconditional control flow, with light single-register/stack constant tracking
/// (<c>mov</c>/<c>lea</c>/<c>add</c>/<c>sub</c>/<c>xor</c>/<c>push</c>/<c>pop</c>) — until it lands on an
/// address an <see cref="IApiResolver"/> recognises as a module export.
/// <para>
/// It is deliberately conservative: anything it can't make concrete (a stub that enters the protector's VM, or
/// runtime-context <c>call [reg+disp]</c> dispatch where the base register isn't a known constant) yields 0, so
/// a bogus import is never fabricated. Handles the common wrapper shapes: <c>jmp/call rel</c>, <c>jmp [mem]</c>,
/// <c>push imm; ret</c>, <c>mov reg, imm; jmp reg</c>, <c>mov reg, [slot]; jmp reg</c>, <c>lea reg, [rip+d]</c>,
/// and short chains of these.
/// </para>
/// </summary>
public static class ImportWrapperTracer
{
    private const int MaxHops = 12;          // jump/deref chain length across blocks
    private const int MaxInsPerBlock = 40;   // instructions decoded per straight-line block

    /// <summary>Trace the wrapper stub at <paramref name="stubVa"/> to the genuine API address it forwards to,
    /// or 0 if it can't be followed to a known export. <paramref name="imageBase"/>/<paramref name="imageEnd"/>
    /// bound the protected image so an intermediate jump to another in-image stub is followed, while a jump
    /// elsewhere that isn't an export stops the trace.</summary>
    public static ulong Trace(MemReader mem, IApiResolver resolver, ulong stubVa, bool is64, ulong imageBase, ulong imageEnd)
    {
        var visited = new HashSet<ulong>();
        ulong ip = stubVa;
        for (int hop = 0; hop < MaxHops && ip != 0 && visited.Add(ip); hop++)
        {
            ulong target = WalkBlock(mem, ip, is64);
            if (target == 0) return 0;
            if (resolver.Resolve(target) is not null) return target;          // reached a genuine export
            if (target >= imageBase && target < imageEnd) { ip = target; continue; }  // another in-image stub
            return 0;   // outside the image but not an export → give up (never fabricate)
        }
        return 0;
    }

    /// <summary>Decode a straight-line block from <paramref name="ip"/>, tracking constant register/stack
    /// values, and return the control-transfer's concrete target (an export, a next stub, or a deref'd slot
    /// value), or 0 if it can't be determined.</summary>
    private static ulong WalkBlock(MemReader mem, ulong ip, bool is64)
    {
        var code = mem(ip, 0x100);
        if (code.Length < 2) return 0;
        var dec = Decoder.Create(is64 ? 64 : 32, new ByteArrayCodeReader(code));
        dec.IP = ip;
        ulong end = ip + (ulong)code.Length;
        int ptr = is64 ? 8 : 4;
        var regs = new Dictionary<Register, ulong>();
        var stack = new Stack<ulong>();

        for (int n = 0; n < MaxInsPerBlock && dec.IP < end; n++)
        {
            dec.Decode(out var ins);
            if (ins.IsInvalid) return 0;

            switch (ins.Mnemonic)
            {
                case Mnemonic.Mov when ins.Op0Kind == OpKind.Register:
                    if (IsImm(ins.Op1Kind))
                        regs[ins.Op0Register] = ins.GetImmediate(1);
                    else if (ins.Op1Kind == OpKind.Register && regs.TryGetValue(ins.Op1Register, out var rv))
                        regs[ins.Op0Register] = rv;
                    else if (ins.Op1Kind == OpKind.Memory && TryMemAddr(ins, regs, out var ma))
                        SetFromMem(mem, regs, ins.Op0Register, ma, ptr);
                    else regs.Remove(ins.Op0Register);
                    break;

                case Mnemonic.Lea when ins.Op0Kind == OpKind.Register && ins.Op1Kind == OpKind.Memory:
                    if (TryMemAddr(ins, regs, out var lea)) regs[ins.Op0Register] = lea;
                    else regs.Remove(ins.Op0Register);
                    break;

                case Mnemonic.Add when ins.Op0Kind == OpKind.Register && IsImm(ins.Op1Kind) && regs.TryGetValue(ins.Op0Register, out var av):
                    regs[ins.Op0Register] = av + ins.GetImmediate(1); break;
                case Mnemonic.Sub when ins.Op0Kind == OpKind.Register && IsImm(ins.Op1Kind) && regs.TryGetValue(ins.Op0Register, out var sv):
                    regs[ins.Op0Register] = sv - ins.GetImmediate(1); break;
                case Mnemonic.Xor when ins.Op0Kind == OpKind.Register && ins.Op1Kind == OpKind.Register && ins.Op0Register == ins.Op1Register:
                    regs[ins.Op0Register] = 0; break;

                case Mnemonic.Push when IsImm(ins.Op0Kind):
                    stack.Push(ins.GetImmediate(0)); break;
                case Mnemonic.Push when ins.Op0Kind == OpKind.Register:
                    stack.Push(regs.GetValueOrDefault(ins.Op0Register)); break;
                case Mnemonic.Pop when ins.Op0Kind == OpKind.Register:
                    if (stack.Count > 0) regs[ins.Op0Register] = stack.Pop(); else regs.Remove(ins.Op0Register);
                    break;

                case Mnemonic.Jmp:
                case Mnemonic.Call:
                    return BranchTarget(mem, ins, regs, ptr);

                case Mnemonic.Ret:
                    return stack.Count > 0 ? stack.Pop() : 0;   // push X; ret
            }
            // Untracked instructions are skipped — wrappers interleave junk that doesn't move our target.
        }
        return 0;
    }

    private static void SetFromMem(MemReader mem, Dictionary<Register, ulong> regs, Register reg, ulong addr, int ptr)
    {
        var pb = mem(addr, ptr);
        if (pb.Length >= ptr) regs[reg] = ptr == 8 ? BitConverter.ToUInt64(pb, 0) : BitConverter.ToUInt32(pb, 0);
        else regs.Remove(reg);
    }

    private static ulong BranchTarget(MemReader mem, in Instruction ins, Dictionary<Register, ulong> regs, int ptr)
    {
        switch (ins.Op0Kind)
        {
            case OpKind.NearBranch16 or OpKind.NearBranch32 or OpKind.NearBranch64:
                return ins.NearBranchTarget;
            case OpKind.Register:
                return regs.GetValueOrDefault(ins.Op0Register);
            case OpKind.Memory:
                if (!TryMemAddr(ins, regs, out var ma)) return 0;
                var pb = mem(ma, ptr);
                return pb.Length >= ptr ? (ptr == 8 ? BitConverter.ToUInt64(pb, 0) : BitConverter.ToUInt32(pb, 0)) : 0;
            default:
                return 0;
        }
    }

    /// <summary>Make a memory operand's address concrete: RIP-relative, pure displacement, or a known
    /// base-register + displacement. False (unknown) for a scaled index or an unknown base — e.g. the
    /// runtime-context <c>[ebp+disp]</c> dispatch, which can't be resolved statically.</summary>
    private static bool TryMemAddr(in Instruction ins, Dictionary<Register, ulong> regs, out ulong addr)
    {
        addr = 0;
        if (ins.IsIPRelativeMemoryOperand) { addr = ins.IPRelativeMemoryAddress; return true; }
        if (ins.MemoryIndex != Register.None) return false;
        if (ins.MemoryBase == Register.None) { addr = ins.MemoryDisplacement64; return addr != 0; }
        if (regs.TryGetValue(ins.MemoryBase, out var b)) { addr = b + ins.MemoryDisplacement64; return true; }
        return false;
    }

    private static bool IsImm(OpKind k) => k is OpKind.Immediate8 or OpKind.Immediate8to16 or OpKind.Immediate8to32
        or OpKind.Immediate8to64 or OpKind.Immediate16 or OpKind.Immediate32 or OpKind.Immediate32to64 or OpKind.Immediate64;
}

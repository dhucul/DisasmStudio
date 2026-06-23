using DisasmStudio.Core.Disasm;
using DisasmStudio.Core.Formats;
using Iced.Intel;

namespace DisasmStudio.Core.Devirt;

/// <summary>
/// A small abstract evaluator over one handler's straight-line native body. It does not emulate the CPU; it
/// extracts the few features that distinguish stack-VM primitives — how far the VIP advances (operand bytes),
/// the net virtual-stack delta, any arithmetic/compare op on temporaries, any virtual-register (context)
/// access, a conditional VIP write (a branch), and whether the handler leaves the VM. <see cref="HandlerClassifier"/>
/// turns these features into a <see cref="HandlerKind"/>. Reuses <see cref="Disassembler"/> and the
/// bounded-scan style already used in the analysis passes.
/// </summary>
internal static class VmStackEval
{
    private const int MaxBody = 48;

    public sealed record Trace
    {
        public List<Instruction> Body { get; } = [];
        public Register Vsp { get; set; } = Register.None;
        public int OperandBytes { get; set; }    // bytes the VIP advanced for operands (beyond the opcode)
        public int Pushes { get; set; }          // sub vsp,4 count
        public int Pops { get; set; }            // add vsp,4 count
        public bool HasRet { get; set; }
        public bool HasCondVipWrite { get; set; }
        public Mnemonic? Arith { get; set; }     // a binop on temporaries (add/sub/imul/...)
        public Mnemonic? SetCc { get; set; }     // a setcc producing a boolean
        public bool HasContextAccess { get; set; }
        public int ContextDisp { get; set; }

        public int StackDelta => Pushes - Pops;  // net values pushed
    }

    private static readonly HashSet<Mnemonic> ArithOps =
    [
        Mnemonic.Add, Mnemonic.Sub, Mnemonic.Imul, Mnemonic.Mul, Mnemonic.And,
        Mnemonic.Or, Mnemonic.Xor, Mnemonic.Shl, Mnemonic.Shr, Mnemonic.Sar,
    ];

    private static readonly HashSet<Mnemonic> CmovOps =
    [
        Mnemonic.Cmova, Mnemonic.Cmovae, Mnemonic.Cmovb, Mnemonic.Cmovbe, Mnemonic.Cmove, Mnemonic.Cmovg,
        Mnemonic.Cmovge, Mnemonic.Cmovl, Mnemonic.Cmovle, Mnemonic.Cmovne, Mnemonic.Cmovno, Mnemonic.Cmovnp,
        Mnemonic.Cmovns, Mnemonic.Cmovo, Mnemonic.Cmovp, Mnemonic.Cmovs,
    ];

    private static readonly HashSet<Mnemonic> SetOps =
    [
        Mnemonic.Seta, Mnemonic.Setae, Mnemonic.Setb, Mnemonic.Setbe, Mnemonic.Sete, Mnemonic.Setg,
        Mnemonic.Setge, Mnemonic.Setl, Mnemonic.Setle, Mnemonic.Setne, Mnemonic.Setno, Mnemonic.Setnp,
        Mnemonic.Setns, Mnemonic.Seto, Mnemonic.Setp, Mnemonic.Sets,
    ];

    public static Trace Run(IBinaryImage image, Disassembler dis, Register vipReg, ulong handlerVa)
    {
        var t = new Trace();
        ulong va = handlerVa;
        Register vip = vipReg.GetFullRegister();

        // Pass 1: identify the virtual-stack pointer — a register (not the VIP) adjusted by an immediate.
        var bodyVas = new List<ulong>();
        for (int i = 0; i < MaxBody; i++)
        {
            if (!dis.TryDecodeAt(va, out var ins)) break;
            if (ins.Mnemonic is Mnemonic.Ret or Mnemonic.Retf or Mnemonic.Leave) { t.HasRet = true; bodyVas.Add(va); break; }
            if (ins.FlowControl == FlowControl.UnconditionalBranch) break;   // jmp back to the dispatcher: body ends
            bodyVas.Add(va);
            if (t.Vsp == Register.None && ins.Mnemonic is Mnemonic.Add or Mnemonic.Sub
                && ins.Op0Kind == OpKind.Register && IsImm(ins.Op1Kind) && ins.Op0Register.GetFullRegister() != vip)
                t.Vsp = ins.Op0Register.GetFullRegister();
            va += (ulong)ins.Length;
        }

        // Pass 2: extract features now that the VSP register is known.
        foreach (var bva in bodyVas)
        {
            if (!dis.TryDecodeAt(bva, out var ins)) continue;
            t.Body.Add(ins);
            if (ins.Mnemonic is Mnemonic.Ret or Mnemonic.Retf or Mnemonic.Leave) continue;

            Register op0 = ins.Op0Kind == OpKind.Register ? ins.Op0Register.GetFullRegister() : Register.None;

            // VIP / VSP pointer adjustments.
            if (ins.Mnemonic is Mnemonic.Add or Mnemonic.Sub && IsImm(ins.Op1Kind) && ins.Op0Kind == OpKind.Register)
            {
                int k = (int)ins.GetImmediate(1);
                if (op0 == vip) { t.OperandBytes += System.Math.Abs(k); continue; }
                if (op0 == t.Vsp) { if (ins.Mnemonic == Mnemonic.Sub) t.Pushes++; else t.Pops++; continue; }
            }

            // Conditional VIP write => a branch handler.
            if (op0 == vip && CmovOps.Contains(ins.Mnemonic)) t.HasCondVipWrite = true;

            // A boolean-producing compare.
            if (SetOps.Contains(ins.Mnemonic)) t.SetCc = ins.Mnemonic;

            // A binop on temporaries (Op0 is neither the VIP nor the VSP; skip the xor r,r zeroing idiom).
            if (ArithOps.Contains(ins.Mnemonic) && op0 != Register.None && op0 != vip && op0 != t.Vsp
                && !(ins.Mnemonic == Mnemonic.Xor && ins.Op1Kind == OpKind.Register && ins.Op1Register.GetFullRegister() == op0))
                t.Arith ??= ins.Mnemonic;

            // A virtual-register (context) memory access: base register that is neither VIP nor VSP.
            if (HasMemBase(ins, out var baseReg) && baseReg != vip && baseReg != t.Vsp)
            {
                t.HasContextAccess = true;
                t.ContextDisp = (int)ins.MemoryDisplacement64;
            }
        }
        return t;
    }

    private static bool HasMemBase(in Instruction ins, out Register baseReg)
    {
        for (int i = 0; i < ins.OpCount; i++)
            if (ins.GetOpKind(i) == OpKind.Memory && ins.MemoryBase != Register.None && ins.MemoryIndex == Register.None)
            { baseReg = ins.MemoryBase.GetFullRegister(); return true; }
        baseReg = Register.None;
        return false;
    }

    private static bool IsImm(OpKind k) => k is OpKind.Immediate8 or OpKind.Immediate8to16 or OpKind.Immediate8to32
        or OpKind.Immediate16 or OpKind.Immediate32 or OpKind.Immediate8to64 or OpKind.Immediate32to64 or OpKind.Immediate64;
}

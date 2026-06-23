using DisasmStudio.Core.Disasm;
using DisasmStudio.Core.Formats;
using DisasmStudio.Core.IL;
using Iced.Intel;

namespace DisasmStudio.Core.Devirt;

/// <summary>
/// Classifies one VM handler's native body into a <see cref="HandlerKind"/> from the features
/// <see cref="VmStackEval"/> extracts (VIP advance, net stack delta, arithmetic/compare op, context access,
/// conditional VIP write, VM exit). Deliberately small and stack-VM-shaped — it recognises the common
/// primitive set a clean stack VM emits. Anything that does not match cleanly stays
/// <see cref="HandlerKind.Unknown"/> (never guessed), which downgrades the run to a partial recovery.
/// </summary>
internal static class HandlerClassifier
{
    public static HandlerInfo Classify(IBinaryImage image, Disassembler dis, VmArchDescriptor arch, ulong handlerVa)
    {
        var t = VmStackEval.Run(image, dis, arch.VipReg, handlerVa);
        int width = arch.Bitness / 8;
        HandlerInfo Make(HandlerKind kind, double conf = 0.95) =>
            new() { Va = handlerVa, Kind = kind, Width = width, OperandBytes = t.OperandBytes, Confidence = conf };

        // Order matters: a compare and a branch both touch the stack, so test the specific tells first.
        if (t.HasRet)
            return Make(HandlerKind.VmExit);
        if (t.HasCondVipWrite)
            return Make(HandlerKind.Branch) with { OperandBytes = t.OperandBytes == 0 ? width : t.OperandBytes };
        if (t.SetCc is { } sc)
            return Make(HandlerKind.Compare) with { CmpOp = SetToCmp(sc) };
        if (t.Arith is { } ar)
            return Make(HandlerKind.BinOp) with { BinOp = ArithToBin(ar) };
        if (t.HasContextAccess)
            return Make(t.StackDelta > 0 ? HandlerKind.PushReg : HandlerKind.PopReg) with { RegIndex = t.ContextDisp / System.Math.Max(1, width) };
        if (t.OperandBytes > 0 && t.StackDelta > 0)
            return Make(HandlerKind.PushImm);

        return new HandlerInfo { Va = handlerVa, Kind = HandlerKind.Unknown, Width = width, Confidence = 0 };
    }

    private static BinOp ArithToBin(Mnemonic m) => m switch
    {
        Mnemonic.Add => BinOp.Add,
        Mnemonic.Sub => BinOp.Sub,
        Mnemonic.Imul => BinOp.Mul,
        Mnemonic.Mul => BinOp.UMul,
        Mnemonic.And => BinOp.And,
        Mnemonic.Or => BinOp.Or,
        Mnemonic.Xor => BinOp.Xor,
        Mnemonic.Shl => BinOp.Shl,
        Mnemonic.Shr => BinOp.Shr,
        Mnemonic.Sar => BinOp.Sar,
        _ => BinOp.Add,
    };

    private static CmpOp SetToCmp(Mnemonic m) => m switch
    {
        Mnemonic.Setl => CmpOp.SLt, Mnemonic.Setle => CmpOp.SLe,
        Mnemonic.Setg => CmpOp.SGt, Mnemonic.Setge => CmpOp.SGe,
        Mnemonic.Setb => CmpOp.ULt, Mnemonic.Setbe => CmpOp.ULe,
        Mnemonic.Seta => CmpOp.UGt, Mnemonic.Setae => CmpOp.UGe,
        Mnemonic.Sete => CmpOp.Eq, Mnemonic.Setne => CmpOp.Ne,
        _ => CmpOp.Ne,
    };
}

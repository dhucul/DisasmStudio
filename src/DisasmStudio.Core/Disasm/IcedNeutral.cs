using Iced.Intel;

namespace DisasmStudio.Core.Disasm;

/// <summary>
/// The x86/x64 <see cref="INeutralDisassembler"/> — a thin, behavior-preserving wrapper over the existing
/// Iced decoder (<see cref="Disassembler"/> or the debugger's live decoder) and <see cref="AsmFormatter"/>.
/// The flow mapping mirrors <see cref="FlowAnalysis"/> exactly, so the x86 listing/graph are unchanged.
/// </summary>
public sealed class IcedNeutral(IInstructionDecoder inner, AsmFormatter fmt) : INeutralDisassembler
{
    private static readonly AsmToken[] Empty = [];

    public bool TryDecode(ulong va, out NeutralInsn insn)
    {
        if (!inner.TryDecodeAt(va, out var i)) { insn = default; return false; }
        insn = new NeutralInsn(i.Length, Map(i.FlowControl), FlowAnalysis.DirectBranchTarget(i));
        return true;
    }

    public IReadOnlyList<AsmToken> Format(ulong va) =>
        inner.TryDecodeAt(va, out var i) ? fmt.Format(i) : Empty;

    private static FlowKind Map(FlowControl fc) => fc switch
    {
        FlowControl.ConditionalBranch => FlowKind.CondJump,
        FlowControl.UnconditionalBranch => FlowKind.Jump,
        FlowControl.IndirectBranch => FlowKind.IndirectJump,
        FlowControl.Call => FlowKind.Call,
        FlowControl.IndirectCall => FlowKind.IndirectCall,
        FlowControl.Return => FlowKind.Ret,
        FlowControl.Interrupt or FlowControl.Exception => FlowKind.Interrupt,
        _ => FlowKind.Seq,
    };
}

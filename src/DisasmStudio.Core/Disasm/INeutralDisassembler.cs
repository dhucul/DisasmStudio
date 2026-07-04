using DisasmStudio.Core.Formats;

namespace DisasmStudio.Core.Disasm;

/// <summary>Architecture-neutral control-flow class of one instruction — the minimum the analysis passes
/// (code discovery, CFG) and the views (branch arrows, "follow") need, common to x86 (Iced) and ARM
/// (Capstone).</summary>
public enum FlowKind { Seq, CondJump, Jump, Call, Ret, IndirectJump, IndirectCall, Interrupt }

/// <summary>An instruction reduced to what the shared listing/CFG code needs: its length, its flow class,
/// and the direct branch/call target (absolute VA) when it has one. Everything richer (registers, operand
/// kinds) stays in the Iced <c>Instruction</c> on the x86 path and is not needed for ARM listing/graphing.</summary>
public readonly record struct NeutralInsn(int Length, FlowKind Flow, ulong? DirectTarget)
{
    /// <summary>Ends a basic block: any jump (direct/conditional/indirect), a return, or a trap. Matches
    /// <see cref="FlowAnalysis.IsBlockTerminator"/> (calls do NOT terminate).</summary>
    public bool IsBlockTerminator => Flow is FlowKind.CondJump or FlowKind.Jump
        or FlowKind.IndirectJump or FlowKind.Ret or FlowKind.Interrupt;

    /// <summary>A direct call with a resolvable target (seeds a new function).</summary>
    public bool IsDirectCall => Flow == FlowKind.Call && DirectTarget is not null;
}

/// <summary>
/// The single decode seam the two views and <see cref="CfgBuilder"/> use, so they never depend on
/// <c>Iced.Intel.Instruction</c> directly. <see cref="IcedNeutral"/> wraps the existing x86/x64 Iced
/// decoder (behavior-preserving); <see cref="ArmDisassembler"/> wraps Capstone for ARM/Thumb/AArch64.
/// </summary>
public interface INeutralDisassembler
{
    /// <summary>Decode length + flow at <paramref name="va"/>; false if unmapped/undecodable.</summary>
    bool TryDecode(ulong va, out NeutralInsn insn);

    /// <summary>The formatted, coloured token run for the line at <paramref name="va"/> (empty if it can't be
    /// decoded). The returned list may be reused between calls, so consume it before the next call.</summary>
    IReadOnlyList<AsmToken> Format(ulong va);
}

/// <summary>Builds the right neutral decoder for an image: Capstone for ARM-family, else Iced (optionally
/// over a supplied live/debugger decoder). This is the one place the arch → decoder routing lives.</summary>
public static class NeutralDisasm
{
    public static INeutralDisassembler For(IBinaryImage image, IReadOnlyDictionary<ulong, string>? names,
                                           IInstructionDecoder? live = null) =>
        image.IsArm
            ? new ArmDisassembler(image, image.Arch, names)
            : new IcedNeutral(live ?? new Disassembler(image), new AsmFormatter(names));
}

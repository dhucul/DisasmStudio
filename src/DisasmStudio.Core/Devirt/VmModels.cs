using DisasmStudio.Core.IL;

namespace DisasmStudio.Core.Devirt;

// Data models for the VM-devirtualization foundation (Phase 1). A virtualizing protector (VMProtect /
// Themida) replaces native code with bytecode for a custom stack machine: an entry stub saves the CPU
// context and hands control to a dispatcher that reads a Virtual Instruction Pointer (VIP) byte stream,
// indexes a handler table, and runs a tiny native handler per virtual opcode against a virtual stack and
// a virtual register context. These records describe what we recover from a *decrypted* image. The
// engine is honest about its limits — see DevirtStatus.

/// <summary>Which protector family a discovered VM belongs to. Phase 1 only proves <see cref="Synthetic"/>.</summary>
public enum VmFamily { Unknown, Synthetic, VmProtect, Themida }

/// <summary>How operands embedded in the VIP byte stream are encoded. Phase 1 ships <see cref="None"/>
/// (plaintext) plus a single demonstration rolling-xor; real per-version key schedules are deferred.</summary>
public enum VipDecode { None, XorRollingKey }

/// <summary>The recovered shape of a VM: where its dispatcher/handler table live and how the VIP works.</summary>
public sealed record VmArchDescriptor
{
    public required VmFamily Family { get; init; }
    public required int Bitness { get; init; }              // 32 / 64, from the image
    public required Iced.Intel.Register VipReg { get; init; }   // the VIP (bytecode pointer) register
    public Iced.Intel.Register VspReg { get; init; }           // virtual-stack pointer (None if undiscovered)
    public Iced.Intel.Register ContextReg { get; init; }       // virtual register-file base (None if undiscovered)
    public bool VipForward { get; init; } = true;          // VIP advances upward
    public VipDecode Decode { get; init; } = VipDecode.None;
    public byte InitialKey { get; init; }
    public required ulong HandlerTableVa { get; init; }
    public required int HandlerCount { get; init; }
    public int HandlerSlotSize { get; init; } = 4;         // 4 (x86 abs / RVA) or 8 (x64 abs)
    public bool HandlerTableIsRva { get; init; }
    public ulong HandlerTableRvaBase { get; init; }        // base added to RVA entries, else 0
}

/// <summary>A located VM entry: the stub, its dispatcher, where the bytecode begins, and the arch.</summary>
public sealed record VmEntry
{
    public required ulong EntryVa { get; init; }
    public required ulong DispatcherVa { get; init; }
    public required ulong FirstVipVa { get; init; }
    public IReadOnlyList<ulong> PushedContext { get; init; } = [];   // evidence: context-save instruction VAs
    public required VmArchDescriptor Arch { get; init; }
}

/// <summary>The semantic class recovered for one VM handler. <see cref="Unknown"/> never fabricates meaning;
/// it downgrades the whole run to <see cref="DevirtStatus.PartialRecovery"/>.</summary>
public enum HandlerKind
{
    Unknown, PushImm, PushReg, PopReg, BinOp, UnOp, Compare, Load, Store, Branch, Jump, VmExit, Nop,
}

/// <summary>One classified handler: its VA, what it does, and how confident the classifier is.</summary>
public sealed record HandlerInfo
{
    public required ulong Va { get; init; }
    public required HandlerKind Kind { get; init; }
    public BinOp? BinOp { get; init; }      // when Kind == BinOp
    public UnOp? UnOp { get; init; }        // when Kind == UnOp
    public CmpOp? CmpOp { get; init; }      // when Kind == Compare
    public int RegIndex { get; init; }      // vreg/context slot for PushReg/PopReg
    public int OperandBytes { get; init; }  // bytes consumed from the VIP stream (immediate / branch target width)
    public int Width { get; init; } = 4;    // value width in bytes
    public string Disasm { get; init; } = "";
    public double Confidence { get; init; } // 0..1
}

/// <summary>One decoded virtual instruction from the VIP stream.</summary>
public sealed record VInsn
{
    public required ulong VipVa { get; init; }    // where this vinsn's opcode byte lives
    public required int Index { get; init; }      // position in the decoded program
    public required HandlerInfo Handler { get; init; }
    public long Operand { get; init; }            // immediate / branch-target operand (0 when none)
    public int? BranchTargetIndex { get; init; }  // resolved target vinsn index, or null if unresolved
}

/// <summary>The outcome class of a devirtualization run. The non-Ok values are the honest off-ramps.</summary>
public enum DevirtStatus
{
    /// <summary>A VM was found and the whole bytecode program was recovered and lifted.</summary>
    Ok,
    /// <summary>No VM-entry/dispatcher shape was found in the image.</summary>
    NoVmFound,
    /// <summary>A virtualizer fingerprint is present but the handlers/bytecode are not readable on disk —
    /// the image is still encrypted; a decrypted dump is required first.</summary>
    ImageEncrypted,
    /// <summary>A VM was found but some handlers/branches could not be recovered (left as Unknown).</summary>
    PartialRecovery,
    Error,
}

/// <summary>The full result of <see cref="DevirtEngine.Run"/>.</summary>
public sealed record DevirtResult
{
    public required DevirtStatus Status { get; init; }
    public string Message { get; init; } = "";
    public VmEntry? Entry { get; init; }
    public IReadOnlyList<HandlerInfo> Handlers { get; init; } = [];
    public IReadOnlyList<VInsn> Program { get; init; } = [];
    public LiftedFunction? Lifted { get; init; }              // feed to Structurer + StructEmitter
    public IReadOnlyList<DecompLine> PseudoC { get; init; } = [];   // rendered, ready to display
}

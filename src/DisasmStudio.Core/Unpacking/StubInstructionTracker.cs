using Iced.Intel;

namespace DisasmStudio.Core.Unpacking;

/// <summary>The kind of control transfer detected at the end of a stub.</summary>
public enum TransferKind
{
    /// <summary><c>jmp target</c> — direct or register-indirect far jump.</summary>
    Jmp,
    /// <summary><c>push target; ret</c> — push-and-return idiom.</summary>
    PushRet,
    /// <summary><c>call target</c> — tail call (unlikely in a stub, but possible).</summary>
    Call,
}

/// <summary>A candidate OEP transfer: the stub ends with a control-flow instruction targeting
/// <see cref="Target"/> via <see cref="Kind"/>.</summary>
public readonly record struct StubTransfer(ulong Target, TransferKind Kind, ulong SourceIp);

/// <summary>
/// Shared, stateless instruction-level tracker that walks a packer stub's bytecode and records every
/// far control transfer (jmp/ret/call) that could be the terminal jump to the Original Entry Point.
/// <para>
/// Extracted from <see cref="OepScanner"/> so both the static (dump-based) and dynamic (live-debugger)
/// OEP-recovery paths share the same register-tracking and transfer-detection logic. The tracker is a
/// pure function: bytes in, candidate transfers out. Callers apply their own acceptance criteria
/// (executable section, prologue validation, far-enough threshold).
/// </para>
/// </summary>
public static class StubInstructionTracker
{
    /// <summary>How many instructions to decode from the stub entry before giving up.</summary>
    public const int DefaultMaxInstructions = 6000;

    /// <summary>
    /// Walk <paramref name="code"/> starting at <paramref name="stubEntry"/> and return every far
    /// control transfer (jmp, push+ret, call) whose target can be resolved from the instruction stream
    /// alone. Register-indirect jumps (<c>jmp eax</c>) are resolved when the register was set by a
    /// prior <c>mov reg, imm</c>; memory-indirect jumps (<c>jmp [addr]</c>) are resolved by reading
    /// the pointer from <paramref name="mem"/>.
    /// </summary>
    /// <param name="mem">Memory reader for resolving memory-indirect jump targets.</param>
    /// <param name="code">The stub bytecode, starting at <paramref name="stubEntry"/>.</param>
    /// <param name="stubEntry">The VA of the first byte of <paramref name="code"/>.</param>
    /// <param name="is64">True for x64, false for x86.</param>
    /// <param name="maxInstructions">Stop after decoding this many instructions.</param>
    /// <returns>Every resolved far transfer, in decode order.</returns>
    public static List<StubTransfer> Track(
        MemReader mem, byte[] code, ulong stubEntry, bool is64,
        int maxInstructions = DefaultMaxInstructions)
    {
        var results = new List<StubTransfer>();
        if (code.Length < 2) return results;

        int ptr = is64 ? 8 : 4;
        var regs = new Dictionary<Register, ulong>();
        ulong lastPush = 0;
        bool havePush = false;

        var dec = Decoder.Create(is64 ? 64 : 32, new ByteArrayCodeReader(code));
        dec.IP = stubEntry;
        ulong end = stubEntry > ulong.MaxValue - (ulong)code.Length
            ? ulong.MaxValue
            : stubEntry + (ulong)code.Length;

        for (int n = 0; n < maxInstructions && dec.IP < end; n++)
        {
            dec.Decode(out var ins);
            if (ins.IsInvalid) continue;

            switch (ins.Mnemonic)
            {
                // mov reg, imm  — track register values for later jmp reg / push reg
                case Mnemonic.Mov when ins.Op0Kind == OpKind.Register && IsImm(ins.Op1Kind):
                    regs[ins.Op0Register] = ins.GetImmediate(1);
                    break;

                // mov reg, reg  — propagate register values
                case Mnemonic.Mov when ins.Op0Kind == OpKind.Register && ins.Op1Kind == OpKind.Register:
                    if (regs.TryGetValue(ins.Op1Register, out ulong srcVal))
                        regs[ins.Op0Register] = srcVal;
                    else
                        regs.Remove(ins.Op0Register);
                    break;

                // push imm  — track for push+ret idiom
                case Mnemonic.Push when IsImm(ins.Op0Kind):
                    lastPush = ins.GetImmediate(0);
                    havePush = true;
                    break;

                // push reg  — resolve from tracked register values
                case Mnemonic.Push when ins.Op0Kind == OpKind.Register:
                    havePush = regs.TryGetValue(ins.Op0Register, out lastPush);
                    break;

                // pop reg  — update tracked register from stack (best-effort: use last push)
                case Mnemonic.Pop when ins.Op0Kind == OpKind.Register && havePush:
                    regs[ins.Op0Register] = lastPush;
                    havePush = false;
                    break;

                // ret after a tracked push → push oep; ret idiom
                case Mnemonic.Ret when havePush:
                    results.Add(new StubTransfer(lastPush, TransferKind.PushRet, ins.IP));
                    havePush = false;
                    break;

                // ret imm16  — near return with stack adjustment (not a stub exit)
                case Mnemonic.Ret:
                    havePush = false;
                    break;

                // jmp target  — direct, register-indirect, or memory-indirect
                case Mnemonic.Jmp:
                {
                    ulong target = ins.Op0Kind switch
                    {
                        OpKind.NearBranch16 or OpKind.NearBranch32 or OpKind.NearBranch64 => ins.NearBranchTarget,
                        OpKind.Register => regs.GetValueOrDefault(ins.Op0Register),
                        OpKind.Memory => DerefJmp(mem, ins, ptr),
                        _ => 0,
                    };
                    if (target != 0)
                        results.Add(new StubTransfer(target, TransferKind.Jmp, ins.IP));
                    break;
                }

                // call target  — tail call (some protectors use call to transfer to OEP)
                case Mnemonic.Call:
                {
                    ulong target = ins.Op0Kind switch
                    {
                        OpKind.NearBranch16 or OpKind.NearBranch32 or OpKind.NearBranch64 => ins.NearBranchTarget,
                        OpKind.Register => regs.GetValueOrDefault(ins.Op0Register),
                        OpKind.Memory => DerefJmp(mem, ins, ptr),
                        _ => 0,
                    };
                    if (target != 0)
                        results.Add(new StubTransfer(target, TransferKind.Call, ins.IP));
                    break;
                }

                // xor reg, reg  — zero the register (common in stub cleanup before OEP jump)
                case Mnemonic.Xor when ins.Op0Kind == OpKind.Register && ins.Op0Register == ins.Op1Register:
                    regs[ins.Op0Register] = 0;
                    break;

                // sub reg, imm / add reg, imm  — adjust tracked register (simple arithmetic)
                case Mnemonic.Sub when ins.Op0Kind == OpKind.Register && IsImm(ins.Op1Kind):
                    if (regs.TryGetValue(ins.Op0Register, out ulong subVal))
                        regs[ins.Op0Register] = subVal - ins.GetImmediate(1);
                    break;
                case Mnemonic.Add when ins.Op0Kind == OpKind.Register && IsImm(ins.Op1Kind):
                    if (regs.TryGetValue(ins.Op0Register, out ulong addVal))
                        regs[ins.Op0Register] = addVal + ins.GetImmediate(1);
                    break;

                // lea reg, [mem]  — compute effective address (common for RIP-relative addressing in x64 stubs)
                case Mnemonic.Lea when ins.Op0Kind == OpKind.Register && ins.IsIPRelativeMemoryOperand:
                    regs[ins.Op0Register] = ins.IPRelativeMemoryAddress;
                    break;
            }
        }

        return results;
    }

    /// <summary>
    /// Walk <paramref name="code"/> starting at <paramref name="stubEntry"/> and return the <b>first</b>
    /// far control transfer whose target passes <paramref name="accept"/>. Returns null when no
    /// acceptable transfer is found. This is the convenience wrapper used by <see cref="OepScanner"/>.
    /// </summary>
    public static StubTransfer? FindFirstTransfer(
        MemReader mem, byte[] code, ulong stubEntry, bool is64,
        Func<StubTransfer, bool> accept, int maxInstructions = DefaultMaxInstructions)
    {
        var transfers = Track(mem, code, stubEntry, is64, maxInstructions);
        foreach (var t in transfers)
            if (accept(t))
                return t;
        return null;
    }

    private static ulong DerefJmp(MemReader mem, in Instruction ins, int ptr)
    {
        ulong addr = ins.IsIPRelativeMemoryOperand ? ins.IPRelativeMemoryAddress
            : ins.MemoryBase == Register.None && ins.MemoryIndex == Register.None ? ins.MemoryDisplacement64 : 0;
        if (addr == 0) return 0;
        var p = mem(addr, ptr);
        return p.Length < ptr ? 0 : ptr == 8 ? BitConverter.ToUInt64(p, 0) : BitConverter.ToUInt32(p, 0);
    }

    private static bool IsImm(OpKind k) => k is OpKind.Immediate8 or OpKind.Immediate8to16 or OpKind.Immediate8to32
        or OpKind.Immediate8to64 or OpKind.Immediate16 or OpKind.Immediate32 or OpKind.Immediate32to64 or OpKind.Immediate64;
}
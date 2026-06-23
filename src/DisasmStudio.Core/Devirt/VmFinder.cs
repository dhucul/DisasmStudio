using DisasmStudio.Core.Disasm;
using DisasmStudio.Core.Formats;
using DisasmStudio.Core.Unpacking;
using Iced.Intel;

namespace DisasmStudio.Core.Devirt;

/// <summary>
/// Locates a VM entry + dispatcher + handler table in a (decrypted) image. Heuristic and honest: it looks
/// for the *shape* of a stack-VM dispatch, not a version signature. Anchored at the image entry point, it
/// follows straight-line flow looking for a context save, the VIP/VSP/context initialisation, and a central
/// indirect dispatch through a handler table (<c>jmp [index*scale + table]</c>). Reuses <see cref="Disassembler"/>
/// + <see cref="FlowAnalysis"/>. When no dispatch shape is found it defers to <see cref="PackerDetector"/>:
/// a virtualizer fingerprint without a visible VM means the body is still encrypted on disk.
/// </summary>
public static class VmFinder
{
    private const int MaxScan = 80;       // instructions to walk from the entry
    private const int MaxHandlers = 256;

    public sealed record Result(VmEntry? Entry, IReadOnlyList<ulong> HandlerVas, DevirtStatus Status, string Note);

    public static Result Find(IBinaryImage image)
    {
        if (image.EntryVa == 0 || !image.IsExecutableVa(image.EntryVa))
            return Encrypted(image, "image has no executable entry point.");

        var dis = new Disassembler(image);
        var regImm = new Dictionary<Register, ulong>();      // reg <- imm32 (VIP/VSP/context init)
        var movzxFrom = new Dictionary<Register, Register>(); // dst <- [base]  (opcode fetch)
        var pushed = new List<ulong>();

        ulong va = image.EntryVa;
        var seen = new HashSet<ulong>();
        for (int steps = 0; steps < MaxScan; steps++)
        {
            if (!seen.Add(va) || !dis.TryDecodeAt(va, out var ins)) break;

            if (ins.Mnemonic is Mnemonic.Pushad or Mnemonic.Pushfd or Mnemonic.Push) pushed.Add(va);
            if (ins.Mnemonic == Mnemonic.Mov && ins.Op0Kind == OpKind.Register && IsImm(ins.Op1Kind))
                regImm[Norm(ins.Op0Register)] = ins.GetImmediate(1);
            if (ins.Mnemonic is Mnemonic.Movzx or Mnemonic.Mov && ins.Op0Kind == OpKind.Register
                && ins.Op1Kind == OpKind.Memory && ins.MemoryBase != Register.None && ins.MemoryIndex == Register.None)
                movzxFrom[Norm(ins.Op0Register)] = Norm(ins.MemoryBase);

            // The dispatcher: an indirect jmp through [index*scale + table].
            if (ins.FlowControl == FlowControl.IndirectBranch && ins.Op0Kind == OpKind.Memory
                && ins.MemoryIndex != Register.None && ins.MemoryBase == Register.None && ins.MemoryIndexScale is 4 or 8)
            {
                ulong tableVa = ins.MemoryDisplacement64;
                Register indexReg = Norm(ins.MemoryIndex);
                Register vipReg = movzxFrom.TryGetValue(indexReg, out var v) ? v : Register.None;
                if (vipReg == Register.None || tableVa == 0)
                    return Partial(image, "found an indirect dispatch but could not recover the VIP register or table.");

                var handlerVas = ReadHandlerTable(image, tableVa, ins.MemoryIndexScale);
                if (handlerVas.Count < 2)
                    return Partial(image, $"dispatcher at {va:X} found but the handler table at {tableVa:X} is unreadable.");

                ulong firstVip = regImm.TryGetValue(vipReg, out var fv) ? fv : 0;
                var arch = new VmArchDescriptor
                {
                    Family = VmFamily.Unknown,
                    Bitness = image.Bitness,
                    VipReg = vipReg,
                    HandlerTableVa = tableVa,
                    HandlerCount = handlerVas.Count,
                    HandlerSlotSize = ins.MemoryIndexScale,
                };
                var entry = new VmEntry
                {
                    EntryVa = image.EntryVa,
                    DispatcherVa = va,
                    FirstVipVa = firstVip,
                    PushedContext = pushed,
                    Arch = arch,
                };
                string note = firstVip == 0
                    ? $"VM found: dispatcher {va:X}, {handlerVas.Count} handlers (VIP start unresolved)."
                    : $"VM found: dispatcher {va:X}, {handlerVas.Count} handlers, VIP @ {firstVip:X}.";
                return new Result(entry, handlerVas, DevirtStatus.Ok, note);
            }

            if (ins.FlowControl == FlowControl.UnconditionalBranch && FlowAnalysis.DirectBranchTarget(ins) is ulong t)
            { va = t; continue; }                     // follow the stub's jump into the dispatcher
            if (FlowAnalysis.IsBlockTerminator(ins)) break;
            va += (ulong)ins.Length;
        }

        return Encrypted(image, "no VM dispatch shape found from the entry point.");
    }

    /// <summary>Read handler-table entries until the first non-executable one (the table's end).</summary>
    private static List<ulong> ReadHandlerTable(IBinaryImage image, ulong tableVa, int slot)
    {
        var handlers = new List<ulong>();
        for (int i = 0; i < MaxHandlers; i++)
        {
            var bytes = image.ReadBytesAtVa(tableVa + (ulong)(i * slot), slot);
            if (bytes.Length < slot) break;
            ulong target = slot == 8 ? BitConverter.ToUInt64(bytes) : BitConverter.ToUInt32(bytes);
            if (!image.IsExecutableVa(target)) break;
            handlers.Add(target);
        }
        return handlers;
    }

    // No visible VM. If the file still fingerprints as a virtualizer, the body is encrypted on disk.
    private static Result Encrypted(IBinaryImage image, string why)
    {
        var verdict = PackerDetector.Detect(image);
        if (verdict.Kind == PackerKind.Virtualizer)
            return new Result(null, [], DevirtStatus.ImageEncrypted,
                "Image fingerprints as a virtualizing protector but its VM is not visible on disk (" + why +
                ") — it is still encrypted. A decrypted dump is required first.");
        return new Result(null, [], DevirtStatus.NoVmFound, "No VM found: " + why);
    }

    private static Result Partial(IBinaryImage image, string why) =>
        new(null, [], DevirtStatus.PartialRecovery, why);

    private static bool IsImm(OpKind k) => k is OpKind.Immediate8 or OpKind.Immediate8to16 or OpKind.Immediate8to32
        or OpKind.Immediate16 or OpKind.Immediate32 or OpKind.Immediate8to64 or OpKind.Immediate32to64 or OpKind.Immediate64;

    /// <summary>Full-width register key, so al/ax/eax map together.</summary>
    private static Register Norm(Register r) => r.GetFullRegister();
}

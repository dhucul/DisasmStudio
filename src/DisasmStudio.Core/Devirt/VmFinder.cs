using DisasmStudio.Core.Disasm;
using DisasmStudio.Core.Formats;
using DisasmStudio.Core.Unpacking;
using Iced.Intel;

namespace DisasmStudio.Core.Devirt;

/// <summary>
/// Locates a VM entry + dispatcher + handler table in a decrypted image. The first pass is anchored at
/// the image entry and follows straight-line control flow, which is ideal for the synthetic stack VM and
/// simple protectors. The fallback pass scans executable sections for the same clean dispatcher shape, so
/// fault snapshots and post-stub dumps can still expose a VM whose dispatcher is not reachable from the PE
/// entry point. Anything outside that clean shape remains an honest UnsupportedVm/PartialRecovery result.
/// </summary>
public static class VmFinder
{
    private const int MaxScan = 80;
    private const int MaxHandlers = 256;
    private const int MaxBroadInstructions = 500_000;

    public sealed record Result(VmEntry? Entry, IReadOnlyList<ulong> HandlerVas, DevirtStatus Status, string Note);

    private readonly record struct TraceInsn(ulong Va, Instruction Ins);

    public static Result Find(IBinaryImage image)
    {
        var dis = new Disassembler(image);
        string why = image.EntryVa == 0 || !image.IsExecutableVa(image.EntryVa)
            ? "image has no executable entry point."
            : "no VM dispatch shape found from the entry point.";

        if (image.EntryVa != 0 && image.IsExecutableVa(image.EntryVa))
        {
            var entry = ScanFromEntry(image, dis);
            if (entry is not null) return entry;
        }

        var broad = ScanExecutableSections(image, dis, out int scanned, out int candidates);
        if (broad is not null) return broad;

        string broadNote = candidates > 0
            ? $" Broad scan checked {candidates} indirect dispatch candidate(s) in {scanned:N0} instruction(s)."
            : $" Broad scan checked {scanned:N0} instruction(s) and found no clean dispatcher.";
        return NoVisibleVm(image, why + broadNote);
    }

    private static Result? ScanFromEntry(IBinaryImage image, Disassembler dis)
    {
        var regImm = new Dictionary<Register, ulong>();
        var opcodeBase = new Dictionary<Register, Register>();
        var pushed = new List<ulong>();
        ulong va = image.EntryVa;
        var seen = new HashSet<ulong>();

        for (int steps = 0; steps < MaxScan; steps++)
        {
            if (!seen.Add(va) || !dis.TryDecodeAt(va, out var ins)) break;
            Observe(va, ins, regImm, opcodeBase, pushed);

            if (IsDispatchJmp(ins))
            {
                var result = TryBuildDispatcher(image, va, ins, regImm, opcodeBase, pushed,
                    entryVa: image.EntryVa, prefix: "VM found");
                return result ?? Partial(image, $"found an indirect dispatch at {va:X} but could not recover its VIP register, table, or handlers.");
            }

            if (ins.FlowControl == FlowControl.UnconditionalBranch && FlowAnalysis.DirectBranchTarget(ins) is ulong t)
            {
                va = t;
                continue;
            }
            if (FlowAnalysis.IsBlockTerminator(ins)) break;
            va += (ulong)ins.Length;
        }

        return null;
    }

    private static Result? ScanExecutableSections(IBinaryImage image, Disassembler dis, out int scanned, out int candidates)
    {
        scanned = 0;
        candidates = 0;
        var window = new Queue<TraceInsn>();

        foreach (var sec in image.Sections.OrderBy(s => s.StartVa))
        {
            if (!sec.IsExecutable || sec.FileSize <= 0) continue;
            window.Clear();
            ulong span = sec.VirtualSize > 0 ? Math.Min(sec.VirtualSize, (ulong)sec.FileSize) : (ulong)sec.FileSize;
            ulong va = sec.StartVa;
            ulong end = sec.StartVa + span;

            while (va < end && scanned < MaxBroadInstructions)
            {
                if (!dis.TryDecodeAt(va, out var ins) || ins.Length <= 0)
                {
                    va++;
                    continue;
                }

                scanned++;
                window.Enqueue(new TraceInsn(va, ins));
                while (window.Count > MaxScan) window.Dequeue();

                if (IsDispatchJmp(ins))
                {
                    candidates++;
                    var result = TryBuildDispatcherFromWindow(image, va, ins, window);
                    if (result is not null) return result;
                }

                va += (ulong)ins.Length;
            }

            if (scanned >= MaxBroadInstructions) break;
        }

        return null;
    }

    private static Result? TryBuildDispatcherFromWindow(IBinaryImage image, ulong dispatchVa, Instruction dispatch,
        IEnumerable<TraceInsn> window)
    {
        var regImm = new Dictionary<Register, ulong>();
        var opcodeBase = new Dictionary<Register, Register>();
        var pushed = new List<ulong>();

        foreach (var (va, ins) in window)
            Observe(va, ins, regImm, opcodeBase, pushed);

        return TryBuildDispatcher(image, dispatchVa, dispatch, regImm, opcodeBase, pushed,
            entryVa: dispatchVa, prefix: "VM found by broad scan");
    }

    private static Result? TryBuildDispatcher(IBinaryImage image, ulong dispatchVa, Instruction dispatch,
        Dictionary<Register, ulong> regImm, Dictionary<Register, Register> opcodeBase, List<ulong> pushed,
        ulong entryVa, string prefix)
    {
        ulong tableVa = dispatch.MemoryDisplacement64;
        Register indexReg = Norm(dispatch.MemoryIndex);
        Register vipReg = opcodeBase.TryGetValue(indexReg, out var v) ? v : Register.None;
        if (vipReg == Register.None || tableVa == 0) return null;

        var (handlerVas, tableIsRva) = ReadHandlerTable(image, tableVa, dispatch.MemoryIndexScale);
        if (handlerVas.Count < 2) return null;

        ulong firstVip = regImm.TryGetValue(vipReg, out var fv) ? fv : 0;
        var arch = new VmArchDescriptor
        {
            Family = VmFamily.Unknown,
            Bitness = image.Bitness,
            VipReg = vipReg,
            HandlerTableVa = tableVa,
            HandlerCount = handlerVas.Count,
            HandlerSlotSize = dispatch.MemoryIndexScale,
            HandlerTableIsRva = tableIsRva,
            HandlerTableRvaBase = tableIsRva ? image.ImageBase : 0,
        };
        var entry = new VmEntry
        {
            EntryVa = entryVa,
            DispatcherVa = dispatchVa,
            FirstVipVa = firstVip,
            PushedContext = pushed,
            Arch = arch,
        };
        string note = firstVip == 0
            ? $"{prefix}: dispatcher {dispatchVa:X}, {handlerVas.Count} handlers (VIP start unresolved)."
            : $"{prefix}: dispatcher {dispatchVa:X}, {handlerVas.Count} handlers, VIP @ {firstVip:X}.";
        if (tableIsRva) note += " Handler table entries are RVAs.";
        return new Result(entry, handlerVas, DevirtStatus.Ok, note);
    }

    private static void Observe(ulong va, Instruction ins, Dictionary<Register, ulong> regImm,
        Dictionary<Register, Register> opcodeBase, List<ulong> pushed)
    {
        if (ins.Mnemonic is Mnemonic.Pushad or Mnemonic.Pushfd or Mnemonic.Push)
            pushed.Add(va);

        if (ins.Mnemonic == Mnemonic.Mov && ins.Op0Kind == OpKind.Register && IsImm(ins.Op1Kind))
            regImm[Norm(ins.Op0Register)] = ins.GetImmediate(1);

        if ((ins.Mnemonic is Mnemonic.Movzx or Mnemonic.Mov) && ins.Op0Kind == OpKind.Register
            && ins.Op1Kind == OpKind.Memory && ins.MemoryBase != Register.None && ins.MemoryIndex == Register.None)
            opcodeBase[Norm(ins.Op0Register)] = Norm(ins.MemoryBase);
    }

    private static bool IsDispatchJmp(in Instruction ins) =>
        ins.FlowControl == FlowControl.IndirectBranch
        && ins.Op0Kind == OpKind.Memory
        && ins.MemoryIndex != Register.None
        && ins.MemoryBase == Register.None
        && ins.MemoryIndexScale is 4 or 8;

    /// <summary>Read handler-table entries until the first non-executable one. x86 tables may store VAs or RVAs.</summary>
    private static (List<ulong> Handlers, bool IsRva) ReadHandlerTable(IBinaryImage image, ulong tableVa, int slot)
    {
        var handlers = new List<ulong>();
        bool isRva = false;
        for (int i = 0; i < MaxHandlers; i++)
        {
            var bytes = image.ReadBytesAtVa(tableVa + (ulong)(i * slot), slot);
            if (bytes.Length < slot) break;

            ulong raw = slot == 8 ? BitConverter.ToUInt64(bytes) : BitConverter.ToUInt32(bytes);
            ulong target = raw;
            if (!image.IsExecutableVa(target) && slot == 4)
            {
                ulong rvaTarget = image.ImageBase + raw;
                if (image.IsExecutableVa(rvaTarget))
                {
                    target = rvaTarget;
                    isRva = true;
                }
            }

            if (!image.IsExecutableVa(target)) break;
            handlers.Add(target);
        }
        return (handlers, isRva);
    }

    private static Result NoVisibleVm(IBinaryImage image, string why)
    {
        var verdict = PackerDetector.Detect(image);
        if (verdict.Kind == PackerKind.Virtualizer)
        {
            bool memoryImage = image.FormatName.Contains("memory", StringComparison.OrdinalIgnoreCase);
            if (memoryImage)
                return new Result(null, [], DevirtStatus.UnsupportedVm,
                    "Image fingerprints as a virtualizing protector, but no supported VM dispatcher shape was found in this memory image (" +
                    why + "). The snapshot may be too early, partially encrypted, or using an obfuscated VMProtect/Themida dispatcher this experimental recognizer does not model yet.");

            return new Result(null, [], DevirtStatus.ImageEncrypted,
                "Image fingerprints as a virtualizing protector but its VM is not visible on disk (" + why +
                ") - it is still encrypted. A decrypted dump is required first.");
        }
        return new Result(null, [], DevirtStatus.NoVmFound, "No VM found: " + why);
    }

    private static Result Partial(IBinaryImage image, string why) =>
        new(null, [], DevirtStatus.PartialRecovery, why);

    private static bool IsImm(OpKind k) => k is OpKind.Immediate8 or OpKind.Immediate8to16 or OpKind.Immediate8to32
        or OpKind.Immediate16 or OpKind.Immediate32 or OpKind.Immediate8to64 or OpKind.Immediate32to64 or OpKind.Immediate64;

    /// <summary>Full-width register key, so al/ax/eax map together.</summary>
    private static Register Norm(Register r) => r.GetFullRegister();
}

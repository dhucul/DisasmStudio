using DisasmStudio.Core.Disasm;
using DisasmStudio.Core.Formats;
using DisasmStudio.Core.IL;

namespace DisasmStudio.Core.Devirt;

/// <summary>
/// The devirtualization entry point. Given a *decrypted* image it discovers the VM (<see cref="VmFinder"/>),
/// classifies each handler (<see cref="HandlerClassifier"/>), decodes the bytecode stream that the VIP walks
/// into virtual instructions, lifts them to the project IR (<see cref="VmLifter"/>), and renders Pseudo-C by
/// reusing the existing <see cref="Structurer"/> + Pseudo-C emitter. Honest about its limits: it returns a
/// non-Ok <see cref="DevirtStatus"/> (NoVmFound / ImageEncrypted / PartialRecovery) rather than guessing.
///
/// Phase 1 foundation: proven on a synthetic stack VM. Real VMProtect/Themida handler semantics, VIP
/// decryption schedules, and obtaining a decrypted dump of an anti-debug-protected sample are later phases.
/// </summary>
public static class DevirtEngine
{
    public static DevirtResult Run(IBinaryImage image)
    {
        var found = VmFinder.Find(image);
        if (found.Status != DevirtStatus.Ok || found.Entry is null)
            return new DevirtResult { Status = found.Status, Message = found.Note };

        var entry = found.Entry;
        var dis = new Disassembler(image);

        // Classify each handler in table order; opcode N is the handler at table slot N.
        var handlers = new List<HandlerInfo>(found.HandlerVas.Count);
        foreach (var hva in found.HandlerVas)
            handlers.Add(HandlerClassifier.Classify(image, dis, entry.Arch, hva));
        bool partial = handlers.Any(h => h.Kind == HandlerKind.Unknown);

        if (entry.FirstVipVa == 0)
            return new DevirtResult
            {
                Status = DevirtStatus.PartialRecovery, Entry = entry, Handlers = handlers,
                Message = "VM located but the bytecode start (VIP) could not be resolved.",
            };

        // Decode the VIP byte stream into virtual instructions, following branch targets + fall-through.
        var byVip = new Dictionary<ulong, VInsn>();
        var work = new Queue<ulong>();
        work.Enqueue(entry.FirstVipVa);
        while (work.Count > 0)
        {
            ulong vip = work.Dequeue();
            if (byVip.ContainsKey(vip)) continue;
            var ob = image.ReadBytesAtVa(vip, 1);
            if (ob.Length < 1) { partial = true; continue; }
            int opcode = ob[0];
            if (opcode >= handlers.Count) { partial = true; continue; }   // outside the handler table

            var h = handlers[opcode];
            long operand = 0;
            if (h.OperandBytes >= 4)
            {
                var opb = image.ReadBytesAtVa(vip + 1, 4);
                if (opb.Length >= 4) operand = BitConverter.ToInt32(opb, 0); else partial = true;
            }
            byVip[vip] = new VInsn { VipVa = vip, Index = -1, Handler = h, Operand = operand };

            if (h.Kind == HandlerKind.Unknown) { partial = true; continue; }   // unknown stride: stop this path
            if (h.Kind == HandlerKind.VmExit) continue;
            work.Enqueue(vip + 1 + (ulong)h.OperandBytes);                      // fall-through
            if (h.Kind is HandlerKind.Branch or HandlerKind.Jump) work.Enqueue((ulong)operand);
        }

        // Order by VIP VA, assign indices, resolve branch target indices.
        var ordered = byVip.Values.OrderBy(v => v.VipVa).ToList();
        var indexOf = new Dictionary<ulong, int>();
        for (int i = 0; i < ordered.Count; i++) indexOf[ordered[i].VipVa] = i;
        var program = new List<VInsn>(ordered.Count);
        for (int i = 0; i < ordered.Count; i++)
        {
            var v = ordered[i];
            int? target = v.Handler.Kind is HandlerKind.Branch or HandlerKind.Jump
                && indexOf.TryGetValue((ulong)v.Operand, out var ti) ? ti : null;
            if (v.Handler.Kind is HandlerKind.Branch or HandlerKind.Jump && target is null) partial = true;
            program.Add(v with { Index = i, BranchTargetIndex = target });
        }

        if (program.Count == 0)
            return new DevirtResult
            {
                Status = DevirtStatus.PartialRecovery, Entry = entry, Handlers = handlers,
                Message = "VM located but no bytecode could be decoded.",
            };

        var lifted = VmLifter.Lift(entry, program);
        var (root, labels) = Structurer.Structure(lifted);
        var pseudoC = StructEmitter.Emit(lifted, root, labels, pseudoC: true, comments: null);

        return new DevirtResult
        {
            Status = partial ? DevirtStatus.PartialRecovery : DevirtStatus.Ok,
            Entry = entry,
            Handlers = handlers,
            Program = program,
            Lifted = lifted,
            PseudoC = pseudoC,
            Message = partial
                ? $"Recovered {program.Count} virtual instruction(s); some handlers/branches were not resolved."
                : $"Devirtualized {program.Count} virtual instruction(s) across {lifted.Blocks.Count} block(s).",
        };
    }
}

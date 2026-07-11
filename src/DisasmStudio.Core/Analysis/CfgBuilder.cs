using DisasmStudio.Core.Disasm;
using DisasmStudio.Core.Formats;

namespace DisasmStudio.Core.Analysis;

/// <summary>
/// Builds a function's control-flow graph by recursive descent from its entry, then splits the
/// reachable instructions into basic blocks at branch targets and after conditional branches.
/// Calls do NOT split blocks (they return), matching the usual disassembler convention. Bounded by
/// an instruction cap so a mis-identified function can't run away.
/// </summary>
public static class CfgBuilder
{
    private const int MaxInstructions = 200_000;

    public static void Build(IBinaryImage image, Function fn, IReadOnlyDictionary<ulong, ulong[]>? jumpTables = null,
        INeutralDisassembler? decoder = null)
    {
        if (fn.BlocksBuilt) return;

        INeutralDisassembler dis = decoder ?? NeutralDisasm.For(image, null);

        // Reachability gate for the descent. Normally an address must sit in an *executable* section — this
        // stops a mis-identified data "function" from decoding pointer bytes into a junk CFG. But some images
        // don't flag their code executable at all: a live-process / memory dump whose region protections read
        // non-exec, a packed section, an odd firmware/ELF layout. There the strict gate rejects even a valid
        // entry the linear listing happily disassembles, so the CFG comes back empty and the graph + every
        // decompiler level show "no code recovered". When the entry is NOT flagged executable yet is mapped and
        // actually decodes to an instruction (and isn't a known IAT data slot), fall back to a mapped-only gate
        // so we still recover the function's control flow, matching what the listing shows.
        bool lenient = !image.IsExecutableVa(fn.Va) && !image.ImportsByIatVa.ContainsKey(fn.Va)
                       && image.IsMappedVa(fn.Va) && dis.TryDecode(fn.Va, out _);
        bool Reachable(ulong va) => lenient ? image.IsMappedVa(va) : image.IsExecutableVa(va);

        // Recursive descent normally begins at the function's entry. If the entry VA doesn't decode —
        // typically because the function was recovered from a code pointer that landed in the middle of
        // an instruction — nudge the start forward to the first decodable instruction so we still
        // disassemble from (near) the function rather than reporting nothing. The realigned stream
        // re-syncs to the real code within a few bytes. Bounded by the longest x86/x64 instruction.
        // A known import (IAT) slot is data, not misaligned code (some images keep the IAT in .text, so a
        // call-through target looks like a function), so it's left to produce no blocks rather than
        // decoding the pointer bytes into a junk CFG.
        ulong entry = fn.Va;
        if (Reachable(entry) && !image.ImportsByIatVa.ContainsKey(entry) && !dis.TryDecode(entry, out _))
            for (int k = 1; k <= 15; k++)
                if (Reachable(entry + (ulong)k) && dis.TryDecode(entry + (ulong)k, out _))
                { entry += (ulong)k; break; }

        var insns = new SortedDictionary<ulong, NeutralInsn>();
        var leaders = new HashSet<ulong> { entry };
        var visited = new HashSet<ulong>();
        var work = new Stack<ulong>();
        work.Push(entry);

        while (work.Count > 0 && insns.Count < MaxInstructions)
        {
            ulong va = work.Pop();
            if (!visited.Add(va)) continue;
            if (!Reachable(va) || !dis.TryDecode(va, out var instr)) continue;

            insns[va] = instr;
            ulong fall = va + (ulong)instr.Length;

            switch (instr.Flow)
            {
                case FlowKind.CondJump:
                {
                    if (instr.DirectTarget is ulong t && image.IsExecutableVa(t)) { leaders.Add(t); work.Push(t); }
                    leaders.Add(fall); work.Push(fall);
                    break;
                }
                case FlowKind.Jump:
                {
                    if (instr.DirectTarget is ulong t && image.IsExecutableVa(t)) { leaders.Add(t); work.Push(t); }
                    break; // no fall-through
                }
                case FlowKind.IndirectJump:
                    // A recovered jump table turns an indirect jmp into real, followable case targets.
                    if (jumpTables is not null && jumpTables.TryGetValue(va, out var cases))
                        foreach (var t in cases)
                            if (image.IsExecutableVa(t)) { leaders.Add(t); work.Push(t); }
                    break;
                case FlowKind.Ret:
                case FlowKind.Interrupt:
                    break; // path ends here
                default:
                    work.Push(fall); // Seq / Call / IndirectCall — execution continues after
                    break;
            }
        }

        fn.SetBlocks(SplitIntoBlocks(insns, leaders, jumpTables), entry);
    }

    private static List<BasicBlock> SplitIntoBlocks(SortedDictionary<ulong, NeutralInsn> insns, HashSet<ulong> leaders,
        IReadOnlyDictionary<ulong, ulong[]>? jumpTables)
    {
        var blocks = new List<BasicBlock>();
        BasicBlock? cur = null;
        bool terminated = false;

        foreach (var (va, instr) in insns)
        {
            if (cur is null || leaders.Contains(va))
            {
                if (cur is not null && !terminated) cur.Out.Add(new CfgEdge(va, EdgeKind.FallThrough));
                cur = new BasicBlock { Start = va };
                blocks.Add(cur);
                terminated = false;
            }

            cur.InstrVas.Add(va);
            cur.End = va + (ulong)instr.Length;

            if (instr.IsBlockTerminator)
            {
                AddTerminatorEdges(instr, va, insns, cur, jumpTables);
                terminated = true;
            }
        }
        return blocks;
    }

    private static void AddTerminatorEdges(in NeutralInsn instr, ulong va,
        SortedDictionary<ulong, NeutralInsn> insns, BasicBlock block, IReadOnlyDictionary<ulong, ulong[]>? jumpTables)
    {
        ulong fall = va + (ulong)instr.Length;
        switch (instr.Flow)
        {
            case FlowKind.CondJump:
                if (instr.DirectTarget is ulong t && insns.ContainsKey(t))
                    block.Out.Add(new CfgEdge(t, EdgeKind.Taken));
                if (insns.ContainsKey(fall)) block.Out.Add(new CfgEdge(fall, EdgeKind.FallThrough));
                break;
            case FlowKind.Jump:
                if (instr.DirectTarget is ulong j && insns.ContainsKey(j))
                    block.Out.Add(new CfgEdge(j, EdgeKind.Jump));
                break;
            case FlowKind.IndirectJump:
                if (jumpTables is not null && jumpTables.TryGetValue(va, out var cases))
                    foreach (var c in cases)
                        if (insns.ContainsKey(c)) block.Out.Add(new CfgEdge(c, EdgeKind.Switch));
                break;
        }
    }
}

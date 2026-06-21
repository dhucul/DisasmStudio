using DisasmStudio.Core.Disasm;
using DisasmStudio.Core.Formats;
using Iced.Intel;

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
        IInstructionDecoder? decoder = null)
    {
        if (fn.BlocksBuilt) return;

        IInstructionDecoder dis = decoder ?? new Disassembler(image);

        // Recursive descent normally begins at the function's entry. If the entry VA doesn't decode —
        // typically because the function was recovered from a code pointer that landed in the middle of
        // an instruction — nudge the start forward to the first decodable instruction so we still
        // disassemble from (near) the function rather than reporting nothing. The realigned stream
        // re-syncs to the real code within a few bytes. Bounded by the longest x86/x64 instruction.
        // A known import (IAT) slot is data, not misaligned code (some images keep the IAT in .text, so a
        // call-through target looks like a function), so it's left to produce no blocks rather than
        // decoding the pointer bytes into a junk CFG.
        ulong entry = fn.Va;
        if (image.IsExecutableVa(entry) && !image.ImportsByIatVa.ContainsKey(entry) && !dis.TryDecodeAt(entry, out _))
            for (int k = 1; k <= 15; k++)
                if (image.IsExecutableVa(entry + (ulong)k) && dis.TryDecodeAt(entry + (ulong)k, out _))
                { entry += (ulong)k; break; }

        var insns = new SortedDictionary<ulong, Instruction>();
        var leaders = new HashSet<ulong> { entry };
        var visited = new HashSet<ulong>();
        var work = new Stack<ulong>();
        work.Push(entry);

        while (work.Count > 0 && insns.Count < MaxInstructions)
        {
            ulong va = work.Pop();
            if (!visited.Add(va)) continue;
            if (!image.IsExecutableVa(va) || !dis.TryDecodeAt(va, out var instr)) continue;

            insns[va] = instr;
            ulong fall = va + (ulong)instr.Length;

            switch (instr.FlowControl)
            {
                case FlowControl.ConditionalBranch:
                {
                    ulong t = instr.NearBranchTarget;
                    if (image.IsExecutableVa(t)) { leaders.Add(t); work.Push(t); }
                    leaders.Add(fall); work.Push(fall);
                    break;
                }
                case FlowControl.UnconditionalBranch:
                {
                    ulong t = instr.NearBranchTarget;
                    if (FlowAnalysis.DirectBranchTarget(instr) is not null && image.IsExecutableVa(t))
                    { leaders.Add(t); work.Push(t); }
                    break; // no fall-through
                }
                case FlowControl.IndirectBranch:
                    // A recovered jump table turns an indirect jmp into real, followable case targets.
                    if (jumpTables is not null && jumpTables.TryGetValue(va, out var cases))
                        foreach (var t in cases)
                            if (image.IsExecutableVa(t)) { leaders.Add(t); work.Push(t); }
                    break;
                case FlowControl.Return:
                case FlowControl.Interrupt:
                case FlowControl.Exception:
                    break; // path ends here
                default:
                    work.Push(fall); // Next / Call / IndirectCall — execution continues after
                    break;
            }
        }

        fn.SetBlocks(SplitIntoBlocks(insns, leaders, jumpTables), entry);
    }

    private static List<BasicBlock> SplitIntoBlocks(SortedDictionary<ulong, Instruction> insns, HashSet<ulong> leaders,
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

            if (FlowAnalysis.IsBlockTerminator(instr))
            {
                AddTerminatorEdges(instr, va, insns, cur, jumpTables);
                terminated = true;
            }
        }
        return blocks;
    }

    private static void AddTerminatorEdges(in Instruction instr, ulong va,
        SortedDictionary<ulong, Instruction> insns, BasicBlock block, IReadOnlyDictionary<ulong, ulong[]>? jumpTables)
    {
        ulong fall = va + (ulong)instr.Length;
        switch (instr.FlowControl)
        {
            case FlowControl.ConditionalBranch:
                if (FlowAnalysis.DirectBranchTarget(instr) is ulong t && insns.ContainsKey(t))
                    block.Out.Add(new CfgEdge(t, EdgeKind.Taken));
                if (insns.ContainsKey(fall)) block.Out.Add(new CfgEdge(fall, EdgeKind.FallThrough));
                break;
            case FlowControl.UnconditionalBranch:
                if (FlowAnalysis.DirectBranchTarget(instr) is ulong j && insns.ContainsKey(j))
                    block.Out.Add(new CfgEdge(j, EdgeKind.Jump));
                break;
            case FlowControl.IndirectBranch:
                if (jumpTables is not null && jumpTables.TryGetValue(va, out var cases))
                    foreach (var c in cases)
                        if (insns.ContainsKey(c)) block.Out.Add(new CfgEdge(c, EdgeKind.Switch));
                break;
        }
    }
}

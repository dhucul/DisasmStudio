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
        var insns = new SortedDictionary<ulong, Instruction>();
        var leaders = new HashSet<ulong> { fn.Va };
        var visited = new HashSet<ulong>();
        var work = new Stack<ulong>();
        work.Push(fn.Va);

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

        fn.SetBlocks(SplitIntoBlocks(insns, leaders, jumpTables));
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

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

    public static void Build(IBinaryImage image, Function fn)
    {
        if (fn.BlocksBuilt) return;

        var dis = new Disassembler(image);
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
                case FlowControl.Return:
                case FlowControl.Interrupt:
                case FlowControl.Exception:
                case FlowControl.IndirectBranch:
                    break; // path ends here
                default:
                    work.Push(fall); // Next / Call / IndirectCall — execution continues after
                    break;
            }
        }

        fn.SetBlocks(SplitIntoBlocks(insns, leaders));
    }

    private static List<BasicBlock> SplitIntoBlocks(SortedDictionary<ulong, Instruction> insns, HashSet<ulong> leaders)
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
                AddTerminatorEdges(instr, va, insns, cur);
                terminated = true;
            }
        }
        return blocks;
    }

    private static void AddTerminatorEdges(in Instruction instr, ulong va,
        SortedDictionary<ulong, Instruction> insns, BasicBlock block)
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
        }
    }
}

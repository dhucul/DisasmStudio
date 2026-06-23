using DisasmStudio.Core.Analysis;
using DisasmStudio.Core.IL;

namespace DisasmStudio.Core.Devirt;

/// <summary>
/// Lifts a recovered virtual-instruction stream into the project's architecture-neutral IR
/// (<see cref="LiftedFunction"/>) by symbolic stack-folding: a compile-time model stack of <see cref="Expr"/>
/// is walked over the vinsns so a <c>push;push;add;pop v0</c> sequence collapses to <c>v0 = a + b</c>. Block
/// boundaries are the branch targets / post-branch / post-exit points; the synthesized blocks + CFG edges feed
/// straight into <see cref="Structurer"/> and the existing Pseudo-C emitter (no new renderer). Each block is
/// lifted with a fresh empty model stack — valid for the well-formed stack VMs this phase targets.
/// </summary>
internal static class VmLifter
{
    public static LiftedFunction Lift(VmEntry entry, IReadOnlyList<VInsn> program)
    {
        int width = entry.Arch.Bitness / 8;
        var vregs = new Dictionary<int, Variable>();
        Variable VReg(int i) => vregs.TryGetValue(i, out var v) ? v
            : vregs[i] = new Variable { Name = $"v{i}", Size = width, Class = VarClass.Local };

        // Block leaders: program start, every branch target + its fall-through, and the slot after a VM exit.
        var leaders = new HashSet<ulong>();
        if (program.Count > 0) leaders.Add(program[0].VipVa);
        for (int i = 0; i < program.Count; i++)
        {
            var k = program[i].Handler.Kind;
            if (k == HandlerKind.Branch)
            {
                leaders.Add((ulong)program[i].Operand);
                if (i + 1 < program.Count) leaders.Add(program[i + 1].VipVa);
            }
            else if (k == HandlerKind.VmExit && i + 1 < program.Count)
                leaders.Add(program[i + 1].VipVa);
        }

        var blocks = new List<LiftedBlock>();
        int idx = 0;
        while (idx < program.Count)
        {
            int start = idx;
            ulong startVip = program[start].VipVa;
            var stack = new Stack<Expr>();
            var stmts = new List<Stmt>();
            IReadOnlyList<CfgEdge> outEdges = [];

            int j = start;
            for (; j < program.Count; j++)
            {
                var vi = program[j];
                bool boundary = j + 1 >= program.Count || leaders.Contains(program[j + 1].VipVa);
                var term = Emit(vi, stack, stmts, VReg, width, j + 1 < program.Count ? program[j + 1].VipVa : 0);
                if (term is not null) { outEdges = term; break; }      // Branch / VmExit ended the block
                if (boundary) { outEdges = [new CfgEdge(program[j + 1].VipVa, EdgeKind.FallThrough)]; break; }
            }
            idx = j + 1;

            var blk = new LiftedBlock { Start = startVip, End = startVip, Out = outEdges };
            blk.Stmts.AddRange(stmts);
            blocks.Add(blk);
        }

        var fn = new LiftedFunction
        {
            Va = program.Count > 0 ? program[0].VipVa : 0,
            Name = $"vm_{entry.EntryVa:X}",
            Blocks = blocks,
        };
        foreach (var v in vregs.Values) fn.Variables.Add(v);
        foreach (var b in blocks) fn.ByStart[b.Start] = b;
        return fn;
    }

    /// <summary>Fold one vinsn into the model stack / statements. Returns the block's out-edges when the vinsn
    /// is a terminator (branch / exit), else null.</summary>
    private static IReadOnlyList<CfgEdge>? Emit(VInsn vi, Stack<Expr> stack, List<Stmt> stmts,
        System.Func<int, Variable> vreg, int width, ulong fallVip)
    {
        var h = vi.Handler;
        switch (h.Kind)
        {
            case HandlerKind.PushImm:
                stack.Push(new Const(vi.Operand, width));
                return null;
            case HandlerKind.PushReg:
                stack.Push(new VarExpr(vreg(h.RegIndex)));
                return null;
            case HandlerKind.PopReg:
                stmts.Add(new AssignStmt { Va = vi.VipVa, Dest = new VarExpr(vreg(h.RegIndex)), Src = Pop(stack) });
                return null;
            case HandlerKind.BinOp:
            {
                var r = Pop(stack); var l = Pop(stack);
                stack.Push(new BinExpr(h.BinOp ?? IL.BinOp.Add, l, r, width));
                return null;
            }
            case HandlerKind.UnOp:
                stack.Push(new UnaryExpr(h.UnOp ?? IL.UnOp.Neg, Pop(stack), width));
                return null;
            case HandlerKind.Compare:
            {
                var r = Pop(stack); var l = Pop(stack);
                stack.Push(new CmpExpr(h.CmpOp ?? IL.CmpOp.Ne, l, r));
                return null;
            }
            case HandlerKind.Load:
                stack.Push(new LoadExpr(Pop(stack), width));
                return null;
            case HandlerKind.Store:
            {
                var val = Pop(stack); var addr = Pop(stack);
                stmts.Add(new AssignStmt { Va = vi.VipVa, Dest = new LoadExpr(addr, width), Src = val });
                return null;
            }
            case HandlerKind.Branch:
            {
                var cond = Pop(stack);
                ulong target = (ulong)vi.Operand;
                stmts.Add(new BranchStmt { Va = vi.VipVa, Cond = cond, IfTrue = fallVip, IfFalse = target });
                return [new CfgEdge(fallVip, EdgeKind.FallThrough), new CfgEdge(target, EdgeKind.Taken)];
            }
            case HandlerKind.Jump:
            {
                ulong target = (ulong)vi.Operand;
                stmts.Add(new GotoStmt { Va = vi.VipVa, Target = target });
                return [new CfgEdge(target, EdgeKind.Jump)];
            }
            case HandlerKind.VmExit:
            {
                Expr? v = stack.Count > 0 ? Pop(stack) : null;
                stmts.Add(new ReturnStmt { Va = vi.VipVa, Value = v });
                return [];
            }
            default:
                stmts.Add(new AsmStmt { Va = vi.VipVa, Text = $"vm_unknown_{vi.Operand:X}" });
                return null;
        }
    }

    private static Expr Pop(Stack<Expr> s) => s.Count > 0 ? s.Pop() : new RawExpr("vm_underflow");
}

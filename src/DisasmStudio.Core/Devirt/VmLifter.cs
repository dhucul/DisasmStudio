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
            if (k is HandlerKind.Branch or HandlerKind.Jump)
            {
                leaders.Add((ulong)program[i].Operand);
                if (k == HandlerKind.Branch)
                {
                    ulong stride = 1UL + (ulong)program[i].Handler.OperandBytes;
                    if (program[i].VipVa <= ulong.MaxValue - stride)
                        leaders.Add(program[i].VipVa + stride);
                }
            }
            else if (k == HandlerKind.VmExit && i + 1 < program.Count)
                leaders.Add(program[i + 1].VipVa);
        }

        // Every decoded vinsn's VIP is a candidate block start (a branch target is always also a leader, so a
        // decoded target is a real block) — used to keep every emitted CFG edge pointing at an existing block.
        var starts = new HashSet<ulong>(program.Select(p => p.VipVa));
        var entryStacks = ComputeEntryStacks(program, leaders, starts, VReg, width);
        var blocks = new List<LiftedBlock>();
        int idx = 0;
        while (idx < program.Count)
        {
            int start = idx;
            ulong startVip = program[start].VipVa;
            var stack = entryStacks.TryGetValue(startVip, out var incoming)
                ? new Stack<Expr>(incoming.Reverse())
                : new Stack<Expr>();
            var stmts = new List<Stmt>();
            IReadOnlyList<CfgEdge> outEdges = [];

            int j = start;
            for (; j < program.Count; j++)
            {
                var vi = program[j];
                ulong fall = NextVip(vi, starts);
                bool boundary = fall == 0 || leaders.Contains(fall)
                    || j + 1 >= program.Count || program[j + 1].VipVa != fall;
                var term = Emit(vi, stack, stmts, VReg, width, fall, starts);
                if (term is not null) { outEdges = term; break; }      // Branch / Jump / VmExit ended the block
                if (boundary) { outEdges = fall != 0 ? [new CfgEdge(fall, EdgeKind.FallThrough)] : []; break; }
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
        System.Func<int, Variable> vreg, int width, ulong fallVip, HashSet<ulong> starts)
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
                ulong fall = fallVip;
                bool tValid = starts.Contains(target), fValid = fall != 0 && starts.Contains(fall);
                if (!tValid && !fValid) { stmts.Add(new ReturnStmt { Va = vi.VipVa }); return []; }  // nowhere to go
                if (!fValid) fall = target;     // only the taken target resolved
                if (!tValid) target = fall;     // only the fall-through resolved
                stmts.Add(new BranchStmt { Va = vi.VipVa, Cond = cond, IfTrue = target, IfFalse = fall });
                var edges = new List<CfgEdge> { new(fall, EdgeKind.FallThrough) };
                if (target != fall) edges.Add(new(target, EdgeKind.Taken));
                return edges;
            }
            case HandlerKind.Jump:
            {
                ulong target = (ulong)vi.Operand;
                if (!starts.Contains(target)) { stmts.Add(new ReturnStmt { Va = vi.VipVa }); return []; }  // unresolved
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

    private static ulong NextVip(VInsn vi, HashSet<ulong> starts)
    {
        ulong stride = 1UL + (ulong)vi.Handler.OperandBytes;
        if (vi.VipVa > ulong.MaxValue - stride) return 0;
        ulong next = vi.VipVa + stride;
        return starts.Contains(next) ? next : 0;
    }

    private static Dictionary<ulong, Expr[]> ComputeEntryStacks(
        IReadOnlyList<VInsn> program, HashSet<ulong> leaders, HashSet<ulong> starts,
        Func<int, Variable> vreg, int width)
    {
        var index = program.Select((v, i) => (v.VipVa, i)).ToDictionary(x => x.VipVa, x => x.i);
        var entries = new Dictionary<ulong, Expr[]> { [program[0].VipVa] = [] };
        var work = new Queue<ulong>();
        work.Enqueue(program[0].VipVa);
        int visits = 0;

        while (work.Count > 0)
        {
            if (++visits > Math.Max(1000, program.Count * 8))
                throw new InvalidDataException("VM stack analysis did not converge.");

            ulong start = work.Dequeue();
            if (!index.TryGetValue(start, out int j)) continue;
            var stack = new Stack<Expr>(entries[start].Reverse());
            IReadOnlyList<CfgEdge> successors = [];

            for (; j < program.Count; j++)
            {
                var vi = program[j];
                ulong fall = NextVip(vi, starts);
                bool boundary = fall == 0 || leaders.Contains(fall)
                    || j + 1 >= program.Count || program[j + 1].VipVa != fall;
                successors = Emit(vi, stack, [], vreg, width, fall, starts) ?? [];
                if (successors.Count > 0 || vi.Handler.Kind is HandlerKind.VmExit or HandlerKind.Jump or HandlerKind.Branch)
                    break;
                if (boundary)
                {
                    successors = fall == 0 ? [] : [new CfgEdge(fall, EdgeKind.FallThrough)];
                    break;
                }
            }

            Expr[] outgoing = stack.ToArray();
            foreach (var edge in successors)
            {
                ulong target = edge.ToBlockStart;
                if (!index.ContainsKey(target)) continue;
                if (!entries.TryGetValue(target, out var old))
                {
                    entries[target] = outgoing;
                    work.Enqueue(target);
                    continue;
                }
                if (old.Length != outgoing.Length)
                    throw new InvalidDataException($"Inconsistent VM stack height at VIP 0x{target:X}.");

                bool changed = false;
                var merged = new Expr[old.Length];
                for (int i = 0; i < old.Length; i++)
                {
                    merged[i] = old[i].Equals(outgoing[i])
                        ? old[i]
                        : new RawExpr($"vm_phi_{target:X}_{i}");
                    changed |= !merged[i].Equals(old[i]);
                }
                if (changed)
                {
                    entries[target] = merged;
                    work.Enqueue(target);
                }
            }
        }
        return entries;
    }
}

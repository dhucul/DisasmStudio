using DisasmStudio.Core.Analysis;

namespace DisasmStudio.Core.IL;

/// <summary>
/// Recovers structured control flow (the High IL / Pseudo-C tree) from a lifted function's CFG. It
/// uses dominators to find natural loops and post-dominators to find the merge point of a
/// conditional, recovering <c>if/else</c>, <c>while</c> and <c>switch</c>. Anything that does not fit
/// a clean pattern falls back to a labelled <c>goto</c>, so the structuring is always a faithful
/// representation of the control flow — never wrong, just less pretty on irreducible code.
/// </summary>
public sealed class Structurer
{
    private const ulong Exit = ulong.MaxValue;       // virtual exit node for post-dominators
    private const int MaxDepth = 400;

    private readonly LiftedFunction _fn;
    private readonly Dictionary<ulong, LiftedBlock> _byStart;
    private readonly List<ulong> _nodes;
    private readonly Dictionary<ulong, List<ulong>> _succ = [];
    private readonly Dictionary<ulong, List<ulong>> _pred = [];
    private Dictionary<ulong, ulong> _idom = [];
    private Dictionary<ulong, ulong> _ipdom = [];
    private readonly Dictionary<ulong, Loop> _loops = [];
    private readonly HashSet<ulong> _emitted = [];
    private readonly HashSet<ulong> _labelNeeded = [];

    private sealed class Loop { public ulong Header; public HashSet<ulong> Body = []; public ulong Follow; public bool HasFollow; }

    private Structurer(LiftedFunction fn)
    {
        _fn = fn;
        _byStart = fn.ByStart;
        _nodes = fn.Blocks.Select(b => b.Start).ToList();
    }

    public static (Stmt Root, IReadOnlySet<ulong> Labels) Structure(LiftedFunction fn)
    {
        if (fn.Blocks.Count == 0) return (new SeqStmt(), new HashSet<ulong>());
        var s = new Structurer(fn);
        s.BuildEdges();
        s.BuildDominators();
        s.DetectLoops();
        var root = s.EmitSeq(fn.Va, [], null, 0);
        return (root, s._labelNeeded);
    }

    // ---- graph ----

    private void BuildEdges()
    {
        foreach (var n in _nodes) { _succ[n] = []; _pred[n] = []; }
        foreach (var b in _fn.Blocks)
            foreach (var e in b.Out)
                if (_byStart.ContainsKey(e.ToBlockStart) && !_succ[b.Start].Contains(e.ToBlockStart))
                    _succ[b.Start].Add(e.ToBlockStart);
        foreach (var n in _nodes)
            foreach (var t in _succ[n])
                _pred[t].Add(n);
    }

    private void BuildDominators()
    {
        _idom = Dominators(_fn.Va, n => _succ[n]);

        // Post-dominators: dominators of the reverse graph from a virtual exit that every
        // terminal block (return / no in-function successor) flows to.
        var rsucc = new Dictionary<ulong, List<ulong>>();
        foreach (var n in _nodes) rsucc[n] = [];
        rsucc[Exit] = [];
        foreach (var n in _nodes)
            foreach (var t in _succ[n]) rsucc[t].Add(n);   // reversed edge t -> n
        // a terminal block (return / no successor) flows to the virtual exit: reversed, Exit -> terminal.
        foreach (var n in _nodes) if (_succ[n].Count == 0) rsucc[Exit].Add(n);
        _ipdom = Dominators(Exit, n => rsucc.TryGetValue(n, out var l) ? l : []);
    }

    /// <summary>Cooper–Harvey–Kennedy iterative dominators over the graph reachable from
    /// <paramref name="entry"/> via <paramref name="succ"/>.</summary>
    private static Dictionary<ulong, ulong> Dominators(ulong entry, Func<ulong, List<ulong>> succ)
    {
        // Iterative post-order DFS (a recursive walk would overflow the stack on a long block chain).
        var rpo = new List<ulong>();
        var seen = new HashSet<ulong> { entry };
        var work = new Stack<(ulong Node, int Idx)>();
        work.Push((entry, 0));
        while (work.Count > 0)
        {
            var (n, i) = work.Pop();
            var ss = succ(n);
            if (i < ss.Count)
            {
                work.Push((n, i + 1));
                if (seen.Add(ss[i])) work.Push((ss[i], 0));
            }
            else rpo.Add(n);   // post-order
        }
        rpo.Reverse();
        var rpoIdx = new Dictionary<ulong, int>();
        for (int i = 0; i < rpo.Count; i++) rpoIdx[rpo[i]] = i;

        var preds = new Dictionary<ulong, List<ulong>>();
        foreach (var n in rpo) preds[n] = [];
        foreach (var n in rpo) foreach (var s in succ(n)) if (preds.ContainsKey(s)) preds[s].Add(n);

        var idom = new Dictionary<ulong, ulong> { [entry] = entry };
        ulong Intersect(ulong a, ulong b)
        {
            while (a != b)
            {
                while (rpoIdx[a] > rpoIdx[b]) a = idom[a];
                while (rpoIdx[b] > rpoIdx[a]) b = idom[b];
            }
            return a;
        }

        bool changed = true;
        int guard = 0;
        while (changed && guard++ < 5000)
        {
            changed = false;
            foreach (var n in rpo)
            {
                if (n == entry) continue;
                ulong newIdom = 0; bool have = false;
                foreach (var p in preds[n])
                {
                    if (!idom.ContainsKey(p)) continue;
                    if (!have) { newIdom = p; have = true; }
                    else newIdom = Intersect(p, newIdom);
                }
                if (have && (!idom.TryGetValue(n, out var cur) || cur != newIdom)) { idom[n] = newIdom; changed = true; }
            }
        }
        return idom;
    }

    private bool Dominates(ulong a, ulong b)
    {
        for (ulong x = b; ; x = _idom[x])
        {
            if (x == a) return true;
            if (!_idom.TryGetValue(x, out var nx) || nx == x) return false;
        }
    }

    private void DetectLoops()
    {
        foreach (var n in _nodes)
            foreach (var s in _succ[n])
                if (_idom.ContainsKey(n) && _idom.ContainsKey(s) && Dominates(s, n))   // back edge n -> header s
                {
                    var loop = _loops.TryGetValue(s, out var ex) ? ex : (_loops[s] = new Loop { Header = s });
                    loop.Body.Add(s);
                    // natural loop body: everything that reaches n without passing through the header
                    var stack = new Stack<ulong>();
                    if (loop.Body.Add(n)) stack.Push(n);
                    while (stack.Count > 0)
                    {
                        var x = stack.Pop();
                        foreach (var p in _pred[x])
                            if (p != s && loop.Body.Add(p)) stack.Push(p);
                    }
                }

        // follow node = an out-of-body successor of a body node (prefer the loop header's exit).
        foreach (var loop in _loops.Values)
        {
            var exits = new List<ulong>();
            foreach (var b in loop.Body)
                foreach (var s in _succ[b])
                    if (!loop.Body.Contains(s) && !exits.Contains(s)) exits.Add(s);
            if (exits.Count > 0) { loop.Follow = exits[0]; loop.HasFollow = true; }
        }
    }

    // ---- structured emission ----

    private SeqStmt EmitSeq(ulong start, HashSet<ulong> stop, Loop? loop, int depth)
    {
        var seq = new SeqStmt();
        ulong? cur = start;
        while (cur is ulong b)
        {
            if (loop is not null && b == loop.Header && start != b) { seq.Items.Add(new ContinueStmt()); break; }
            if (loop is { HasFollow: true } && b == loop.Follow) { seq.Items.Add(new BreakStmt()); break; }
            if (stop.Contains(b)) break;                                   // outer scope owns this block
            if (_emitted.Contains(b)) { seq.Items.Add(new GotoStmt { Target = b }); _labelNeeded.Add(b); break; }
            if (depth > MaxDepth) { seq.Items.Add(new GotoStmt { Target = b }); _labelNeeded.Add(b); break; }

            // Start of a loop we are not already inside.
            if (_loops.TryGetValue(b, out var lp) && (loop is null || loop.Header != b))
            {
                seq.Items.Add(EmitLoop(lp, stop, loop, depth));
                cur = lp is { HasFollow: true } && !_emitted.Contains(lp.Follow) ? lp.Follow : null;
                continue;
            }

            _emitted.Add(b);
            var block = _byStart[b];
            var (body, term) = Split(block);
            seq.Items.Add(new LabelStmt { Target = b });   // placeholder; pruned later if unreferenced
            foreach (var st in body) seq.Items.Add(st);

            cur = EmitTerminator(seq, block, term, stop, loop, depth);
        }
        return seq;
    }

    private ulong? EmitTerminator(SeqStmt seq, LiftedBlock block, Stmt? term, HashSet<ulong> stop, Loop? loop, int depth)
    {
        switch (term)
        {
            case ReturnStmt r:
                seq.Items.Add(r);
                return null;

            case GotoStmt g:
                return FollowEdge(seq, g.Target, loop) ? null : g.Target;

            case null:   // fall-through block
            {
                ulong? f = FallThrough(block);
                if (f is null) return null;
                return FollowEdge(seq, f.Value, loop) ? null : f.Value;
            }

            case SwitchTermStmt sw:
            {
                ulong merge = MergeOf(block.Start);
                var stmt = new StructSwitchStmt { Va = sw.Va, Value = sw.Value };
                var childStop = new HashSet<ulong>(stop); if (merge != 0) childStop.Add(merge);
                // Group the case values (jump-table indices) by their target, in first-appearance order, so a
                // target reached by several values emits `case 0: case 1: …` with the real selectors instead of
                // a single synthetic ordinal lost to Distinct().
                var byTarget = new Dictionary<ulong, List<long>>();
                var order = new List<ulong>();
                for (int i = 0; i < sw.Cases.Count; i++)
                {
                    if (!byTarget.TryGetValue(sw.Cases[i], out var vals)) { vals = []; byTarget[sw.Cases[i]] = vals; order.Add(sw.Cases[i]); }
                    vals.Add(i);
                }
                foreach (var c in order)
                {
                    var caseBody = (c == merge || _emitted.Contains(c) || childStop.Contains(c))
                        ? GotoSeq(c) : EmitSeq(c, childStop, loop, depth + 1);
                    stmt.Cases.Add(new SwitchCase { Values = byTarget[c], Body = caseBody });
                }
                seq.Items.Add(stmt);
                return merge != 0 && !_emitted.Contains(merge) ? merge : null;
            }

            case BranchStmt br:
            {
                ulong merge = MergeOf(block.Start);
                var childStop = new HashSet<ulong>(stop); if (merge != 0) childStop.Add(merge);

                Stmt? thenS = BranchRegion(br.IfTrue, merge, childStop, loop, depth);
                Stmt? elseS = BranchRegion(br.IfFalse, merge, childStop, loop, depth);

                Expr cond = br.Cond;
                if (thenS is null && elseS is not null) { cond = Negate(cond); (thenS, elseS) = (elseS, null); }

                seq.Items.Add(new IfStmt { Va = br.Va, Cond = cond, Then = thenS ?? new SeqStmt(), Else = elseS });
                return merge != 0 && !_emitted.Contains(merge) ? merge : null;
            }

            default:
                seq.Items.Add(term);   // AsmStmt or anything unexpected — path ends
                return null;
        }
    }

    /// <summary>A branch arm: null when the target is the merge point (no arm), else its region.</summary>
    private Stmt? BranchRegion(ulong target, ulong merge, HashSet<ulong> childStop, Loop? loop, int depth)
    {
        if (target == merge) return null;
        if (loop is not null && target == loop.Header) return new SeqStmt { Items = { new ContinueStmt() } };
        if (loop is { HasFollow: true } && target == loop.Follow) return new SeqStmt { Items = { new BreakStmt() } };
        if (_emitted.Contains(target)) return GotoSeq(target);
        return EmitSeq(target, childStop, loop, depth + 1);
    }

    private Stmt EmitLoop(Loop lp, HashSet<ulong> stop, Loop? outer, int depth)
    {
        var header = _byStart[lp.Header];
        var (body, term) = Split(header);

        // test-at-top while: header is just a conditional whose two arms are "stay in loop" / "exit".
        if (body.Count == 0 && term is BranchStmt br)
        {
            bool tIn = lp.Body.Contains(br.IfTrue), fIn = lp.Body.Contains(br.IfFalse);
            if (tIn ^ fIn)
            {
                ulong inSucc = tIn ? br.IfTrue : br.IfFalse;
                Expr cond = tIn ? br.Cond : Negate(br.Cond);
                _emitted.Add(lp.Header);
                var bodyStop = new HashSet<ulong>(stop) { lp.Header };
                if (lp.HasFollow) bodyStop.Add(lp.Follow);
                var inner = EmitSeq(inSucc, bodyStop, lp, depth + 1);
                return new WhileStmt { Va = br.Va, Cond = cond, Body = inner };
            }
        }

        // general loop: while (true) { ... } with break/continue from the edges.
        _emitted.Add(lp.Header);
        var seq = new SeqStmt();
        seq.Items.Add(new LabelStmt { Target = lp.Header });
        foreach (var st in body) seq.Items.Add(st);
        var loopStop = new HashSet<ulong>(stop) { lp.Header };
        if (lp.HasFollow) loopStop.Add(lp.Follow);
        var next = EmitTerminator(seq, header, term, loopStop, lp, depth);
        if (next is ulong nb) { var tail = EmitSeq(nb, loopStop, lp, depth + 1); foreach (var st in tail.Items) seq.Items.Add(st); }
        return new WhileStmt { Cond = new Const(1, 1), Body = seq };   // while (true)
    }

    /// <summary>Emit break/continue/goto for a straight-line edge; true if the edge ended the path.</summary>
    private bool FollowEdge(SeqStmt seq, ulong target, Loop? loop)
    {
        if (loop is not null && target == loop.Header) { seq.Items.Add(new ContinueStmt()); return true; }
        if (loop is { HasFollow: true } && target == loop.Follow) { seq.Items.Add(new BreakStmt()); return true; }
        if (_emitted.Contains(target)) { seq.Items.Add(new GotoStmt { Target = target }); _labelNeeded.Add(target); return true; }
        return false;   // caller continues straight-line into target
    }

    private SeqStmt GotoSeq(ulong target) { _labelNeeded.Add(target); return new SeqStmt { Items = { new GotoStmt { Target = target } } }; }

    private ulong MergeOf(ulong b)
    {
        if (_ipdom.TryGetValue(b, out var m) && m != Exit && m != b && _byStart.ContainsKey(m)) return m;
        return 0;
    }

    private ulong? FallThrough(LiftedBlock b)
    {
        foreach (var e in b.Out) if (e.Kind == EdgeKind.FallThrough && _byStart.ContainsKey(e.ToBlockStart)) return e.ToBlockStart;
        foreach (var e in b.Out) if (_byStart.ContainsKey(e.ToBlockStart)) return e.ToBlockStart;
        return null;
    }

    private static (List<Stmt> Body, Stmt? Term) Split(LiftedBlock b)
    {
        if (b.Stmts.Count == 0) return ([], null);
        var last = b.Stmts[^1];
        if (last is BranchStmt or GotoStmt or ReturnStmt or SwitchTermStmt)
            return (b.Stmts.Take(b.Stmts.Count - 1).ToList(), last);
        return (b.Stmts.ToList(), null);
    }

    private static Expr Negate(Expr cond) => cond switch
    {
        CmpExpr c => new CmpExpr(NegateOp(c.Op), c.L, c.R),
        _ => new CmpExpr(CmpOp.Eq, cond, new Const(0, 1)),
    };

    private static CmpOp NegateOp(CmpOp op) => op switch
    {
        CmpOp.Eq => CmpOp.Ne, CmpOp.Ne => CmpOp.Eq,
        CmpOp.ULt => CmpOp.UGe, CmpOp.UGe => CmpOp.ULt, CmpOp.ULe => CmpOp.UGt, CmpOp.UGt => CmpOp.ULe,
        CmpOp.SLt => CmpOp.SGe, CmpOp.SGe => CmpOp.SLt, CmpOp.SLe => CmpOp.SGt, CmpOp.SGt => CmpOp.SLe,
        _ => op,
    };
}

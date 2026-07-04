using DisasmStudio.Core.Formats;

namespace DisasmStudio.Core.IL;

/// <summary>
/// Raises Low IL to Medium IL. Three things make the difference visible: constant stack slots
/// (<c>[rbp-0x10]</c>) become named locals/arguments; prologue/epilogue and stack-pointer bookkeeping
/// is elided; expressions are forward-substituted and constant-folded, and assignments whose result
/// is never read are dropped (dead-store elimination via a backward liveness pass over the CFG). Call
/// arguments are recovered from the register values reaching the call. The result is a new
/// <see cref="LiftedFunction"/> — the Low IL form is left untouched so both can be shown.
/// All architecture-specific register roles / ABI come from the injected <see cref="ArchModel"/>.
/// </summary>
public sealed class MediumLifter
{
    private readonly record struct Loc(RegId Reg, Variable? Var);

    private readonly ArchModel _model;
    private readonly bool _is64;

    private MediumLifter(ArchModel model, bool is64) { _model = model; _is64 = is64; }

    public static LiftedFunction Transform(LiftedFunction low, IBinaryImage image, ArchModel model) =>
        new MediumLifter(model, image.Bitness == 64).Run(low);

    private LiftedFunction Run(LiftedFunction low)
    {
        var slots = new Dictionary<(RegId Base, long Disp), Variable>();

        // 1+2: drop frame bookkeeping, then map constant stack slots to variables.
        var blocks = new List<LiftedBlock>();
        foreach (var lb in low.Blocks)
        {
            var nb = new LiftedBlock { Start = lb.Start, End = lb.End, Out = lb.Out };
            foreach (var s in lb.Stmts)
            {
                if (s is AssignStmt fa && IsFrameBookkeeping(fa)) continue;
                nb.Stmts.Add(MapSlots(s, slots));
            }
            blocks.Add(nb);
        }

        // 3: per-block forward substitution / folding + call-argument recovery.
        foreach (var b in blocks)
        {
            var p = Propagate(b.Stmts);
            b.Stmts.Clear();
            b.Stmts.AddRange(p);
        }

        // 4: dead-store elimination, guided by CFG liveness.
        var byStart = blocks.ToDictionary(b => b.Start);
        var liveOut = ComputeLiveOut(blocks, byStart);
        foreach (var b in blocks)
        {
            var kept = Dce(b.Stmts, liveOut[b.Start]);
            b.Stmts.Clear();
            b.Stmts.AddRange(kept);
        }

        var mid = new LiftedFunction { Va = low.Va, Name = low.Name, Blocks = blocks };
        foreach (var b in blocks) mid.ByStart[b.Start] = b;
        mid.Variables.AddRange(slots.Values.OrderBy(v => v.Name, StringComparer.Ordinal));
        return mid;
    }

    // ---- frame bookkeeping ----

    private bool IsFrameBookkeeping(AssignStmt a)
    {
        // stack-pointer adjustments and `mov <framebase>, <sp>`.
        if (a.Dest is RegExpr d)
        {
            var c = _model.Canon(d.Reg);
            if (_model.IsStackPtr(c)) return true;
            if (_model.IsFrameBase(c) && !_model.IsStackPtr(c) && a.Src is RegExpr sr && _model.IsStackPtr(_model.Canon(sr.Reg))) return true;
            // pop of a callee-saved register: `reg = [sp/frame ...]`.
            if (_model.IsCalleeSaved(c) && a.Src is LoadExpr ld && IsFrameRelative(ld.Addr)) return true;
        }
        // push of a callee-saved register: `[sp/frame ...] = reg`.
        if (a.Dest is LoadExpr sd && IsFrameRelative(sd.Addr) && a.Src is RegExpr sv && _model.IsCalleeSaved(_model.Canon(sv.Reg)))
            return true;
        return false;
    }

    private bool IsFrameRelative(Expr addr) => TryMatchSlot(addr, out _, out _);

    // ---- stack-slot → variable mapping ----

    private Stmt MapSlots(Stmt s, Dictionary<(RegId, long), Variable> slots)
    {
        switch (s)
        {
            case AssignStmt a:
                return new AssignStmt { Va = a.Va, Dest = MapExpr(a.Dest, slots, dest: true), Src = MapExpr(a.Src, slots) };
            case BranchStmt b:
                return new BranchStmt { Va = b.Va, Cond = MapExpr(b.Cond, slots), IfTrue = b.IfTrue, IfFalse = b.IfFalse };
            case SwitchTermStmt sw:
                return new SwitchTermStmt { Va = sw.Va, Value = MapExpr(sw.Value, slots), Cases = sw.Cases };
            case ReturnStmt r:
                return new ReturnStmt { Va = r.Va, Value = r.Value is null ? null : MapExpr(r.Value, slots) };
            case CallStmt cs:
                return new CallStmt { Va = cs.Va, Call = (CallExpr)MapExpr(cs.Call, slots) };
            default:
                return s;   // Goto / Asm / Nop carry through
        }
    }

    private Expr MapExpr(Expr e, Dictionary<(RegId, long), Variable> slots, bool dest = false)
    {
        switch (e)
        {
            case LoadExpr ld:
                if (TryMatchSlot(ld.Addr, out var bas, out var disp))
                    return new VarExpr(SlotVar(slots, bas, disp, ld.Width));
                return new LoadExpr(MapExpr(ld.Addr, slots), ld.Width);
            case BinExpr b:
                return new BinExpr(b.Op, MapExpr(b.L, slots), MapExpr(b.R, slots), b.Width);
            case UnaryExpr u:
                return new UnaryExpr(u.Op, MapExpr(u.E, slots), u.Width);
            case CmpExpr c:
                return new CmpExpr(c.Op, MapExpr(c.L, slots), MapExpr(c.R, slots));
            case TernaryExpr t:
                return new TernaryExpr(MapExpr(t.Cond, slots), MapExpr(t.T, slots), MapExpr(t.F, slots));
            case CallExpr call:
                return new CallExpr(MapExpr(call.Target, slots), call.Args.Select(a => MapExpr(a, slots)).ToList(), call.Name);
            default:
                return e;
        }
    }

    private Variable SlotVar(Dictionary<(RegId, long), Variable> slots, RegId bas, long disp, int width)
    {
        var key = (bas, disp);
        if (slots.TryGetValue(key, out var v)) { if (v.Size == 0 && width > 0) v.Size = width; return v; }
        bool arg = _model.IsArgSlot(bas, disp);
        string baseName = arg ? $"arg_{disp:X}" : $"var_{Math.Abs(disp):X}";
        // Distinct slots can map to the same base name (e.g. [rbp-0x20] and [rsp+0x20]); keep them unique
        // so declarations don't collide.
        string name = baseName;
        for (int suffix = 2; slots.Values.Any(e => e.Name == name); suffix++) name = $"{baseName}_{suffix}";
        v = new Variable { Name = name, Size = width, Class = arg ? VarClass.Arg : VarClass.Local };
        slots[key] = v;
        return v;
    }

    private bool TryMatchSlot(Expr addr, out RegId bas, out long disp)
    {
        bas = RegId.None; disp = 0;
        if (addr is RegExpr r && _model.IsFrameBase(_model.Canon(r.Reg))) { bas = _model.Canon(r.Reg); return true; }
        if (addr is BinExpr { Op: BinOp.Add, L: RegExpr br, R: Const c } && _model.IsFrameBase(_model.Canon(br.Reg)))
        { bas = _model.Canon(br.Reg); disp = c.Value; return true; }
        return false;
    }

    // ---- forward propagation + constant folding + call arg recovery ----

    private List<Stmt> Propagate(List<Stmt> stmts)
    {
        var env = new Dictionary<Loc, Expr>();
        var outp = new List<Stmt>(stmts.Count);

        void InvalidateMemory()
        {
            foreach (var k in env.Where(kv => ContainsLoad(kv.Value)).Select(kv => kv.Key).ToList()) env.Remove(k);
        }

        foreach (var s in stmts)
        {
            switch (s)
            {
                case AssignStmt a:
                {
                    var src = Subst(a.Src, env);
                    // Recover call arguments from the values currently reaching the call.
                    if (src is CallExpr ce) src = WithArgs(ce, env);
                    var dest = a.Dest is LoadExpr ld ? new LoadExpr(Subst(ld.Addr, env), ld.Width) : a.Dest;

                    if (dest is LoadExpr) { InvalidateMemory(); }
                    if (src is CallExpr || ContainsCall(src)) env.Clear();   // a call clobbers registers

                    var na = new AssignStmt { Va = a.Va, Dest = dest, Src = src };
                    outp.Add(na);

                    if (dest is RegExpr or VarExpr)
                    {
                        var loc = LocOf(dest);
                        // Invalidate anything that referenced the old value of this location.
                        foreach (var k in env.Where(kv => Mentions(kv.Value, loc)).Select(kv => kv.Key).ToList()) env.Remove(k);
                        if (!(src is CallExpr) && IsInlinable(src) && NodeCount(src) <= 24) env[loc] = src; else env.Remove(loc);
                    }
                    break;
                }
                case BranchStmt b:
                    outp.Add(new BranchStmt { Va = b.Va, Cond = Subst(b.Cond, env), IfTrue = b.IfTrue, IfFalse = b.IfFalse });
                    break;
                case SwitchTermStmt sw:
                    outp.Add(new SwitchTermStmt { Va = sw.Va, Value = Subst(sw.Value, env), Cases = sw.Cases });
                    break;
                case ReturnStmt r:
                    outp.Add(new ReturnStmt { Va = r.Va, Value = r.Value is null ? null : Subst(r.Value, env) });
                    break;
                case CallStmt cs:
                {
                    var ce = WithArgs((CallExpr)Subst(cs.Call, env), env);
                    env.Clear();
                    outp.Add(new CallStmt { Va = cs.Va, Call = ce });
                    break;
                }
                default:
                    outp.Add(s);
                    break;
            }
        }
        return outp;
    }

    private CallExpr WithArgs(CallExpr ce, Dictionary<Loc, Expr> env)
    {
        var argRegs = _model.ArgRegs;
        if (ce.Args.Count > 0 || argRegs.Count == 0) return ce;
        // Don't stop at the first register we couldn't recover: a real call often sets rcx and r8 but loads
        // rdx from memory we didn't track. Collect all slots, then trim trailing unknowns and fill interior
        // gaps with the register name, so e.g. f(a, rdx, c) is recovered instead of truncating to f(a).
        var slots = new List<Expr?>(argRegs.Count);
        foreach (var r in argRegs)
            slots.Add(env.TryGetValue(new Loc(_model.Canon(r), null), out var v) ? v : null);
        int last = slots.FindLastIndex(a => a is not null);
        if (last < 0) return ce;
        var args = new List<Expr>(last + 1);
        for (int i = 0; i <= last; i++) args.Add(slots[i] ?? new RegExpr(argRegs[i]));
        return ce with { Args = args };
    }

    private Expr Subst(Expr e, Dictionary<Loc, Expr> env)
    {
        switch (e)
        {
            case RegExpr or VarExpr:
                return env.TryGetValue(LocOf(e), out var v) ? v : e;
            case LoadExpr ld:
                return new LoadExpr(Subst(ld.Addr, env), ld.Width);
            case UnaryExpr u:
                return Fold(new UnaryExpr(u.Op, Subst(u.E, env), u.Width));
            case BinExpr b:
                return Fold(new BinExpr(b.Op, Subst(b.L, env), Subst(b.R, env), b.Width));
            case CmpExpr c:
                return new CmpExpr(c.Op, Subst(c.L, env), Subst(c.R, env));
            case TernaryExpr t:
                return new TernaryExpr(Subst(t.Cond, env), Subst(t.T, env), Subst(t.F, env));
            case CallExpr call:
                return call with { Args = call.Args.Select(a => Subst(a, env)).ToList() };
            default:
                return e;
        }
    }

    private static Expr Fold(Expr e)
    {
        if (e is BinExpr { L: Const l, R: Const r } b)
        {
            long x = l.Value, y = r.Value;
            long? z = b.Op switch
            {
                BinOp.Add => x + y, BinOp.Sub => x - y, BinOp.Mul or BinOp.UMul => x * y,
                BinOp.And => x & y, BinOp.Or => x | y, BinOp.Xor => x ^ y,
                BinOp.Shl => x << (int)(y & 63), BinOp.Shr => (long)((ulong)x >> (int)(y & 63)),
                BinOp.Sar => x >> (int)(y & 63),
                _ => null,
            };
            if (z is long zv) return new Const(zv, b.Width);
        }
        // x + 0, x - 0, x | 0  → x
        if (e is BinExpr { R: Const { Value: 0 }, Op: BinOp.Add or BinOp.Sub or BinOp.Or or BinOp.Xor } b2) return b2.L;
        return e;
    }

    // ---- dead-store elimination ----

    private List<Stmt> Dce(List<Stmt> stmts, HashSet<Loc> liveOut)
    {
        var live = new HashSet<Loc>(liveOut);
        var rev = new List<Stmt>(stmts.Count);
        for (int i = stmts.Count - 1; i >= 0; i--)
        {
            var s = stmts[i];
            if (s is AssignStmt a && a.Dest is RegExpr or VarExpr && !ContainsCall(a.Src) && a.Dest is not LoadExpr)
            {
                // Only a full-width write that is never read again is safe to drop. A partial write
                // (al/ax) preserves the rest of the register, so it is never dead on its own.
                if (!live.Contains(LocOf(a.Dest)) && _model.IsFullDef(a.Dest)) continue;
            }
            // A dead `reg = call(...)` keeps the call but discards the result.
            if (s is AssignStmt ca && ca.Dest is RegExpr && ca.Src is CallExpr ce
                && _model.IsFullDef(ca.Dest) && !live.Contains(LocOf(ca.Dest)))
            {
                rev.Add(new CallStmt { Va = ca.Va, Call = ce });
                AddReads(ce, live);
                continue;
            }

            // Update liveness: a full write kills the location; a partial write reads (and preserves) it.
            if (s is AssignStmt da && da.Dest is RegExpr or VarExpr && da.Dest is not LoadExpr)
            {
                if (_model.IsFullDef(da.Dest)) live.Remove(LocOf(da.Dest)); else live.Add(LocOf(da.Dest));
                AddReads(da.Src, live);
            }
            else
            {
                AddStmtReads(s, live);
            }
            rev.Add(s);
        }
        rev.Reverse();
        // tidy: drop self-assignments and nops left behind.
        return rev.Where(s => s is not NopStmt && !(s is AssignStmt sa && sa.Dest.Equals(sa.Src))).ToList();
    }

    private Dictionary<ulong, HashSet<Loc>> ComputeLiveOut(List<LiftedBlock> blocks, Dictionary<ulong, LiftedBlock> byStart)
    {
        var use = new Dictionary<ulong, HashSet<Loc>>();
        var def = new Dictionary<ulong, HashSet<Loc>>();
        foreach (var b in blocks)
        {
            var u = new HashSet<Loc>(); var d = new HashSet<Loc>();
            foreach (var s in b.Stmts)
            {
                // uses are reads not already defined earlier in the block
                var reads = new HashSet<Loc>();
                AddStmtReads(s, reads);
                foreach (var r in reads) if (!d.Contains(r)) u.Add(r);
                if (s is AssignStmt a && a.Dest is RegExpr or VarExpr && a.Dest is not LoadExpr)
                {
                    var loc = LocOf(a.Dest);
                    if (_model.IsFullDef(a.Dest)) d.Add(loc);
                    else if (!d.Contains(loc)) u.Add(loc);   // partial write uses the old value
                }
            }
            use[b.Start] = u; def[b.Start] = d;
        }

        var liveIn = blocks.ToDictionary(b => b.Start, _ => new HashSet<Loc>());
        var liveOut = blocks.ToDictionary(b => b.Start, _ => new HashSet<Loc>());
        bool changed = true;
        int guard = 0;
        while (changed && guard++ < 1000)
        {
            changed = false;
            for (int i = blocks.Count - 1; i >= 0; i--)
            {
                var b = blocks[i];
                var outSet = new HashSet<Loc>();
                foreach (var edge in b.Out)
                    if (liveIn.TryGetValue(edge.ToBlockStart, out var li)) outSet.UnionWith(li);
                var inSet = new HashSet<Loc>(use[b.Start]);
                foreach (var l in outSet) if (!def[b.Start].Contains(l)) inSet.Add(l);
                if (!liveOut[b.Start].SetEquals(outSet)) { liveOut[b.Start] = outSet; changed = true; }
                if (!liveIn[b.Start].SetEquals(inSet)) { liveIn[b.Start] = inSet; changed = true; }
            }
        }
        return liveOut;
    }

    // ---- expression utilities ----

    private Loc LocOf(Expr e) => e switch
    {
        RegExpr r => new Loc(_model.Canon(r.Reg), null),
        VarExpr v => new Loc(RegId.None, v.Var),
        _ => new Loc(RegId.None, null),
    };

    private void AddStmtReads(Stmt s, HashSet<Loc> set)
    {
        switch (s)
        {
            case AssignStmt a:
                if (a.Dest is LoadExpr ld) AddReads(ld.Addr, set);   // store: address is read
                AddReads(a.Src, set);
                break;
            case BranchStmt b: AddReads(b.Cond, set); break;
            case SwitchTermStmt sw: AddReads(sw.Value, set); break;
            case ReturnStmt r: if (r.Value is not null) AddReads(r.Value, set); break;
            case CallStmt cs: AddReads(cs.Call, set); break;
        }
    }

    private void AddReads(Expr e, HashSet<Loc> set)
    {
        switch (e)
        {
            case RegExpr r: set.Add(new Loc(_model.Canon(r.Reg), null)); break;
            case VarExpr v: set.Add(new Loc(RegId.None, v.Var)); break;
            case LoadExpr ld: AddReads(ld.Addr, set); break;
            case UnaryExpr u: AddReads(u.E, set); break;
            case BinExpr b: AddReads(b.L, set); AddReads(b.R, set); break;
            case CmpExpr c: AddReads(c.L, set); AddReads(c.R, set); break;
            case TernaryExpr t: AddReads(t.Cond, set); AddReads(t.T, set); AddReads(t.F, set); break;
            case CallExpr call: AddReads(call.Target, set); foreach (var a in call.Args) AddReads(a, set); break;
        }
    }

    private bool Mentions(Expr e, Loc loc)
    {
        var set = new HashSet<Loc>();
        AddReads(e, set);
        return set.Contains(loc);
    }

    private static bool ContainsCall(Expr e) => e switch
    {
        CallExpr => true,
        LoadExpr ld => ContainsCall(ld.Addr),
        UnaryExpr u => ContainsCall(u.E),
        BinExpr b => ContainsCall(b.L) || ContainsCall(b.R),
        CmpExpr c => ContainsCall(c.L) || ContainsCall(c.R),
        TernaryExpr t => ContainsCall(t.Cond) || ContainsCall(t.T) || ContainsCall(t.F),
        _ => false,
    };

    private static bool ContainsLoad(Expr e) => e switch
    {
        LoadExpr => true,
        UnaryExpr u => ContainsLoad(u.E),
        BinExpr b => ContainsLoad(b.L) || ContainsLoad(b.R),
        CmpExpr c => ContainsLoad(c.L) || ContainsLoad(c.R),
        TernaryExpr t => ContainsLoad(t.Cond) || ContainsLoad(t.T) || ContainsLoad(t.F),
        CallExpr call => call.Args.Any(ContainsLoad) || ContainsLoad(call.Target),
        _ => false,
    };

    private static bool IsInlinable(Expr e) => e switch
    {
        Const or SymExpr or RegExpr or VarExpr or RawExpr => true,
        LoadExpr ld => IsInlinable(ld.Addr),
        UnaryExpr u => IsInlinable(u.E),
        BinExpr b => IsInlinable(b.L) && IsInlinable(b.R),
        CmpExpr c => IsInlinable(c.L) && IsInlinable(c.R),
        _ => false,
    };

    private static int NodeCount(Expr e) => e switch
    {
        LoadExpr ld => 1 + NodeCount(ld.Addr),
        UnaryExpr u => 1 + NodeCount(u.E),
        BinExpr b => 1 + NodeCount(b.L) + NodeCount(b.R),
        CmpExpr c => 1 + NodeCount(c.L) + NodeCount(c.R),
        TernaryExpr t => 1 + NodeCount(t.Cond) + NodeCount(t.T) + NodeCount(t.F),
        _ => 1,
    };
}

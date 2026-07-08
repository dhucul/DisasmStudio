using DisasmStudio.Core.Analysis;
using DisasmStudio.Core.Formats;

namespace DisasmStudio.Core.IL;

/// <summary>Why an emulation run stopped.</summary>
public enum EmuStatus { Returned, UnknownBranch, Budget, HaltedAsm, NoCode }

/// <summary>A concrete value an instruction computed under emulation (an obfuscated constant resolved).</summary>
public readonly record struct ResolvedValue(ulong Va, string Reg, long Value, int Width);

/// <summary>A branch whose condition was constant under emulation (a folded / opaque predicate). <see cref="Taken"/>
/// is true when the taken (IfTrue) edge is the one always followed.</summary>
public readonly record struct BranchFold(ulong Va, bool Taken);

/// <summary>Everything an <see cref="IlEmulator"/> run observed.</summary>
public sealed class EmulationResult
{
    /// <summary>Instruction VA → the concrete value it computed into a register (only non-trivial computations).</summary>
    public Dictionary<ulong, ResolvedValue> Values { get; } = [];
    /// <summary>Writes to mapped (image) addresses — decrypted/patched bytes, address → byte.</summary>
    public SortedDictionary<ulong, byte> MemoryWrites { get; } = [];
    /// <summary>Branches whose condition folded to a constant along the emulated path.</summary>
    public List<BranchFold> Branches { get; } = [];
    public EmuStatus Status { get; set; }
    public ulong StoppedAt { get; set; }
    public int Steps { get; set; }
}

/// <summary>Knobs for one emulation run.</summary>
public sealed class EmulationOptions
{
    /// <summary>Hard cap on executed statements — stops runaway loops (a constant-bounded decrypt loop runs to
    /// completion well under this).</summary>
    public int StepBudget { get; init; } = 2_000_000;
    /// <summary>Where the synthetic stack pointer starts (unmapped, so stack spills aren't reported as image writes).</summary>
    public ulong StackBase { get; init; } = 0x0000_7FFC_0000_0000;
}

/// <summary>
/// A tree-walking interpreter over the decompiler's Low IL. It runs a lifted function from its entry with
/// unknown inputs, propagating <b>concrete</b> values through registers and memory: reads of the image's own
/// bytes are known, arithmetic on known values stays known, and anything derived from an uninitialised input
/// is <i>unknown</i> and simply doesn't produce a result. That is exactly what resolves obfuscated constants
/// (a chain of xor/add/rol on literals), decrypts constant-keyed buffers (a constant-bounded loop over image
/// bytes → the plaintext lands in <see cref="EmulationResult.MemoryWrites"/>), and folds constant ("opaque")
/// predicates (a branch whose condition is known). Nothing in the target executes — this is pure interpretation
/// of our IR against a copy of the bytes, bounded by a step budget.
/// </summary>
public sealed class IlEmulator
{
    private readonly IBinaryImage _image;
    private readonly ArchModel _model;
    private readonly EmulationOptions _opts;

    private readonly Dictionary<RegId, long> _regKnown = [];   // canonical reg → value (present ⇒ known)
    private readonly Dictionary<ulong, byte> _mem = [];        // written bytes (overlay over the image)
    private readonly EmulationResult _result = new();

    // x86-64 volatile (caller-saved) registers a call clobbers, by canonical name — conservative for other arches.
    private static readonly HashSet<string> Volatile = ["rax", "rcx", "rdx", "r8", "r9", "r10", "r11"];

    private IlEmulator(IBinaryImage image, ArchModel model, EmulationOptions opts)
    {
        _image = image; _model = model; _opts = opts;
    }

    public static EmulationResult Run(LiftedFunction lf, IBinaryImage image, EmulationOptions? opts = null)
    {
        var em = new IlEmulator(image, ArchModel.For(image), opts ?? new EmulationOptions());
        em.Execute(lf);
        return em._result;
    }

    private void Execute(LiftedFunction lf)
    {
        if (lf.Blocks.Count == 0) { _result.Status = EmuStatus.NoCode; return; }
        // Seed the stack pointer so push/pop/[rsp+…] spills work (into the unmapped scratch overlay).
        _regKnown[_model.Canon(SpReg())] = (long)_opts.StackBase;

        var block = lf.ByStart.TryGetValue(lf.Va, out var entry) ? entry : lf.Blocks[0];
        int steps = 0;
        while (true)
        {
            ulong? next = null;
            foreach (var st in block.Stmts)
            {
                if (++steps > _opts.StepBudget) { Finish(EmuStatus.Budget, st.Va, steps); return; }
                switch (st)
                {
                    case AssignStmt a: ExecAssign(a); break;
                    case CallStmt: ClobberVolatiles(); break;
                    case NopStmt: break;
                    case ReturnStmt: Finish(EmuStatus.Returned, st.Va, steps); return;
                    case AsmStmt: Finish(EmuStatus.HaltedAsm, st.Va, steps); return;   // unmodelled op — state is now unreliable
                    case GotoStmt g: next = g.Target; break;
                    case BranchStmt b:
                    {
                        var c = Eval(b.Cond);
                        if (!c.Known) { Finish(EmuStatus.UnknownBranch, st.Va, steps); return; }
                        bool taken = c.V != 0;
                        _result.Branches.Add(new BranchFold(st.Va, taken));
                        next = taken ? b.IfTrue : b.IfFalse;
                        break;
                    }
                    case SwitchTermStmt sw:
                    {
                        var v = Eval(sw.Value);
                        if (!v.Known || v.V < 0 || v.V >= sw.Cases.Count) { Finish(EmuStatus.UnknownBranch, st.Va, steps); return; }
                        next = sw.Cases[(int)v.V];
                        break;
                    }
                }
                if (next is not null) break;   // a terminator set the next block
            }

            // No terminator statement set a target → this block falls through to its CFG successor.
            if (next is null)
            {
                if (FallThrough(block) is ulong ft) next = ft;
                else { Finish(EmuStatus.Returned, block.Stmts.Count > 0 ? block.Stmts[^1].Va : lf.Va, steps); return; }
            }
            if (!lf.ByStart.TryGetValue(next.Value, out block!)) { Finish(EmuStatus.Returned, next.Value, steps); return; }   // edge leaves the function
        }
    }

    /// <summary>The fall-through successor of a block with no terminator statement (the FallThrough edge, or the
    /// sole out-edge), or null when the block has no successor.</summary>
    private static ulong? FallThrough(LiftedBlock block)
    {
        foreach (var e in block.Out) if (e.Kind == EdgeKind.FallThrough) return e.ToBlockStart;
        return block.Out.Count == 1 ? block.Out[0].ToBlockStart : null;
    }

    private void Finish(EmuStatus status, ulong at, int steps)
    {
        _result.Status = status;
        _result.StoppedAt = at;
        _result.Steps = steps;
        foreach (var (addr, b) in _mem)
            if (_image.IsMappedVa(addr)) _result.MemoryWrites[addr] = b;   // only report writes to real image addresses
    }

    private void ExecAssign(AssignStmt a)
    {
        // A call result (and its clobber of volatile registers) — the Lifter models `call` as rax = call(...).
        if (a.Src is CallExpr) { ClobberVolatiles(); WriteDest(a.Dest, Val.Unknown); return; }

        var v = Eval(a.Src);
        WriteDest(a.Dest, v);

        // Record a genuinely-computed constant (skip trivial moves of a literal/symbol/register, and skip
        // stack-pointer bookkeeping like `sub rsp, N` which is just prologue noise, not a resolved value).
        if (v.Known && a.Dest is RegExpr re && a.Src is BinExpr or UnaryExpr or LoadExpr or TernaryExpr
            && !_model.IsStackPtr(_model.Canon(re.Reg)))
            _result.Values[a.Va] = new ResolvedValue(a.Va, re.Reg.Name, Mask(v.V, re.Reg.Width), re.Reg.Width);
    }

    private void WriteDest(Expr dest, Val v)
    {
        switch (dest)
        {
            case RegExpr re:
            {
                var canon = _model.Canon(re.Reg);
                if (!v.Known) { _regKnown.Remove(canon); break; }
                if (re.Reg.Width >= 4) _regKnown[canon] = Mask(v.V, re.Reg.Width);       // 32-bit write zero-extends
                else if (_regKnown.TryGetValue(canon, out var old))                       // sub-register merge into a known parent
                    _regKnown[canon] = MergeLow(old, v.V, re.Reg.Width);
                else _regKnown.Remove(canon);                                             // partial write over an unknown parent
                break;
            }
            case LoadExpr store:   // *(addr) = value  → a memory store
            {
                var addr = Eval(store.Addr);
                if (addr.Known) WriteMem((ulong)addr.V, store.Width, v);
                break;
            }
        }
    }

    // ---- expression evaluation ----

    private readonly record struct Val(long V, bool Known)
    {
        public static readonly Val Unknown = new(0, false);
        public static Val K(long v) => new(v, true);
    }

    private Val Eval(Expr e)
    {
        switch (e)
        {
            case Const c: return Val.K(c.Value);
            case SymExpr s: return Val.K((long)s.Va);
            case RegExpr r:
            {
                if (_regKnown.TryGetValue(_model.Canon(r.Reg), out var pv)) return Val.K(Mask(pv, r.Reg.Width));
                return Val.Unknown;
            }
            case LoadExpr ld:
            {
                var a = Eval(ld.Addr);
                return a.Known ? ReadMem((ulong)a.V, ld.Width) : Val.Unknown;
            }
            case UnaryExpr u:
            {
                var x = Eval(u.E);
                if (!x.Known) return Val.Unknown;
                long r = u.Op == UnOp.Neg ? -x.V : ~x.V;
                return Val.K(Mask(r, u.Width));
            }
            case BinExpr b: return EvalBin(b);
            case CmpExpr c: return EvalCmp(c);
            case TernaryExpr t:
            {
                var cond = Eval(t.Cond);
                if (!cond.Known) return Val.Unknown;
                return Eval(cond.V != 0 ? t.T : t.F);
            }
            default: return Val.Unknown;   // RawExpr / CallExpr / VarExpr (not present in Low IL) → unknown
        }
    }

    private Val EvalBin(BinExpr b)
    {
        var l = Eval(b.L); var r = Eval(b.R);
        if (!l.Known || !r.Known) return Val.Unknown;
        int w = b.Width <= 0 ? 8 : b.Width;
        long lv = l.V, rv = r.V;
        long res;
        switch (b.Op)
        {
            case BinOp.Add: res = lv + rv; break;
            case BinOp.Sub: res = lv - rv; break;
            case BinOp.Mul: case BinOp.UMul: res = lv * rv; break;
            case BinOp.And: res = lv & rv; break;
            case BinOp.Or: res = lv | rv; break;
            case BinOp.Xor: res = lv ^ rv; break;
            case BinOp.Shl: res = lv << (int)(rv & (w * 8 - 1)); break;
            case BinOp.Shr: res = (long)(Zext(lv, w) >> (int)(rv & (w * 8 - 1))); break;   // logical
            case BinOp.Sar: res = Sext(lv, w) >> (int)(rv & (w * 8 - 1)); break;           // arithmetic
            case BinOp.Rol: { int s = (int)(rv & (w * 8 - 1)); ulong u = Zext(lv, w); int bits = w * 8; res = (long)(bits == 64 ? (u << s) | (u >> (64 - s == 64 ? 0 : 64 - s)) : ((u << s) | (u >> (bits - s))) & ((1UL << bits) - 1)); break; }
            case BinOp.Ror: { int s = (int)(rv & (w * 8 - 1)); ulong u = Zext(lv, w); int bits = w * 8; res = (long)(bits == 64 ? (u >> s) | (u << (64 - s == 64 ? 0 : 64 - s)) : ((u >> s) | (u << (bits - s))) & ((1UL << bits) - 1)); break; }
            case BinOp.UDiv: { ulong d = Zext(rv, w); if (d == 0) return Val.Unknown; res = (long)(Zext(lv, w) / d); break; }
            case BinOp.UMod: { ulong d = Zext(rv, w); if (d == 0) return Val.Unknown; res = (long)(Zext(lv, w) % d); break; }
            case BinOp.SDiv: { long d = Sext(rv, w); if (d == 0) return Val.Unknown; res = Sext(lv, w) / d; break; }
            case BinOp.SMod: { long d = Sext(rv, w); if (d == 0) return Val.Unknown; res = Sext(lv, w) % d; break; }
            default: return Val.Unknown;
        }
        return Val.K(Mask(res, w));
    }

    private Val EvalCmp(CmpExpr c)
    {
        var l = Eval(c.L); var r = Eval(c.R);
        if (!l.Known || !r.Known) return Val.Unknown;
        int w = Math.Max(1, Math.Max(c.L.Size, c.R.Size));
        bool res = c.Op switch
        {
            CmpOp.Eq => Zext(l.V, w) == Zext(r.V, w),
            CmpOp.Ne => Zext(l.V, w) != Zext(r.V, w),
            CmpOp.ULt => Zext(l.V, w) < Zext(r.V, w),
            CmpOp.ULe => Zext(l.V, w) <= Zext(r.V, w),
            CmpOp.UGt => Zext(l.V, w) > Zext(r.V, w),
            CmpOp.UGe => Zext(l.V, w) >= Zext(r.V, w),
            CmpOp.SLt => Sext(l.V, w) < Sext(r.V, w),
            CmpOp.SLe => Sext(l.V, w) <= Sext(r.V, w),
            CmpOp.SGt => Sext(l.V, w) > Sext(r.V, w),
            CmpOp.SGe => Sext(l.V, w) >= Sext(r.V, w),
            _ => false,
        };
        return Val.K(res ? 1 : 0);
    }

    // ---- memory ----

    private Val ReadMem(ulong addr, int width)
    {
        if (width is <= 0 or > 8) return Val.Unknown;
        long v = 0;
        for (int i = 0; i < width; i++)
        {
            if (!TryReadByte(addr + (ulong)i, out byte b)) return Val.Unknown;
            v |= (long)b << (i * 8);
        }
        return Val.K(v);
    }

    private bool TryReadByte(ulong va, out byte b)
    {
        if (_mem.TryGetValue(va, out b)) return true;
        if (_image.IsMappedVa(va))
        {
            var got = _image.ReadBytesAtVa(va, 1);
            if (got.Length == 1) { b = got[0]; return true; }
        }
        b = 0;
        return false;
    }

    private void WriteMem(ulong addr, int width, Val v)
    {
        if (width is <= 0 or > 8) return;
        if (!v.Known) { for (int i = 0; i < width; i++) _mem.Remove(addr + (ulong)i); return; }
        for (int i = 0; i < width; i++) _mem[addr + (ulong)i] = (byte)(v.V >> (i * 8));
    }

    // ---- helpers ----

    private void ClobberVolatiles()
    {
        // Remove volatile registers (a call may have changed them); by canonical name so sub-regs go too.
        var drop = _regKnown.Keys.Where(k => Volatile.Contains(k.Name)).ToList();
        foreach (var k in drop) _regKnown.Remove(k);
    }

    private RegId SpReg()
    {
        // The stack pointer's canonical RegId: probe the model's frame/stack predicate over the arg-independent set.
        // x86: rsp; ARM64: sp; ARM32: sp. Build it from the return-reg family is wrong, so name it directly.
        return _image.IsArm
            ? new RegId("sp", _image.Bitness == 64 ? 8 : 4)
            : X86Model.FromIced(_image.Bitness == 64 ? Iced.Intel.Register.RSP : Iced.Intel.Register.ESP);
    }

    /// <summary>Mask a value to the low <paramref name="w"/> bytes (result carries only those bits, zero-extended).</summary>
    private static long Mask(long v, int w) => w is <= 0 or >= 8 ? v : v & ((1L << (w * 8)) - 1);

    /// <summary>Zero-extend the low <paramref name="w"/> bytes of <paramref name="v"/> to a 64-bit unsigned value.</summary>
    private static ulong Zext(long v, int w) => w is <= 0 or >= 8 ? (ulong)v : (ulong)v & ((1UL << (w * 8)) - 1);

    /// <summary>Sign-extend the low <paramref name="w"/> bytes of <paramref name="v"/> to 64 bits.</summary>
    private static long Sext(long v, int w)
    {
        if (w is <= 0 or >= 8) return v;
        int bits = w * 8;
        long m = 1L << (bits - 1);
        long masked = v & ((1L << bits) - 1);
        return (masked ^ m) - m;
    }

    /// <summary>Merge the low <paramref name="w"/> bytes of <paramref name="lo"/> into the known parent <paramref name="parent"/>.</summary>
    private static long MergeLow(long parent, long lo, int w)
    {
        long m = (1L << (w * 8)) - 1;
        return (parent & ~m) | (lo & m);
    }
}

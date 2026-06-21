using DisasmStudio.Core.Analysis;
using DisasmStudio.Core.Disasm;
using DisasmStudio.Core.Formats;
using Iced.Intel;

namespace DisasmStudio.Core.IL;

/// <summary>
/// Lifts a function's decoded instructions to Low IL — a per-instruction lowering over physical
/// registers, memory and a deferred flag model. Each x86/x64 instruction in the covered integer +
/// control-flow subset becomes one or more IR statements; anything outside the subset is carried
/// through verbatim as an <see cref="AsmStmt"/> so output is always produced and always traceable
/// to a VA. Flags are not modelled bit-by-bit: a flag-setting instruction records a deferred
/// "definition" (compare / test / result-vs-zero) that the following <c>jcc</c>/<c>setcc</c>/
/// <c>cmovcc</c> turns into a real comparison expression — the standard decompiler trick.
/// </summary>
public sealed class Lifter
{
    private enum FlagSource { None, Compare, Test, Result }
    private readonly record struct FlagDef(FlagSource Source, Expr Left, Expr Right);

    private readonly IBinaryImage _image;
    private readonly IReadOnlyDictionary<ulong, string> _names;
    private readonly IReadOnlyDictionary<ulong, ulong[]> _jumpTables;
    private readonly Disassembler _dis;
    private readonly AsmFormatter _fmt;
    private readonly bool _is64;

    private FlagDef _flag;

    public Lifter(IBinaryImage image, IReadOnlyDictionary<ulong, string> names,
        IReadOnlyDictionary<ulong, ulong[]> jumpTables)
    {
        _image = image;
        _names = names;
        _jumpTables = jumpTables;
        _dis = new Disassembler(image);
        _fmt = new AsmFormatter(names);
        _is64 = image.Bitness == 64;
    }

    private Register Sp => _is64 ? Register.RSP : Register.ESP;
    private Register Ax => _is64 ? Register.RAX : Register.EAX;
    private int Ptr => _is64 ? 8 : 4;

    // Width-sized accumulator (al/ax/eax/rax) and data (ah/dx/edx/rdx) registers for one-operand mul/div, so a
    // 32-bit div reads as eax = eax / … instead of rax = rax / ….
    private static Register AxW(int w) => w switch { 1 => Register.AL, 2 => Register.AX, 4 => Register.EAX, _ => Register.RAX };
    private static Register DxW(int w) => w switch { 1 => Register.AH, 2 => Register.DX, 4 => Register.EDX, _ => Register.RDX };

    /// <summary>Lift a function (its CFG must already be built) into Low IL form.</summary>
    public LiftedFunction Lift(Function fn)
    {
        var blocks = new List<LiftedBlock>();
        foreach (var bb in fn.Blocks)
        {
            var lb = new LiftedBlock { Start = bb.Start, End = bb.End, Out = bb.Out };
            _flag = default;   // flags don't carry meaningfully across block boundaries
            foreach (var va in bb.InstrVas)
            {
                if (!_dis.TryDecodeAt(va, out var ins)) continue;
                LiftOne(va, ins, lb.Stmts);
            }
            blocks.Add(lb);
        }

        var lf = new LiftedFunction { Va = fn.EntryVa, Name = fn.Name, Blocks = blocks };
        foreach (var b in blocks) lf.ByStart[b.Start] = b;
        return lf;
    }

    private void LiftOne(ulong va, in Instruction ins, List<Stmt> outp)
    {
        void Emit(Stmt s) { s.Va = va; outp.Add(s); }

        switch (ins.Mnemonic)
        {
            case Mnemonic.Mov or Mnemonic.Movzx or Mnemonic.Movsx or Mnemonic.Movsxd or Mnemonic.Movaps
                or Mnemonic.Movups or Mnemonic.Movdqa or Mnemonic.Movdqu or Mnemonic.Movd or Mnemonic.Movq:
                Emit(new AssignStmt { Dest = Dest(ins), Src = Src1(ins, DestWidth(ins)) });
                break;

            case Mnemonic.Lea:
                Emit(new AssignStmt { Dest = Dest(ins), Src = MemAddr(ins) });
                break;

            case Mnemonic.Push:
                // Store the operand at [sp - Ptr] BEFORE adjusting sp, so `push rsp` pushes the original sp.
                Emit(new AssignStmt { Dest = new LoadExpr(new BinExpr(BinOp.Sub, new RegExpr(Sp), new Const(Ptr, Ptr), Ptr), Ptr), Src = Operand(ins, 0, Ptr) });
                Emit(new AssignStmt { Dest = new RegExpr(Sp), Src = new BinExpr(BinOp.Sub, new RegExpr(Sp), new Const(Ptr, Ptr), Ptr) });
                break;

            case Mnemonic.Pop:
                Emit(new AssignStmt { Dest = Operand(ins, 0, Ptr), Src = new LoadExpr(new RegExpr(Sp), Ptr) });
                // `pop rsp` loads rsp directly — the +Ptr is overridden; only adjust sp when popping another reg.
                if (!(ins.Op0Kind == OpKind.Register && ins.Op0Register == Sp))
                    Emit(new AssignStmt { Dest = new RegExpr(Sp), Src = new BinExpr(BinOp.Add, new RegExpr(Sp), new Const(Ptr, Ptr), Ptr) });
                break;

            case Mnemonic.Add: Arith(BinOp.Add, ins, Emit); break;
            case Mnemonic.Sub: Arith(BinOp.Sub, ins, Emit); break;
            case Mnemonic.Adc: Arith(BinOp.Add, ins, Emit); break;   // carry-in approximated away
            case Mnemonic.Sbb: Arith(BinOp.Sub, ins, Emit); break;
            case Mnemonic.And: Arith(BinOp.And, ins, Emit); break;
            case Mnemonic.Or: Arith(BinOp.Or, ins, Emit); break;
            case Mnemonic.Shl or Mnemonic.Sal: Arith(BinOp.Shl, ins, Emit); break;
            case Mnemonic.Shr: Arith(BinOp.Shr, ins, Emit); break;
            case Mnemonic.Sar: Arith(BinOp.Sar, ins, Emit); break;
            case Mnemonic.Rol: Arith(BinOp.Rol, ins, Emit); break;
            case Mnemonic.Ror: Arith(BinOp.Ror, ins, Emit); break;

            case Mnemonic.Xor:
            {
                var d = Dest(ins);
                int w = DestWidth(ins);
                var s = Src1(ins, w);
                // xor r, r — the canonical zero idiom.
                if (d.Equals(s)) { Emit(new AssignStmt { Dest = d, Src = new Const(0, w) }); _flag = new FlagDef(FlagSource.Result, d, new Const(0, w)); }
                else { Emit(new AssignStmt { Dest = d, Src = new BinExpr(BinOp.Xor, d, s, w) }); _flag = new FlagDef(FlagSource.Result, d, new Const(0, w)); }
                break;
            }

            case Mnemonic.Inc:
            {
                var d = Dest(ins); int w = DestWidth(ins);
                Emit(new AssignStmt { Dest = d, Src = new BinExpr(BinOp.Add, d, new Const(1, w), w) });
                _flag = new FlagDef(FlagSource.Result, d, new Const(0, w));
                break;
            }
            case Mnemonic.Dec:
            {
                var d = Dest(ins); int w = DestWidth(ins);
                Emit(new AssignStmt { Dest = d, Src = new BinExpr(BinOp.Sub, d, new Const(1, w), w) });
                _flag = new FlagDef(FlagSource.Result, d, new Const(0, w));
                break;
            }
            case Mnemonic.Neg:
            {
                var d = Dest(ins); int w = DestWidth(ins);
                Emit(new AssignStmt { Dest = d, Src = new UnaryExpr(UnOp.Neg, d, w) });
                _flag = new FlagDef(FlagSource.Result, d, new Const(0, w));
                break;
            }
            case Mnemonic.Not:
            {
                var d = Dest(ins); int w = DestWidth(ins);
                Emit(new AssignStmt { Dest = d, Src = new UnaryExpr(UnOp.Not, d, w) });   // NOT does not affect flags
                break;
            }

            case Mnemonic.Imul when ins.OpCount == 2:
            {
                var d = Dest(ins); int w = DestWidth(ins);
                Emit(new AssignStmt { Dest = d, Src = new BinExpr(BinOp.Mul, d, Src1(ins, w), w) });
                _flag = new FlagDef(FlagSource.Result, d, new Const(0, w));
                break;
            }
            case Mnemonic.Imul when ins.OpCount == 3:
            {
                var d = Dest(ins); int w = DestWidth(ins);
                Emit(new AssignStmt { Dest = d, Src = new BinExpr(BinOp.Mul, Operand(ins, 1, w), Operand(ins, 2, w), w) });
                _flag = new FlagDef(FlagSource.Result, d, new Const(0, w));
                break;
            }
            case Mnemonic.Imul or Mnemonic.Mul:   // one-operand: {a}x = {a}x * src at the operand width (high half dropped)
            {
                int w = DestWidth(ins);
                Emit(new AssignStmt { Dest = new RegExpr(AxW(w)), Src = new BinExpr(ins.Mnemonic == Mnemonic.Mul ? BinOp.UMul : BinOp.Mul, new RegExpr(AxW(w)), Operand(ins, 0, w), w) });
                _flag = default;
                break;
            }

            case Mnemonic.Div or Mnemonic.Idiv:
            {
                bool s = ins.Mnemonic == Mnemonic.Idiv;
                int w = DestWidth(ins);                 // operand width: byte/word/dword/qword
                var src = Operand(ins, 0, w);           // dividend modelled as {a}x; the high half in {d}x is ignored
                Emit(new AssignStmt { Dest = new RegExpr(DxW(w)), Src = new BinExpr(s ? BinOp.SMod : BinOp.UMod, new RegExpr(AxW(w)), src, w) });
                Emit(new AssignStmt { Dest = new RegExpr(AxW(w)), Src = new BinExpr(s ? BinOp.SDiv : BinOp.UDiv, new RegExpr(AxW(w)), src, w) });
                _flag = default;
                break;
            }

            case Mnemonic.Cmp:
                _flag = new FlagDef(FlagSource.Compare, Operand(ins, 0, DestWidth(ins)), Operand(ins, 1, DestWidth(ins)));
                break;
            case Mnemonic.Test:
                _flag = new FlagDef(FlagSource.Test, Operand(ins, 0, DestWidth(ins)), Operand(ins, 1, DestWidth(ins)));
                break;

            case Mnemonic.Nop or Mnemonic.Endbr64 or Mnemonic.Endbr32 or Mnemonic.Pause or Mnemonic.Fnop:
                Emit(new NopStmt());
                break;

            case Mnemonic.Leave:
                Emit(new AssignStmt { Dest = new RegExpr(Sp), Src = new RegExpr(_is64 ? Register.RBP : Register.EBP) });
                Emit(new AssignStmt { Dest = new RegExpr(_is64 ? Register.RBP : Register.EBP), Src = new LoadExpr(new RegExpr(Sp), Ptr) });
                Emit(new AssignStmt { Dest = new RegExpr(Sp), Src = new BinExpr(BinOp.Add, new RegExpr(Sp), new Const(Ptr, Ptr), Ptr) });
                break;

            case Mnemonic.Call:
            {
                var call = MakeCall(ins);
                Emit(new AssignStmt { Dest = new RegExpr(Ax), Src = call });
                _flag = default;   // a call clobbers flags
                break;
            }

            case Mnemonic.Ret or Mnemonic.Retf:
                Emit(new ReturnStmt { Value = null });
                break;

            case Mnemonic.Jmp:
                if (FlowAnalysis.DirectBranchTarget(ins) is ulong jt)
                    Emit(new GotoStmt { Target = jt });
                else if (_jumpTables.TryGetValue(va, out var cases))
                    Emit(new SwitchTermStmt { Value = Operand(ins, 0, Ptr), Cases = cases });
                else
                    Emit(new AsmStmt { Text = _fmt.FormatText(ins) });   // unresolved indirect jump
                break;

            default:
                if (ins.FlowControl == FlowControl.ConditionalBranch && FlowAnalysis.DirectBranchTarget(ins) is ulong tt)
                {
                    Emit(new BranchStmt { Cond = Condition(ins.ConditionCode), IfTrue = tt, IfFalse = va + (ulong)ins.Length });
                    break;
                }
                // setcc / cmovcc both expose a ConditionCode with FlowControl.Next; they differ by arity
                // (setcc writes one 8-bit operand, cmovcc is a 2-operand conditional move).
                if (ins.ConditionCode != ConditionCode.None && ins.FlowControl == FlowControl.Next)
                {
                    if (ins.OpCount == 1) { Emit(new AssignStmt { Dest = Dest(ins), Src = Condition(ins.ConditionCode) }); break; }
                    if (ins.OpCount == 2)
                    {
                        var d = Dest(ins); int w = DestWidth(ins);
                        Emit(new AssignStmt { Dest = d, Src = new TernaryExpr(Condition(ins.ConditionCode), Src1(ins, w), d) });
                        break;
                    }
                }
                // Outside the lifted subset — carry the instruction verbatim, and assume it touched flags.
                Emit(new AsmStmt { Text = _fmt.FormatText(ins) });
                _flag = default;
                break;
        }
    }

    private void Arith(BinOp op, in Instruction ins, Action<Stmt> emit)
    {
        var d = Dest(ins);
        int w = DestWidth(ins);
        emit(new AssignStmt { Dest = d, Src = new BinExpr(op, d, Src1(ins, w), w) });
        _flag = new FlagDef(FlagSource.Result, d, new Const(0, w));
    }

    // ---- call / argument resolution ----

    private CallExpr MakeCall(in Instruction ins)
    {
        // Direct call to a known/sub_ target.
        if (FlowAnalysis.IsDirectCall(ins))
        {
            ulong t = ins.NearBranchTarget;
            string name = _names.TryGetValue(t, out var n) ? n : $"sub_{t:X}";
            return new CallExpr(new SymExpr(t, name), [], name);
        }
        // Indirect call through an import (IAT) slot.
        if (ins.Op0Kind == OpKind.Memory)
        {
            ulong addr = ins.IsIPRelativeMemoryOperand ? ins.IPRelativeMemoryAddress : ins.MemoryDisplacement64;
            if (_image.ImportsByIatVa.TryGetValue(addr, out var imp))
                return new CallExpr(new SymExpr(addr, imp.Name), [], imp.Name);
            if (_names.TryGetValue(addr, out var nm))
                return new CallExpr(new SymExpr(addr, nm), [], nm);
            return new CallExpr(new LoadExpr(MemAddr(ins), Ptr), [], null);
        }
        // Indirect call through a register / other operand.
        return new CallExpr(Operand(ins, 0, Ptr), [], null);
    }

    // ---- operand helpers ----

    private Expr Dest(in Instruction ins) => Operand(ins, 0, DestWidth(ins));
    private Expr Src1(in Instruction ins, int width) => Operand(ins, 1, width);

    private int DestWidth(in Instruction ins)
    {
        var k = ins.Op0Kind;
        if (k == OpKind.Register) return Math.Max(1, ins.Op0Register.GetSize());
        if (k == OpKind.Memory) return MemWidth(ins);
        return Ptr;
    }

    private Expr Operand(in Instruction ins, int i, int width)
    {
        var kind = ins.GetOpKind(i);
        switch (kind)
        {
            case OpKind.Register:
                return new RegExpr(ins.GetOpRegister(i));
            case OpKind.Memory:
                return new LoadExpr(MemAddr(ins), MemWidth(ins));
            case OpKind.NearBranch16 or OpKind.NearBranch64 or OpKind.NearBranch32:
            {
                ulong t = ins.NearBranchTarget;
                return _names.TryGetValue(t, out var n) ? new SymExpr(t, n) : new Const((long)t, Ptr);
            }
            case OpKind.Immediate8 or OpKind.Immediate8_2nd or OpKind.Immediate16 or OpKind.Immediate32
                or OpKind.Immediate64 or OpKind.Immediate8to16 or OpKind.Immediate8to32 or OpKind.Immediate8to64
                or OpKind.Immediate32to64:
            {
                long v = (long)ins.GetImmediate(i);
                ulong uv = (ulong)v;
                if (_image.IsMappedVa(uv) && _names.TryGetValue(uv, out var n)) return new SymExpr(uv, n);
                return new Const(v, width == 0 ? Ptr : width);
            }
            default:
                return new RawExpr(kind.ToString());
        }
    }

    /// <summary>The address expression of a memory operand: <c>[base + index*scale + disp]</c>,
    /// with absolute targets replaced by their symbol where known.</summary>
    private Expr MemAddr(in Instruction ins)
    {
        if (ins.IsIPRelativeMemoryOperand)
        {
            ulong a = ins.IPRelativeMemoryAddress;
            return _names.TryGetValue(a, out var n) ? new SymExpr(a, n) : new Const((long)a, Ptr);
        }

        Register bas = ins.MemoryBase, idx = ins.MemoryIndex;
        ulong disp = ins.MemoryDisplacement64;

        if (bas == Register.None && idx == Register.None)
            return _names.TryGetValue(disp, out var n) ? new SymExpr(disp, n) : new Const((long)disp, Ptr);

        Expr? acc = bas != Register.None && bas != Register.RIP && bas != Register.EIP ? new RegExpr(bas) : null;
        if (idx != Register.None)
        {
            Expr ix = new RegExpr(idx);
            int scale = ins.MemoryIndexScale;
            if (scale > 1) ix = new BinExpr(BinOp.Mul, ix, new Const(scale, Ptr), Ptr);
            acc = acc is null ? ix : new BinExpr(BinOp.Add, acc, ix, Ptr);
        }
        if (disp != 0)
        {
            Expr de = _names.TryGetValue(disp, out var n) ? new SymExpr(disp, n) : new Const((long)disp, Ptr);
            acc = acc is null ? de : new BinExpr(BinOp.Add, acc, de, Ptr);
        }
        return acc ?? new Const(0, Ptr);
    }

    private int MemWidth(in Instruction ins)
    {
        try { int s = ins.MemorySize.GetSize(); if (s is > 0 and <= 32) return s; } catch { /* fall through */ }
        return Ptr;
    }

    // ---- flag → condition lowering ----

    private Expr Condition(ConditionCode cc)
    {
        var f = _flag;
        if (f.Source == FlagSource.None) return new RawExpr(CcName(cc));

        Expr a = f.Left, b = f.Right;
        switch (f.Source)
        {
            case FlagSource.Compare:
                return cc switch
                {
                    ConditionCode.e => new CmpExpr(CmpOp.Eq, a, b),
                    ConditionCode.ne => new CmpExpr(CmpOp.Ne, a, b),
                    ConditionCode.b => new CmpExpr(CmpOp.ULt, a, b),
                    ConditionCode.ae => new CmpExpr(CmpOp.UGe, a, b),
                    ConditionCode.be => new CmpExpr(CmpOp.ULe, a, b),
                    ConditionCode.a => new CmpExpr(CmpOp.UGt, a, b),
                    ConditionCode.l => new CmpExpr(CmpOp.SLt, a, b),
                    ConditionCode.ge => new CmpExpr(CmpOp.SGe, a, b),
                    ConditionCode.le => new CmpExpr(CmpOp.SLe, a, b),
                    ConditionCode.g => new CmpExpr(CmpOp.SGt, a, b),
                    ConditionCode.s => new CmpExpr(CmpOp.SLt, a, b),
                    ConditionCode.ns => new CmpExpr(CmpOp.SGe, a, b),
                    _ => new RawExpr(CcName(cc)),
                };

            case FlagSource.Test:
            {
                Expr lhs = a.Equals(b) ? a : new BinExpr(BinOp.And, a, b, a.Size);
                return ZeroCompare(cc, lhs);
            }

            default: // Result vs zero
                return ZeroCompare(cc, a);
        }
    }

    private static Expr ZeroCompare(ConditionCode cc, Expr lhs)
    {
        var zero = new Const(0, lhs.Size == 0 ? 4 : lhs.Size);
        return cc switch
        {
            ConditionCode.e => new CmpExpr(CmpOp.Eq, lhs, zero),
            ConditionCode.ne => new CmpExpr(CmpOp.Ne, lhs, zero),
            ConditionCode.s => new CmpExpr(CmpOp.SLt, lhs, zero),
            ConditionCode.ns => new CmpExpr(CmpOp.SGe, lhs, zero),
            ConditionCode.g => new CmpExpr(CmpOp.SGt, lhs, zero),
            ConditionCode.ge => new CmpExpr(CmpOp.SGe, lhs, zero),
            ConditionCode.l => new CmpExpr(CmpOp.SLt, lhs, zero),
            ConditionCode.le => new CmpExpr(CmpOp.SLe, lhs, zero),
            _ => new RawExpr(CcName(cc)),
        };
    }

    private static string CcName(ConditionCode cc) => cc switch
    {
        ConditionCode.o => "overflow", ConditionCode.no => "!overflow",
        ConditionCode.p => "parity", ConditionCode.np => "!parity",
        _ => "cc_" + cc,
    };
}

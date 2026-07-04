using DisasmStudio.Core.Analysis;
using DisasmStudio.Core.Formats;
using Gee.External.Capstone;
using Gee.External.Capstone.Arm;
using Gee.External.Capstone.Arm64;

namespace DisasmStudio.Core.IL;

/// <summary>
/// Lifts an ARM-family function's decoded instructions to Low IL, parallel to the x86/x64 <see cref="Lifter"/>
/// but driven by Capstone. This stage covers the AArch64 (ARM64) integer + control-flow subset; anything
/// outside it (SIMD/FP/system/atomics, and — for now — 32-bit ARM / Thumb) is carried through verbatim as an
/// <see cref="AsmStmt"/> so output is always produced. Flags use the same deferred model as the x86 lifter:
/// a flag-setting instruction (the <c>s</c> suffix / <c>cmp</c> / <c>tst</c>) records a deferred definition
/// that the following <c>b.&lt;cc&gt;</c> / <c>cs*</c> turns into a real comparison.
/// The neutral IL it produces feeds the shared MediumLifter / Structurer / emitters unchanged.
/// </summary>
public sealed class ArmLifter : ILifter, IDisposable
{
    private enum FlagSource { None, Compare, Test, Result }
    private readonly record struct FlagDef(FlagSource Source, Expr Left, Expr Right);

    private readonly IBinaryImage _image;
    private readonly IReadOnlyDictionary<ulong, string> _names;
    private readonly IReadOnlyDictionary<ulong, ulong[]> _jumpTables;
    private readonly bool _is64;
    private readonly CapstoneArm64Disassembler? _a64;   // AArch64
    private readonly CapstoneArmDisassembler? _a32;      // 32-bit ARM + Thumb
    private FlagDef _flag;

    public ArmLifter(IBinaryImage image, IReadOnlyDictionary<ulong, string> names,
        IReadOnlyDictionary<ulong, ulong[]> jumpTables)
    {
        _image = image;
        _names = names;
        _jumpTables = jumpTables;
        _is64 = image.Arch == Architecture.Arm64;
        if (_is64)
        {
            _a64 = CapstoneDisassembler.CreateArm64Disassembler(Arm64DisassembleMode.Arm | Arm64DisassembleMode.LittleEndian);
            _a64.EnableInstructionDetails = true;
        }
        else
        {
            var mode = (image.Arch == Architecture.Thumb ? ArmDisassembleMode.Thumb : ArmDisassembleMode.Arm)
                       | ArmDisassembleMode.LittleEndian;
            _a32 = CapstoneDisassembler.CreateArmDisassembler(mode);
            _a32.EnableInstructionDetails = true;
        }
    }

    public void Dispose() { _a64?.Dispose(); _a32?.Dispose(); }

    private static readonly RegExpr X0 = new(new RegId("x0", 8));
    private static readonly RegExpr R0 = new(new RegId("r0", 4));

    public LiftedFunction Lift(Function fn)
    {
        var blocks = new List<LiftedBlock>();
        foreach (var bb in fn.Blocks)
        {
            var lb = new LiftedBlock { Start = bb.Start, End = bb.End, Out = bb.Out };
            _flag = default;   // flags don't carry meaningfully across block boundaries

            // Decode the whole block in one Capstone call, not instruction-by-instruction: this is what
            // lets Capstone carry Thumb IT-block state (the predication of the guarded instructions) and
            // handle mixed 16/32-bit Thumb encodings. A64/A32 are unaffected by the change.
            int len = bb.End > bb.Start ? (int)(bb.End - bb.Start) : 4;
            byte[] buf = _image.ReadBytesAtVa(bb.Start, Math.Min(len, 1 << 20));
            if (buf.Length == 0) { blocks.Add(lb); continue; }

            if (_is64)
                foreach (var i in _a64!.Disassemble(buf, (long)bb.Start)) LiftA64((ulong)i.Address, i, lb.Stmts);
            else
                foreach (var i in _a32!.Disassemble(buf, (long)bb.Start)) LiftA32((ulong)i.Address, i, lb.Stmts);

            blocks.Add(lb);
        }

        var lf = new LiftedFunction { Va = fn.EntryVa, Name = fn.Name, Blocks = blocks };
        foreach (var b in blocks) lf.ByStart[b.Start] = b;
        return lf;
    }

    private void LiftA64(ulong va, Arm64Instruction ins, List<Stmt> outp)
    {
        void Emit(Stmt s) { s.Va = va; outp.Add(s); }
        Arm64Operand[] ops = ins.Details.Operands;
        string m = ins.Mnemonic;

        // ---- control flow ----
        switch (m)
        {
            case "ret": Emit(new ReturnStmt { Value = null }); return;
            case "nop": Emit(new NopStmt()); return;
            case "b" when ops.Length >= 1 && ops[0].Type == Arm64OperandType.Immediate:
                Emit(new GotoStmt { Target = (ulong)ops[0].Immediate }); return;
            case "bl" when ops.Length >= 1 && ops[0].Type == Arm64OperandType.Immediate:
            {
                ulong t = (ulong)ops[0].Immediate;
                string name = _names.TryGetValue(t, out var n) ? n : $"sub_{t:X}";
                Emit(new AssignStmt { Dest = X0, Src = new CallExpr(new SymExpr(t, name), [], name) });
                _flag = default;
                return;
            }
            case "blr" when ops.Length >= 1:
                Emit(new AssignStmt { Dest = X0, Src = new CallExpr(Val(ops[0], 8), [], null) });
                _flag = default;
                return;
            case "br":
                Emit(new AsmStmt { Text = Text(ins) }); _flag = default; return;
            case "cbz" or "cbnz" when ops.Length >= 2:
            {
                int w = W(ops[0]);
                var cond = new CmpExpr(m == "cbz" ? CmpOp.Eq : CmpOp.Ne, Val(ops[0], w), new Const(0, w));
                Emit(new BranchStmt { Cond = cond, IfTrue = (ulong)ops[1].Immediate, IfFalse = va + 4 });
                return;
            }
            case "tbz" or "tbnz" when ops.Length >= 3:
            {
                int bit = (int)ops[1].Immediate;
                var masked = new BinExpr(BinOp.And, Val(ops[0], 8), new Const(1L << bit, 8), 8);
                var cond = new CmpExpr(m == "tbz" ? CmpOp.Eq : CmpOp.Ne, masked, new Const(0, 8));
                Emit(new BranchStmt { Cond = cond, IfTrue = (ulong)ops[2].Immediate, IfFalse = va + 4 });
                return;
            }
        }
        if (m.StartsWith("b.", StringComparison.Ordinal) && ops.Length >= 1)
        {
            Emit(new BranchStmt { Cond = Condition(ins.Details.ConditionCode), IfTrue = (ulong)ops[0].Immediate, IfFalse = va + 4 });
            return;
        }

        // ---- compares (deferred flag, no value written) ----
        switch (m)
        {
            case "cmp" when ops.Length >= 2:
                _flag = new FlagDef(FlagSource.Compare, Val(ops[0], W(ops[0])), Val(ops[1], W(ops[0]))); return;
            case "cmn" when ops.Length >= 2:
                _flag = new FlagDef(FlagSource.Compare, Val(ops[0], W(ops[0])), new UnaryExpr(UnOp.Neg, Val(ops[1], W(ops[0])), W(ops[0]))); return;
            case "tst" when ops.Length >= 2:
                _flag = new FlagDef(FlagSource.Test, Val(ops[0], W(ops[0])), Val(ops[1], W(ops[0]))); return;
        }

        // ---- moves ----
        switch (m)
        {
            case "mov" or "movz" when ops.Length >= 2 && ops[0].Type == Arm64OperandType.Register:
                Emit(Assign(RegE(ops[0].Register), Val(ops[1], W(ops[0])))); return;
            case "movn" or "mvn" when ops.Length >= 2 && ops[0].Type == Arm64OperandType.Register:
            {
                int w = W(ops[0]);
                Emit(Assign(RegE(ops[0].Register), new UnaryExpr(UnOp.Not, Val(ops[1], w), w))); return;
            }
            case "movk" when ops.Length >= 2 && ops[0].Type == Arm64OperandType.Register:
            {
                int w = W(ops[0]);
                var d = RegE(ops[0].Register);
                Emit(Assign(d, new BinExpr(BinOp.Or, d, Val(ops[1], w), w))); return;   // approximate: insert without mask
            }
            case "adr" or "adrp" when ops.Length >= 2 && ops[0].Type == Arm64OperandType.Register:
            {
                long addr = ops[1].Immediate;
                Expr src = _names.TryGetValue((ulong)addr, out var nm) ? new SymExpr((ulong)addr, nm) : new Const(addr, 8);
                Emit(Assign(RegE(ops[0].Register), src)); return;
            }
        }

        // ---- conditional select ----
        if ((m == "csel") && ops.Length >= 3 && ops[0].Type == Arm64OperandType.Register)
        {
            int w = W(ops[0]);
            Emit(Assign(RegE(ops[0].Register), new TernaryExpr(Condition(ins.Details.ConditionCode), Val(ops[1], w), Val(ops[2], w))));
            return;
        }
        if (m is "cset" or "csetm" && ops.Length >= 1 && ops[0].Type == Arm64OperandType.Register)
        {
            int w = W(ops[0]);
            Expr t = m == "cset" ? new Const(1, w) : new Const(-1, w);
            Emit(Assign(RegE(ops[0].Register), new TernaryExpr(Condition(ins.Details.ConditionCode), t, new Const(0, w))));
            return;
        }

        // ---- loads / stores ----
        if (IsLoad(m) && ops.Length >= 2 && ops[0].Type == Arm64OperandType.Register && ops[1].Type == Arm64OperandType.Memory)
        { EmitLoad(m, ins, ops, Emit); return; }
        if (IsStore(m) && ops.Length >= 2 && ops[0].Type == Arm64OperandType.Register && ops[1].Type == Arm64OperandType.Memory)
        { EmitStore(m, ins, ops, Emit); return; }
        if ((m == "ldp" || m == "stp") && ops.Length >= 3 && ops[2].Type == Arm64OperandType.Memory)
        { EmitPair(m, ins, ops, Emit); return; }

        // ---- two-source arithmetic / logical ----
        if (ArithOp(m) is BinOp bop && ops.Length >= 3 && ops[0].Type == Arm64OperandType.Register)
        {
            var d = RegE(ops[0].Register); int w = W(ops[0]);
            Emit(Assign(d, new BinExpr(bop, Val(ops[1], w), Val(ops[2], w), w)));
            SetFlags(ins, d, w);
            return;
        }
        // bic/orn: op1 <op> ~op2
        if ((m is "bic" or "bics" or "orn") && ops.Length >= 3 && ops[0].Type == Arm64OperandType.Register)
        {
            var d = RegE(ops[0].Register); int w = W(ops[0]);
            var notR = new UnaryExpr(UnOp.Not, Val(ops[2], w), w);
            Emit(Assign(d, new BinExpr(m == "orn" ? BinOp.Or : BinOp.And, Val(ops[1], w), notR, w)));
            SetFlags(ins, d, w);
            return;
        }
        if ((m is "neg" or "negs") && ops.Length >= 2 && ops[0].Type == Arm64OperandType.Register)
        {
            var d = RegE(ops[0].Register); int w = W(ops[0]);
            Emit(Assign(d, new UnaryExpr(UnOp.Neg, Val(ops[1], w), w)));
            SetFlags(ins, d, w);
            return;
        }
        // madd/msub: op0 = op3 +/- op1*op2
        if ((m is "madd" or "msub" or "mul" or "mneg") && ops.Length >= 3 && ops[0].Type == Arm64OperandType.Register)
        {
            var d = RegE(ops[0].Register); int w = W(ops[0]);
            var prod = new BinExpr(BinOp.Mul, Val(ops[1], w), Val(ops[2], w), w);
            Expr src = m switch
            {
                "madd" when ops.Length >= 4 => new BinExpr(BinOp.Add, Val(ops[3], w), prod, w),
                "msub" when ops.Length >= 4 => new BinExpr(BinOp.Sub, Val(ops[3], w), prod, w),
                "mneg" => new UnaryExpr(UnOp.Neg, prod, w),
                _ => prod,
            };
            Emit(Assign(d, src));
            return;
        }

        // Outside the lifted subset — carry verbatim and assume flags touched.
        Emit(new AsmStmt { Text = Text(ins) });
        _flag = default;
    }

    // ---- load / store helpers ----

    private static bool IsLoad(string m) => m is "ldr" or "ldrb" or "ldrh" or "ldrsb" or "ldrsh" or "ldrsw"
        or "ldur" or "ldurb" or "ldurh" or "ldursb" or "ldursh" or "ldursw" or "ldar" or "ldxr";
    private static bool IsStore(string m) => m is "str" or "strb" or "strh"
        or "stur" or "sturb" or "sturh" or "stlr" or "stxr";

    private void EmitLoad(string m, Arm64Instruction ins, Arm64Operand[] ops, Action<Stmt> emit)
    {
        var d = RegE(ops[0].Register);
        int w = MemWidth(m, ops[0]);
        var mem = ops[1];
        bool post = ins.Details.WriteBack && ops.Length >= 3 && ops[2].Type == Arm64OperandType.Immediate;
        if (ins.Details.WriteBack && !post)   // pre-index: base += disp, then load from base
        {
            emit(Assign(RegE(mem.Memory.Base), AddDisp(RegE(mem.Memory.Base), mem.Memory.Displacement)));
            emit(Assign(d, new LoadExpr(RegE(mem.Memory.Base), w)));
        }
        else if (post)                        // post-index: load from base, then base += imm
        {
            emit(Assign(d, new LoadExpr(RegE(mem.Memory.Base), w)));
            emit(Assign(RegE(mem.Memory.Base), AddDisp(RegE(mem.Memory.Base), ops[2].Immediate)));
        }
        else emit(Assign(d, new LoadExpr(Addr(mem), w)));
    }

    private void EmitStore(string m, Arm64Instruction ins, Arm64Operand[] ops, Action<Stmt> emit)
    {
        var src = Val(ops[0], W(ops[0]));
        int w = MemWidth(m, ops[0]);
        var mem = ops[1];
        bool post = ins.Details.WriteBack && ops.Length >= 3 && ops[2].Type == Arm64OperandType.Immediate;
        if (ins.Details.WriteBack && !post)
        {
            emit(Assign(RegE(mem.Memory.Base), AddDisp(RegE(mem.Memory.Base), mem.Memory.Displacement)));
            emit(Assign(new LoadExpr(RegE(mem.Memory.Base), w), src));
        }
        else if (post)
        {
            emit(Assign(new LoadExpr(RegE(mem.Memory.Base), w), src));
            emit(Assign(RegE(mem.Memory.Base), AddDisp(RegE(mem.Memory.Base), ops[2].Immediate)));
        }
        else emit(Assign(new LoadExpr(Addr(mem), w), src));
    }

    private void EmitPair(string m, Arm64Instruction ins, Arm64Operand[] ops, Action<Stmt> emit)
    {
        bool load = m == "ldp";
        var mem = ops[2];
        int w = W(ops[0]);                       // element width (x = 8, w = 4)
        long disp = mem.Memory.Displacement;
        bool post = ins.Details.WriteBack && ops.Length >= 4 && ops[3].Type == Arm64OperandType.Immediate;

        if (ins.Details.WriteBack && !post)      // pre-index: fold disp into the base up front
        {
            emit(Assign(RegE(mem.Memory.Base), AddDisp(RegE(mem.Memory.Base), disp)));
            disp = 0;
        }

        Expr a0 = AddrOf(mem.Memory.Base, disp);
        Expr a1 = AddrOf(mem.Memory.Base, disp + w);
        if (load)
        {
            emit(Assign(RegE(ops[0].Register), new LoadExpr(a0, w)));
            emit(Assign(RegE(ops[1].Register), new LoadExpr(a1, w)));
        }
        else
        {
            emit(Assign(new LoadExpr(a0, w), RegE(ops[0].Register)));
            emit(Assign(new LoadExpr(a1, w), RegE(ops[1].Register)));
        }

        if (post) emit(Assign(RegE(mem.Memory.Base), AddDisp(RegE(mem.Memory.Base), ops[3].Immediate)));
    }

    // ---- operand lowering ----

    private Expr Val(Arm64Operand op, int width)
    {
        int w = width == 0 ? 8 : width;
        switch (op.Type)
        {
            case Arm64OperandType.Register:
                return Shifted(RegE(op.Register), op, w);
            case Arm64OperandType.Immediate:
                return Shifted(new Const(op.Immediate, w), op, w);   // e.g. `#1, lsl #12` → 0x1000 (folded downstream)
            case Arm64OperandType.Memory:
                return new LoadExpr(Addr(op), w);                    // the index shift is handled inside Addr
            default:
                return new RawExpr(op.Type.ToString());
        }
    }

    // Apply an operand-level shift/extend (LSL/LSR/ASR/ROR). ShiftValue must only be read when a shift
    // is present — Capstone throws otherwise.
    private static Expr Shifted(Expr e, Arm64Operand op, int w) =>
        op.ShiftOperation != Arm64ShiftOperation.Invalid
            ? new BinExpr(ShiftOp(op.ShiftOperation), e, new Const(op.ShiftValue, w), w)
            : e;

    /// <summary>Address expression of a memory operand: <c>base + (index &lt;&lt; shift) + disp</c>.</summary>
    private Expr Addr(Arm64Operand op)
    {
        var mem = op.Memory;
        Expr? acc = Has(mem.Base) ? RegE(mem.Base) : null;
        if (Has(mem.Index))
        {
            Expr ix = RegE(mem.Index);
            if (op.ShiftOperation != Arm64ShiftOperation.Invalid && op.ShiftValue > 0)
                ix = new BinExpr(ShiftOp(op.ShiftOperation), ix, new Const(op.ShiftValue, 8), 8);
            acc = acc is null ? ix : new BinExpr(BinOp.Add, acc, ix, 8);
        }
        if (mem.Displacement != 0)
        {
            var d = new Const(mem.Displacement, 8);   // negative disp renders as `base - N` in the emitter
            acc = acc is null ? d : new BinExpr(BinOp.Add, acc, d, 8);
        }
        return acc ?? new Const(0, 8);
    }

    private static Expr AddrOf(Arm64Register baseReg, long disp) =>
        disp == 0 ? RegE(baseReg) : new BinExpr(BinOp.Add, RegE(baseReg), new Const(disp, 8), 8);

    private static AssignStmt Assign(Expr dest, Expr src) => new() { Dest = dest, Src = src };
    private static Expr AddDisp(Expr baseExpr, long disp) => new BinExpr(BinOp.Add, baseExpr, new Const(disp, 8), 8);

    private static RegExpr RegE(Arm64Register r) => new(new RegId(r.Name, WidthOf(r.Name)));

    private static int W(Arm64Operand op) => op.Type == Arm64OperandType.Register ? WidthOf(op.Register.Name) : 8;

    private static bool Has(Arm64Register? r) => r is not null && !string.IsNullOrEmpty(r.Name);

    private static int WidthOf(string name)
    {
        if (string.IsNullOrEmpty(name)) return 8;
        char c = name[0];
        if (c == 'w') return 4;    // w0..w30, wsp, wzr
        if (c == 'x') return 8;    // x0..x30, xzr
        return 8;                  // sp, lr, xzr, and anything else default to 64-bit
    }

    private static int MemWidth(string m, Arm64Operand reg)
    {
        if (m.EndsWith("sw", StringComparison.Ordinal)) return 4;
        if (m.EndsWith("b", StringComparison.Ordinal)) return 1;
        if (m.EndsWith("h", StringComparison.Ordinal)) return 2;
        return W(reg);
    }

    private static string Text(Arm64Instruction ins) =>
        string.IsNullOrEmpty(ins.Operand) ? ins.Mnemonic : $"{ins.Mnemonic} {ins.Operand}";

    private void SetFlags(Arm64Instruction ins, Expr dest, int w)
    {
        if (ins.Details.UpdateFlags) _flag = new FlagDef(FlagSource.Result, dest, new Const(0, w));
    }

    private static BinOp? ArithOp(string m) => m switch
    {
        "add" or "adds" => BinOp.Add,
        "sub" or "subs" => BinOp.Sub,
        "and" or "ands" => BinOp.And,
        "orr" => BinOp.Or,
        "eor" => BinOp.Xor,
        "lsl" or "lsls" => BinOp.Shl,
        "lsr" or "lsrs" => BinOp.Shr,
        "asr" or "asrs" => BinOp.Sar,
        "ror" => BinOp.Ror,
        "udiv" => BinOp.UDiv,
        "sdiv" => BinOp.SDiv,
        _ => null,
    };

    private static BinOp ShiftOp(Arm64ShiftOperation s) => s switch
    {
        Arm64ShiftOperation.ARM64_SFT_LSL or Arm64ShiftOperation.ARM64_SFT_MSL => BinOp.Shl,
        Arm64ShiftOperation.ARM64_SFT_LSR => BinOp.Shr,
        Arm64ShiftOperation.ARM64_SFT_ASR => BinOp.Sar,
        Arm64ShiftOperation.ARM64_SFT_ROR => BinOp.Ror,
        _ => BinOp.Shl,
    };

    // ---- flag → condition lowering ----

    private Expr Condition(Arm64ConditionCode cc)
    {
        var f = _flag;
        if (f.Source == FlagSource.None) return new RawExpr(CcName(cc));

        if (f.Source == FlagSource.Compare)
            return CompareCond(cc, f.Left, f.Right);

        // Test / Result → compare against zero.
        Expr lhs = f.Source == FlagSource.Test
            ? (f.Left.Equals(f.Right) ? f.Left : new BinExpr(BinOp.And, f.Left, f.Right, Math.Max(1, f.Left.Size)))
            : f.Left;
        return ZeroCond(cc, lhs);
    }

    private static Expr CompareCond(Arm64ConditionCode cc, Expr a, Expr b) => cc switch
    {
        Arm64ConditionCode.ARM64_CC_EQ => new CmpExpr(CmpOp.Eq, a, b),
        Arm64ConditionCode.ARM64_CC_NE => new CmpExpr(CmpOp.Ne, a, b),
        Arm64ConditionCode.ARM64_CC_HS => new CmpExpr(CmpOp.UGe, a, b),
        Arm64ConditionCode.ARM64_CC_LO => new CmpExpr(CmpOp.ULt, a, b),
        Arm64ConditionCode.ARM64_CC_HI => new CmpExpr(CmpOp.UGt, a, b),
        Arm64ConditionCode.ARM64_CC_LS => new CmpExpr(CmpOp.ULe, a, b),
        Arm64ConditionCode.ARM64_CC_GE => new CmpExpr(CmpOp.SGe, a, b),
        Arm64ConditionCode.ARM64_CC_LT => new CmpExpr(CmpOp.SLt, a, b),
        Arm64ConditionCode.ARM64_CC_GT => new CmpExpr(CmpOp.SGt, a, b),
        Arm64ConditionCode.ARM64_CC_LE => new CmpExpr(CmpOp.SLe, a, b),
        Arm64ConditionCode.ARM64_CC_MI => new CmpExpr(CmpOp.SLt, a, b),
        Arm64ConditionCode.ARM64_CC_PL => new CmpExpr(CmpOp.SGe, a, b),
        Arm64ConditionCode.ARM64_CC_AL => new Const(1, 1),
        _ => new RawExpr(CcName(cc)),
    };

    private static Expr ZeroCond(Arm64ConditionCode cc, Expr lhs)
    {
        var zero = new Const(0, lhs.Size == 0 ? 8 : lhs.Size);
        return cc switch
        {
            Arm64ConditionCode.ARM64_CC_EQ => new CmpExpr(CmpOp.Eq, lhs, zero),
            Arm64ConditionCode.ARM64_CC_NE => new CmpExpr(CmpOp.Ne, lhs, zero),
            Arm64ConditionCode.ARM64_CC_MI => new CmpExpr(CmpOp.SLt, lhs, zero),
            Arm64ConditionCode.ARM64_CC_PL => new CmpExpr(CmpOp.SGe, lhs, zero),
            Arm64ConditionCode.ARM64_CC_GT => new CmpExpr(CmpOp.SGt, lhs, zero),
            Arm64ConditionCode.ARM64_CC_GE => new CmpExpr(CmpOp.SGe, lhs, zero),
            Arm64ConditionCode.ARM64_CC_LT => new CmpExpr(CmpOp.SLt, lhs, zero),
            Arm64ConditionCode.ARM64_CC_LE => new CmpExpr(CmpOp.SLe, lhs, zero),
            Arm64ConditionCode.ARM64_CC_AL => new Const(1, 1),
            _ => new RawExpr(CcName(cc)),
        };
    }

    private static string CcName(Arm64ConditionCode cc)
    {
        string s = cc.ToString();               // e.g. "ARM64_CC_EQ"
        int u = s.LastIndexOf('_');
        return "cc_" + (u >= 0 ? s[(u + 1)..] : s).ToLowerInvariant();
    }

    // ================================================================================================
    //  32-bit ARM (A32) + Thumb. Dispatched on the condition-independent instruction Id; the condition
    //  suffix rides on the mnemonic in A32, so a predicated non-branch becomes a conditional assignment.
    // ================================================================================================

    private void LiftA32(ulong va, ArmInstruction ins, List<Stmt> outp)
    {
        void Emit(Stmt s) { s.Va = va; outp.Add(s); }
        ArmOperand[] ops = ins.Details.Operands;
        var cc = ins.Details.ConditionCode;
        ulong fall = va + (ulong)ins.Bytes.Length;

        // A predicated value-producing instruction is a conditional move: dest = cc ? src : dest.
        void Assn(Expr dest, Expr src) =>
            Emit(Assign(dest, IsUncond(cc) ? src : new TernaryExpr(ConditionA(cc), src, dest)));

        switch (ins.Id)
        {
            case ArmInstructionId.ARM_INS_PUSH when ops.Length > 0:
            {
                int n = ops.Length;
                Emit(Assign(SpA, new BinExpr(BinOp.Sub, SpA, new Const(4L * n, 4), 4)));
                for (int k = 0; k < n; k++)
                    Emit(Assign(new LoadExpr(SpPlus(4 * k), 4), RegEA(ops[k])));
                return;
            }
            case ArmInstructionId.ARM_INS_POP when ops.Length > 0:
            {
                int n = ops.Length;
                bool hasPc = false;
                for (int k = 0; k < n; k++)
                {
                    if (ops[k].Type == ArmOperandType.Register && ops[k].Register.Name == "pc") { hasPc = true; continue; }
                    Emit(Assign(RegEA(ops[k]), new LoadExpr(SpPlus(4 * k), 4)));
                }
                Emit(Assign(SpA, new BinExpr(BinOp.Add, SpA, new Const(4L * n, 4), 4)));
                if (hasPc) Emit(new ReturnStmt { Value = null });
                return;
            }

            case ArmInstructionId.ARM_INS_NOP: Emit(new NopStmt()); return;
            // An IT instruction only predicates the following 1–4 instructions; Capstone folds that
            // predication into each guarded instruction's condition code (handled by the Assn wrapper),
            // so the IT itself lowers to nothing.
            case ArmInstructionId.ARM_INS_IT: Emit(new NopStmt()); return;

            case ArmInstructionId.ARM_INS_B when ops.Length >= 1:
                if (IsUncond(cc)) Emit(new GotoStmt { Target = (ulong)ops[0].Immediate });
                else Emit(new BranchStmt { Cond = ConditionA(cc), IfTrue = (ulong)ops[0].Immediate, IfFalse = fall });
                return;

            case ArmInstructionId.ARM_INS_BL or ArmInstructionId.ARM_INS_BLX when ops.Length >= 1:
            {
                if (ops[0].Type == ArmOperandType.Immediate)
                {
                    ulong t = (ulong)ops[0].Immediate;
                    string name = _names.TryGetValue(t, out var n) ? n : $"sub_{t:X}";
                    Emit(Assign(R0, new CallExpr(new SymExpr(t, name), [], name)));
                }
                else Emit(Assign(R0, new CallExpr(ValA(ops[0]), [], null)));
                _flag = default;
                return;
            }

            case ArmInstructionId.ARM_INS_BX when ops.Length >= 1:
                if (ops[0].Type == ArmOperandType.Register && ops[0].Register.Name == "lr") Emit(new ReturnStmt { Value = null });
                else Emit(new AsmStmt { Text = TextA(ins) });
                return;

            case ArmInstructionId.ARM_INS_CMP when ops.Length >= 2:
                _flag = new FlagDef(FlagSource.Compare, ValA(ops[0]), ValA(ops[1])); return;
            case ArmInstructionId.ARM_INS_CMN when ops.Length >= 2:
                _flag = new FlagDef(FlagSource.Compare, ValA(ops[0]), new UnaryExpr(UnOp.Neg, ValA(ops[1]), 4)); return;
            case ArmInstructionId.ARM_INS_TST or ArmInstructionId.ARM_INS_TEQ when ops.Length >= 2:
                _flag = new FlagDef(FlagSource.Test, ValA(ops[0]), ValA(ops[1])); return;

            case ArmInstructionId.ARM_INS_MOV or ArmInstructionId.ARM_INS_MOVW when ops.Length >= 2 && ops[0].Type == ArmOperandType.Register:
                Assn(RegEA(ops[0]), ValA(ops[1])); SetFlagsA(ins, RegEA(ops[0])); return;
            case ArmInstructionId.ARM_INS_MVN when ops.Length >= 2 && ops[0].Type == ArmOperandType.Register:
                Assn(RegEA(ops[0]), new UnaryExpr(UnOp.Not, ValA(ops[1]), 4)); SetFlagsA(ins, RegEA(ops[0])); return;
        }

        // load / store
        if (IsLoadA(ins.Id) && ops.Length >= 2 && ops[0].Type == ArmOperandType.Register && ops[1].Type == ArmOperandType.Memory)
        {
            int w = MemWidthA(ins.Id);
            Assn(RegEA(ops[0]), new LoadExpr(AddrA(ops[1]), w));
            return;
        }
        // Only an unconditional store maps to a plain assignment; a predicated store has no clean IL form,
        // so it falls through to a verbatim AsmStmt rather than emitting a wrong unconditional write.
        if (IsStoreA(ins.Id) && IsUncond(cc) && ops.Length >= 2 && ops[0].Type == ArmOperandType.Register && ops[1].Type == ArmOperandType.Memory)
        {
            int w = MemWidthA(ins.Id);
            Emit(Assign(new LoadExpr(AddrA(ops[1]), w), ValA(ops[0])));
            return;
        }

        // two-source arithmetic / logical (3-operand; fall back to 2-operand accumulate form)
        if (ArithOpA(ins.Id) is BinOp bop && ops.Length >= 2 && ops[0].Type == ArmOperandType.Register)
        {
            var d = RegEA(ops[0]);
            // RSB is reverse-subtract (Op2 - Rn). Everything else is Rn <op> Op2. Both have a 3-operand
            // form (Rd, Rn, Op2) and a 2-operand shorthand (Rd, Op2) where Rn == Rd.
            Expr src = ins.Id == ArmInstructionId.ARM_INS_RSB
                ? (ops.Length >= 3 ? new BinExpr(BinOp.Sub, ValA(ops[2]), ValA(ops[1]), 4)
                                   : new BinExpr(BinOp.Sub, ValA(ops[1]), d, 4))
                : (ops.Length >= 3 ? new BinExpr(bop, ValA(ops[1]), ValA(ops[2]), 4)
                                   : new BinExpr(bop, d, ValA(ops[1]), 4));
            Assn(d, src);
            SetFlagsA(ins, d);
            return;
        }
        if (ins.Id == ArmInstructionId.ARM_INS_BIC && ops.Length >= 3 && ops[0].Type == ArmOperandType.Register)
        {
            var d = RegEA(ops[0]);
            Assn(d, new BinExpr(BinOp.And, ValA(ops[1]), new UnaryExpr(UnOp.Not, ValA(ops[2]), 4), 4));
            SetFlagsA(ins, d);
            return;
        }

        Emit(new AsmStmt { Text = TextA(ins) });
        _flag = default;
    }

    // ---- A32 helpers ----

    private static readonly RegExpr SpA = new(new RegId("sp", 4));
    private static Expr SpPlus(int off) => off == 0 ? SpA : new BinExpr(BinOp.Add, SpA, new Const(off, 4), 4);

    private static bool IsUncond(ArmConditionCode cc) => cc is ArmConditionCode.ARM_CC_AL or ArmConditionCode.Invalid;

    private static bool IsLoadA(ArmInstructionId id) => id is ArmInstructionId.ARM_INS_LDR or ArmInstructionId.ARM_INS_LDRB
        or ArmInstructionId.ARM_INS_LDRH or ArmInstructionId.ARM_INS_LDRSB or ArmInstructionId.ARM_INS_LDRSH;
    private static bool IsStoreA(ArmInstructionId id) => id is ArmInstructionId.ARM_INS_STR or ArmInstructionId.ARM_INS_STRB
        or ArmInstructionId.ARM_INS_STRH;

    private static int MemWidthA(ArmInstructionId id) => id switch
    {
        ArmInstructionId.ARM_INS_LDRB or ArmInstructionId.ARM_INS_LDRSB or ArmInstructionId.ARM_INS_STRB => 1,
        ArmInstructionId.ARM_INS_LDRH or ArmInstructionId.ARM_INS_LDRSH or ArmInstructionId.ARM_INS_STRH => 2,
        _ => 4,
    };

    private static BinOp? ArithOpA(ArmInstructionId id) => id switch
    {
        ArmInstructionId.ARM_INS_ADD => BinOp.Add,
        ArmInstructionId.ARM_INS_SUB or ArmInstructionId.ARM_INS_RSB => BinOp.Sub,
        ArmInstructionId.ARM_INS_AND => BinOp.And,
        ArmInstructionId.ARM_INS_ORR => BinOp.Or,
        ArmInstructionId.ARM_INS_EOR => BinOp.Xor,
        ArmInstructionId.ARM_INS_MUL => BinOp.Mul,
        ArmInstructionId.ARM_INS_LSL => BinOp.Shl,
        ArmInstructionId.ARM_INS_LSR => BinOp.Shr,
        ArmInstructionId.ARM_INS_ASR => BinOp.Sar,
        ArmInstructionId.ARM_INS_ROR => BinOp.Ror,
        ArmInstructionId.ARM_INS_UDIV => BinOp.UDiv,
        ArmInstructionId.ARM_INS_SDIV => BinOp.SDiv,
        _ => null,
    };

    private void SetFlagsA(ArmInstruction ins, Expr dest)
    {
        if (ins.Details.UpdateFlags) _flag = new FlagDef(FlagSource.Result, dest, new Const(0, 4));
    }

    private static RegExpr RegEA(ArmOperand op) => new(new RegId(op.Register.Name, 4));

    private Expr ValA(ArmOperand op)
    {
        switch (op.Type)
        {
            case ArmOperandType.Register:
            {
                Expr e = new RegExpr(new RegId(op.Register.Name, 4));
                if (op.ShiftOperation != ArmShiftOperation.Invalid && op.ShiftValue > 0)
                    e = new BinExpr(ShiftOpA(op.ShiftOperation), e, new Const(op.ShiftValue, 4), 4);
                return e;
            }
            case ArmOperandType.Immediate:
                return new Const(op.Immediate, 4);
            case ArmOperandType.Memory:
                return new LoadExpr(AddrA(op), 4);
            default:
                return new RawExpr(op.Type.ToString());
        }
    }

    private Expr AddrA(ArmOperand op)
    {
        var mem = op.Memory;
        Expr? acc = HasA(mem.Base) ? new RegExpr(new RegId(mem.Base.Name, 4)) : null;
        if (HasA(mem.Index))
        {
            Expr ix = new RegExpr(new RegId(mem.Index.Name, 4));
            if (mem.LeftShit > 0) ix = new BinExpr(BinOp.Shl, ix, new Const(mem.LeftShit, 4), 4);
            acc = acc is null ? ix : new BinExpr(op.IsSubtracted ? BinOp.Sub : BinOp.Add, acc, ix, 4);
        }
        if (mem.Displacement != 0)
        {
            var d = new Const(mem.Displacement, 4);
            acc = acc is null ? d : new BinExpr(BinOp.Add, acc, d, 4);
        }
        return acc ?? new Const(0, 4);
    }

    private static bool HasA(ArmRegister? r) => r is not null && !string.IsNullOrEmpty(r.Name);

    private static string TextA(ArmInstruction ins) =>
        string.IsNullOrEmpty(ins.Operand) ? ins.Mnemonic : $"{ins.Mnemonic} {ins.Operand}";

    private static BinOp ShiftOpA(ArmShiftOperation s) => s switch
    {
        ArmShiftOperation.ARM_SFT_LSL or ArmShiftOperation.ARM_SFT_LSL_REG => BinOp.Shl,
        ArmShiftOperation.ARM_SFT_LSR or ArmShiftOperation.ARM_SFT_LSR_REG => BinOp.Shr,
        ArmShiftOperation.ARM_SFT_ASR or ArmShiftOperation.ARM_SFT_ASR_REG => BinOp.Sar,
        ArmShiftOperation.ARM_SFT_ROR or ArmShiftOperation.ARM_SFT_ROR_REG => BinOp.Ror,
        _ => BinOp.Shl,
    };

    private Expr ConditionA(ArmConditionCode cc)
    {
        var f = _flag;
        if (f.Source == FlagSource.None) return new RawExpr(CcNameA(cc));
        if (f.Source == FlagSource.Compare) return CompareCondA(cc, f.Left, f.Right);
        Expr lhs = f.Source == FlagSource.Test
            ? (f.Left.Equals(f.Right) ? f.Left : new BinExpr(BinOp.And, f.Left, f.Right, Math.Max(1, f.Left.Size)))
            : f.Left;
        return ZeroCondA(cc, lhs);
    }

    private static Expr CompareCondA(ArmConditionCode cc, Expr a, Expr b) => cc switch
    {
        ArmConditionCode.ARM_CC_EQ => new CmpExpr(CmpOp.Eq, a, b),
        ArmConditionCode.ARM_CC_NE => new CmpExpr(CmpOp.Ne, a, b),
        ArmConditionCode.ARM_CC_HS => new CmpExpr(CmpOp.UGe, a, b),
        ArmConditionCode.ARM_CC_LO => new CmpExpr(CmpOp.ULt, a, b),
        ArmConditionCode.ARM_CC_HI => new CmpExpr(CmpOp.UGt, a, b),
        ArmConditionCode.ARM_CC_LS => new CmpExpr(CmpOp.ULe, a, b),
        ArmConditionCode.ARM_CC_GE => new CmpExpr(CmpOp.SGe, a, b),
        ArmConditionCode.ARM_CC_LT => new CmpExpr(CmpOp.SLt, a, b),
        ArmConditionCode.ARM_CC_GT => new CmpExpr(CmpOp.SGt, a, b),
        ArmConditionCode.ARM_CC_LE => new CmpExpr(CmpOp.SLe, a, b),
        ArmConditionCode.ARM_CC_MI => new CmpExpr(CmpOp.SLt, a, b),
        ArmConditionCode.ARM_CC_PL => new CmpExpr(CmpOp.SGe, a, b),
        ArmConditionCode.ARM_CC_AL => new Const(1, 1),
        _ => new RawExpr(CcNameA(cc)),
    };

    private static Expr ZeroCondA(ArmConditionCode cc, Expr lhs)
    {
        var zero = new Const(0, lhs.Size == 0 ? 4 : lhs.Size);
        return cc switch
        {
            ArmConditionCode.ARM_CC_EQ => new CmpExpr(CmpOp.Eq, lhs, zero),
            ArmConditionCode.ARM_CC_NE => new CmpExpr(CmpOp.Ne, lhs, zero),
            ArmConditionCode.ARM_CC_MI => new CmpExpr(CmpOp.SLt, lhs, zero),
            ArmConditionCode.ARM_CC_PL => new CmpExpr(CmpOp.SGe, lhs, zero),
            ArmConditionCode.ARM_CC_GT => new CmpExpr(CmpOp.SGt, lhs, zero),
            ArmConditionCode.ARM_CC_GE => new CmpExpr(CmpOp.SGe, lhs, zero),
            ArmConditionCode.ARM_CC_LT => new CmpExpr(CmpOp.SLt, lhs, zero),
            ArmConditionCode.ARM_CC_LE => new CmpExpr(CmpOp.SLe, lhs, zero),
            ArmConditionCode.ARM_CC_AL => new Const(1, 1),
            _ => new RawExpr(CcNameA(cc)),
        };
    }

    private static string CcNameA(ArmConditionCode cc)
    {
        string s = cc.ToString();               // e.g. "ARM_CC_EQ"
        int u = s.LastIndexOf('_');
        return "cc_" + (u >= 0 ? s[(u + 1)..] : s).ToLowerInvariant();
    }
}

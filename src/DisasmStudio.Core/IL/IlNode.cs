using DisasmStudio.Core.Analysis;
using Iced.Intel;

namespace DisasmStudio.Core.IL;

// The intermediate representation shared by every decompiler stage. It is deliberately small: a
// handful of expression and statement node kinds that the lifter (Low IL), the medium-level
// transforms, and the structurer all build on. Nodes carry no rendering — the emitters turn them
// into coloured token lines per level.

/// <summary>Binary operators in the IR (signedness is on the operator where it matters).</summary>
public enum BinOp
{
    Add, Sub, Mul, UMul, SDiv, UDiv, SMod, UMod,
    And, Or, Xor, Shl, Shr, Sar, Rol, Ror,
}

/// <summary>Unary operators.</summary>
public enum UnOp { Neg, Not }

/// <summary>Comparison operators (the U/S prefixes pick unsigned vs signed ordering).</summary>
public enum CmpOp { Eq, Ne, ULt, ULe, UGt, UGe, SLt, SLe, SGt, SGe }

/// <summary>What a recovered variable stands for, used for naming and declaration.</summary>
public enum VarClass { Local, Arg, Temp, RegVar, Return }

/// <summary>A recovered variable (register promotion or stack slot). Identity matters, so this is a
/// reference type — two uses of the same variable share one instance.</summary>
public sealed class Variable
{
    public required string Name { get; set; }
    public int Size { get; set; }        // bytes; 0 = unknown
    public VarClass Class { get; init; }
    public string CType => Size switch { 1 => "char", 2 => "short", 4 => "int", 8 => "int64_t", _ => "int" };
    public override string ToString() => Name;
}

// ---- expressions -------------------------------------------------------------------------------

public abstract record Expr
{
    /// <summary>Width in bytes of the value this expression produces (0 = unknown/irrelevant).</summary>
    public virtual int Size => 0;
}

/// <summary>An integer constant of a given width.</summary>
public sealed record Const(long Value, int Width) : Expr { public override int Size => Width; }

/// <summary>A physical CPU register (Low IL). Promoted to a <see cref="VarExpr"/> at medium level.</summary>
public sealed record RegExpr(Register Reg) : Expr
{
    public override int Size => Reg.GetSize();
}

/// <summary>A recovered variable (medium level and above).</summary>
public sealed record VarExpr(Variable Var) : Expr { public override int Size => Var.Size; }

/// <summary>A memory load of <paramref name="Width"/> bytes from <paramref name="Addr"/>.</summary>
public sealed record LoadExpr(Expr Addr, int Width) : Expr { public override int Size => Width; }

public sealed record UnaryExpr(UnOp Op, Expr E, int Width) : Expr { public override int Size => Width; }

public sealed record BinExpr(BinOp Op, Expr L, Expr R, int Width) : Expr { public override int Size => Width; }

/// <summary>A boolean comparison (the value feeding an <c>if</c> / conditional branch).</summary>
public sealed record CmpExpr(CmpOp Op, Expr L, Expr R) : Expr { public override int Size => 1; }

/// <summary>A C-style ternary, used to lower <c>setcc</c>/<c>cmovcc</c> at medium level.</summary>
public sealed record TernaryExpr(Expr Cond, Expr T, Expr F) : Expr;

/// <summary>A call expression; <see cref="Name"/> is the resolved callee when known.</summary>
public sealed record CallExpr(Expr Target, IReadOnlyList<Expr> Args, string? Name) : Expr;

/// <summary>A named address (function / loc_ / import / data symbol).</summary>
public sealed record SymExpr(ulong Va, string Name) : Expr { public override int Size => 8; }

/// <summary>An opaque sub-expression carried verbatim (fallback for unmodelled operands).</summary>
public sealed record RawExpr(string Text) : Expr;

// ---- statements --------------------------------------------------------------------------------

/// <summary>Base statement; every statement remembers the instruction VA it came from so the views
/// can sync the linear/graph/hex panes when a decompiler line is clicked.</summary>
public abstract class Stmt
{
    public ulong Va;
}

/// <summary><c>Dest = Src</c>. When <see cref="Dest"/> is a <see cref="LoadExpr"/> this is a store.</summary>
public sealed class AssignStmt : Stmt { public required Expr Dest; public required Expr Src; }

/// <summary>A call whose return value is discarded.</summary>
public sealed class CallStmt : Stmt { public required CallExpr Call; }

/// <summary>An unconditional transfer to another block (rendered as goto / fallthrough).</summary>
public sealed class GotoStmt : Stmt { public ulong Target; }

/// <summary>A two-way conditional block terminator (Low/Medium IL).</summary>
public sealed class BranchStmt : Stmt { public required Expr Cond; public ulong IfTrue; public ulong IfFalse; }

/// <summary>A multi-way (jump-table) block terminator.</summary>
public sealed class SwitchTermStmt : Stmt { public required Expr Value; public required IReadOnlyList<ulong> Cases; }

public sealed class ReturnStmt : Stmt { public Expr? Value; }

/// <summary>Verbatim assembly carried through when an instruction is outside the lifted subset.</summary>
public sealed class AsmStmt : Stmt { public required string Text; }

public sealed class NopStmt : Stmt { }

// ---- structured statements (High IL / Pseudo-C) ------------------------------------------------

public sealed class SeqStmt : Stmt { public List<Stmt> Items = []; }

public sealed class IfStmt : Stmt { public required Expr Cond; public required Stmt Then; public Stmt? Else; }

public sealed class WhileStmt : Stmt { public required Expr Cond; public required Stmt Body; public bool DoWhile; }

public sealed class StructSwitchStmt : Stmt { public required Expr Value; public List<SwitchCase> Cases = []; public Stmt? Default; }

public sealed class SwitchCase { public List<long> Values = []; public required Stmt Body; }

public sealed class BreakStmt : Stmt { }
public sealed class ContinueStmt : Stmt { }
public sealed class LabelStmt : Stmt { public ulong Target; }

// ---- lifted (unstructured) function ------------------------------------------------------------

/// <summary>A basic block after lifting: its straight-line statements plus the original CFG edges.</summary>
public sealed class LiftedBlock
{
    public required ulong Start { get; init; }
    public ulong End { get; set; }
    public List<Stmt> Stmts { get; } = [];
    public required IReadOnlyList<CfgEdge> Out { get; init; }
}

/// <summary>A function lowered to Low or Medium IL: an ordered list of basic blocks.</summary>
public sealed class LiftedFunction
{
    public required ulong Va { get; init; }
    public required string Name { get; init; }
    public required List<LiftedBlock> Blocks { get; init; }
    public List<Variable> Variables { get; } = [];   // recovered at medium level
    public Dictionary<ulong, LiftedBlock> ByStart { get; } = [];
}

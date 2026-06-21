using DisasmStudio.Core.Disasm;
using Iced.Intel;

namespace DisasmStudio.Core.IL;

/// <summary>Accumulates coloured tokens for the current line and flushes them as <see cref="DecompLine"/>s.</summary>
internal sealed class IlWriter
{
    public readonly List<DecompLine> Lines = [];
    private List<AsmToken> _cur = [];

    public void T(string s, AsmTokenKind k) => _cur.Add(new AsmToken(s, k));
    public void Kw(string s) => T(s, AsmTokenKind.Keyword);
    public void Op(string s) => T(s, AsmTokenKind.Punctuation);
    public void Sym(string s) => T(s, AsmTokenKind.Symbol);
    public void Var(string s) => T(s, AsmTokenKind.Variable);
    public void Type(string s) => T(s, AsmTokenKind.Type);
    public void Num(string s) => T(s, AsmTokenKind.Number);
    public void Txt(string s) => T(s, AsmTokenKind.Text);
    public void Sp() => T(" ", AsmTokenKind.Text);

    public void Flush(ulong va, int indent) { Lines.Add(new DecompLine(va, _cur, indent)); _cur = []; }
    public bool Pending => _cur.Count > 0;
}

/// <summary>Renders IR expressions and the leaf statements shared by every level into tokens.</summary>
internal static class ExprWriter
{
    // `comp` = compilable C: render valid C (typed pointer casts for memory, a helper for indirect
    // calls, sanitized/forward-declarable names, numeric addresses for data symbols).
    public static void Write(IlWriter w, Expr e, bool c, bool comp = false)
    {
        switch (e)
        {
            case Const k: { var (s, _) = Num(k.Value); w.Num(s); break; }
            case RegExpr r: w.T(r.Reg.ToString().ToLowerInvariant(), AsmTokenKind.Register); break;
            case VarExpr v: w.Var(v.Var.Name); break;
            case SymExpr sy: if (comp) w.Num($"0x{sy.Va:X}"); else w.Sym(sy.Name); break;
            case RawExpr rx: if (comp) WriteRaw(w, rx.Text); else w.Txt(rx.Text); break;

            case LoadExpr ld:
                if (comp) { w.Op($"*({PtrType(ld.Width)}*)("); Write(w, ld.Addr, c, comp); w.Op(")"); }
                else if (c) { w.Op("*("); Write(w, ld.Addr, c); w.Op(")"); }
                else { w.Op("["); Write(w, ld.Addr, c); w.Op("]"); }
                break;

            case UnaryExpr u:
                w.Op(u.Op == UnOp.Neg ? "-" : "~");
                Child(w, u.E, c, comp);
                break;

            case BinExpr b when b.Op is BinOp.Rol or BinOp.Ror:
                w.Sym(b.Op == BinOp.Rol ? "__rol" : "__ror"); w.Op("(");
                Write(w, b.L, c, comp); w.Op(", "); Write(w, b.R, c, comp); w.Op(")");
                break;

            // `x + -0x10` reads better as `x - 0x10`.
            case BinExpr { Op: BinOp.Add, R: Const { Value: < 0 } nc } b:
                Child(w, b.L, c, comp); w.Sp(); w.Op("-"); w.Sp(); w.Num(Num(-nc.Value).Text);
                break;

            case BinExpr b:
                Child(w, b.L, c, comp); w.Sp(); w.Op(BinStr(b.Op)); w.Sp(); Child(w, b.R, c, comp);
                break;

            case CmpExpr cm:
                Child(w, cm.L, c, comp); w.Sp(); w.Op(CmpStr(cm.Op)); w.Sp(); Child(w, cm.R, c, comp);
                break;

            case TernaryExpr t:
                Child(w, t.Cond, c, comp); w.Op(" ? "); Child(w, t.T, c, comp); w.Op(" : "); Child(w, t.F, c, comp);
                break;

            case CallExpr call:
                // Indirect calls (no resolved name) go through a declared helper so they stay valid C.
                if (call.Name is null && comp) w.Sym("__icall");
                else if (call.Name is not null) w.Sym(comp ? Sanitize(call.Name) : call.Name);
                else Write(w, call.Target, c, comp);
                w.Op("(");
                bool first = true;
                if (call.Name is null && comp) { Write(w, call.Target, c, comp); first = false; }
                for (int i = 0; i < call.Args.Count; i++) { if (!first || i > 0) w.Op(", "); Write(w, call.Args[i], c, comp); }
                w.Op(")");
                break;
        }
    }

    private static void Child(IlWriter w, Expr e, bool c, bool comp = false)
    {
        bool paren = e is BinExpr or CmpExpr or TernaryExpr;
        if (paren) w.Op("(");
        Write(w, e, c, comp);
        if (paren) w.Op(")");
    }

    private static readonly HashSet<string> KnownFlags =
    [
        "cc_b", "cc_ae", "cc_be", "cc_a", "cc_l", "cc_ge", "cc_le", "cc_g",
        "cc_e", "cc_ne", "cc_s", "cc_ns", "overflow", "parity",
    ];

    /// <summary>The fixed set of placeholder globals the compilable preamble must declare.</summary>
    public static IEnumerable<string> FlagGlobals => KnownFlags.Append("__unk");

    private static void WriteRaw(IlWriter w, string text)
    {
        bool neg = text.StartsWith('!');
        string id = neg ? text[1..] : text;
        if (!KnownFlags.Contains(id)) id = "__unk";
        if (neg) w.Op("!");
        w.Var(id);
    }

    private static string PtrType(int width) => width switch { 1 => "uint8_t", 2 => "uint16_t", 4 => "uint32_t", _ => "uint64_t" };

    /// <summary>Map any symbol name to a valid C identifier (used consistently at definition and call).
    /// A leading underscore or digit is moved out of the way: file-scope leading underscores are reserved
    /// and clash with compiler intrinsics (e.g. <c>__report_gsfailure</c>) and our own <c>__</c> helpers.</summary>
    public static string Sanitize(string name)
    {
        var sb = new System.Text.StringBuilder(name.Length);
        foreach (char ch in name) sb.Append(char.IsLetterOrDigit(ch) || ch == '_' ? ch : '_');
        string s = sb.Length == 0 ? "_" : sb.ToString();
        return char.IsLetter(s[0]) ? s : "f_" + s;
    }

    /// <summary>Render a leaf (non-structured) statement inline. Returns false if it produced nothing.</summary>
    public static bool WriteLeaf(IlWriter w, Stmt s, bool c, bool comp = false)
    {
        switch (s)
        {
            case AssignStmt a:
                Write(w, a.Dest, c, comp); w.Op(" = "); Write(w, a.Src, c, comp); return true;
            case CallStmt cs:
                Write(w, cs.Call, c, comp); return true;
            case ReturnStmt r:
                w.Kw("return");
                if (r.Value is not null) { w.Sp(); Write(w, r.Value, c, comp); }
                else if (comp) { w.Sp(); w.T("rax", AsmTokenKind.Register); }   // x64 return register, always declared
                return true;
            case GotoStmt g:
                w.Kw("goto"); w.Sp(); w.Sym($"loc_{g.Target:X}"); return true;
            case BranchStmt b:
                w.Kw("if"); w.Sp(); w.Op("("); Write(w, b.Cond, c, comp); w.Op(")"); w.Sp();
                w.Kw("goto"); w.Sp(); w.Sym($"loc_{b.IfTrue:X}"); return true;
            case SwitchTermStmt sw:
                w.Kw("switch"); w.Sp(); w.Op("("); Write(w, sw.Value, c, comp); w.Op(")");
                w.Sp(); w.T($"// {sw.Cases.Count} cases", AsmTokenKind.Comment); return true;
            case AsmStmt asm:
                // No portable inline-asm form, so in compilable mode it becomes a commented no-op
                // (guarding against a stray "*/" in the text that would close the comment early).
                if (comp) { w.T($"/* asm: {asm.Text.Replace("*/", "* /")} */", AsmTokenKind.Comment); return true; }
                w.Kw("__asm"); w.Op("("); w.T(asm.Text, AsmTokenKind.Comment); w.Op(")"); return true;
            default:
                return false;
        }
    }

    private static string BinStr(BinOp op) => op switch
    {
        BinOp.Add => "+", BinOp.Sub => "-", BinOp.Mul or BinOp.UMul => "*",
        BinOp.SDiv or BinOp.UDiv => "/", BinOp.SMod or BinOp.UMod => "%",
        BinOp.And => "&", BinOp.Or => "|", BinOp.Xor => "^",
        BinOp.Shl => "<<", BinOp.Shr or BinOp.Sar => ">>", _ => "?",
    };

    private static string CmpStr(CmpOp op) => op switch
    {
        CmpOp.Eq => "==", CmpOp.Ne => "!=",
        CmpOp.ULt or CmpOp.SLt => "<", CmpOp.ULe or CmpOp.SLe => "<=",
        CmpOp.UGt or CmpOp.SGt => ">", CmpOp.UGe or CmpOp.SGe => ">=",
        _ => "?",
    };

    public static (string Text, bool Hex) Num(long v)
    {
        if (v is >= -9 and <= 9) return (v.ToString(), false);
        return v < 0 ? ($"-0x{-v:X}", true) : ($"0x{v:X}", true);
    }

    /// <summary>Append the analysis's inline annotation for this statement's instruction — a referenced
    /// string (e.g. the address of a lookup table loaded by a <c>lea</c>) or a decoded API call-site (its
    /// arguments) — as a trailing comment, reusing the annotations <c>AnalysisEngine</c>/<c>ApiAnnotator</c>
    /// already keyed by instruction VA. <paramref name="seen"/> keeps it to one comment per source
    /// instruction, since one instruction can lower to several statements (e.g. a <c>push</c>).</summary>
    public static void Annotate(IlWriter w, Stmt s, IReadOnlyDictionary<ulong, string>? comments, HashSet<ulong>? seen = null)
    {
        if (comments is null || s.Va == 0) return;
        if (s is SwitchTermStmt) return;   // a switch already prints its own "// N cases" comment
        if (!comments.TryGetValue(s.Va, out var cmt)) return;
        if (seen is not null && !seen.Add(s.Va)) return;
        w.Sp(); w.T("// " + cmt, AsmTokenKind.Comment);
    }
}

/// <summary>Emits Low / Medium IL: every basic block as a labelled list of statements.</summary>
internal static class BlockEmitter
{
    public static List<DecompLine> Emit(LiftedFunction fn, IReadOnlyDictionary<ulong, string>? comments)
    {
        var w = new IlWriter();
        var seen = new HashSet<ulong>();
        // header comment
        w.T($"// {fn.Name}", AsmTokenKind.Comment);
        w.Flush(fn.Va, 0);

        foreach (var b in fn.Blocks)
        {
            string label = b.Start == fn.Va ? fn.Name : $"loc_{b.Start:X}";
            w.Sym(label); w.Op(":"); w.Flush(b.Start, 0);
            foreach (var s in b.Stmts)
            {
                if (s is NopStmt) continue;
                if (ExprWriter.WriteLeaf(w, s, c: false)) { ExprWriter.Annotate(w, s, comments, seen); w.Flush(s.Va, 1); }
            }
        }
        return w.Lines;
    }
}

/// <summary>Emits the structured tree as High IL (<paramref name="pseudoC"/> = false) or Pseudo-C
/// (true). The two differ only in surface syntax: C gets a typed signature, local declarations,
/// statement terminators and pointer dereference syntax.</summary>
internal sealed class StructEmitter
{
    private readonly IlWriter _w = new();
    private readonly bool _c;
    private readonly bool _comp;
    private readonly IReadOnlySet<ulong> _labels;
    private readonly LiftedFunction _fn;
    private readonly IReadOnlyDictionary<ulong, string>? _comments;
    private readonly HashSet<ulong> _annotated = [];

    private StructEmitter(LiftedFunction fn, IReadOnlySet<ulong> labels, bool pseudoC, bool compilable,
        IReadOnlyDictionary<ulong, string>? comments)
    {
        _fn = fn; _labels = labels; _c = pseudoC; _comp = compilable; _comments = comments;
    }

    public static List<DecompLine> Emit(LiftedFunction fn, Stmt root, IReadOnlySet<ulong> labels, bool pseudoC,
        IReadOnlyDictionary<ulong, string>? comments, bool compilable = false)
    {
        var e = new StructEmitter(fn, labels, pseudoC, compilable, comments);
        e.Signature();
        e.EmitStmt(root, 1);
        e._w.Op("}"); e._w.Flush(0, 0);
        return e._w.Lines;
    }

    private void Signature()
    {
        if (_c) { _w.Type(_comp ? "int64_t" : "int"); _w.Sp(); }
        _w.Sym(_comp ? ExprWriter.Sanitize(_fn.Name) : _fn.Name); _w.Op("(");
        // Readable C shows the recovered arguments as parameters. Compilable C uses empty parens (so call
        // sites with a different recovered arg count stay valid) and declares the args as locals below.
        if (!_comp)
        {
            var args = _fn.Variables.Where(v => v.Class == VarClass.Arg).ToList();
            for (int i = 0; i < args.Count; i++)
            {
                if (i > 0) _w.Op(", ");
                _w.Type(args[i].CType); _w.Sp(); _w.Var(args[i].Name);
            }
        }
        _w.Op(")"); _w.Sp(); _w.Op("{");
        _w.Flush(_fn.Va, 0);

        if (_c)
            foreach (var v in _fn.Variables.Where(v => _comp || v.Class == VarClass.Local))
            { _w.Type(v.CType); _w.Sp(); _w.Var(v.Name); _w.Op(";"); _w.Flush(0, 1); }
    }

    private void EmitStmt(Stmt s, int indent)
    {
        switch (s)
        {
            case SeqStmt seq:
                foreach (var it in seq.Items) EmitStmt(it, indent);
                break;

            case LabelStmt lab:
                // A label that ends a block needs a following statement in C (pre-C23); a null statement covers it.
                if (_labels.Contains(lab.Target)) { _w.Sym($"loc_{lab.Target:X}"); _w.Op(_comp ? ": ;" : ":"); _w.Flush(lab.Target, Math.Max(0, indent - 1)); }
                break;

            case IfStmt iff:
                _w.Kw("if"); _w.Sp(); _w.Op("("); ExprWriter.Write(_w, iff.Cond, _c, _comp); _w.Op(")"); _w.Sp(); _w.Op("{");
                _w.Flush(iff.Va, indent);
                EmitStmt(iff.Then, indent + 1);
                if (iff.Else is not null && !IsEmpty(iff.Else))
                {
                    _w.Op("}"); _w.Sp(); _w.Kw("else"); _w.Sp(); _w.Op("{"); _w.Flush(0, indent);
                    EmitStmt(iff.Else, indent + 1);
                }
                _w.Op("}"); _w.Flush(0, indent);
                break;

            case WhileStmt wh:
                _w.Kw("while"); _w.Sp(); _w.Op("(");
                if (wh.Cond is Const { Value: 1 }) _w.Kw("true"); else ExprWriter.Write(_w, wh.Cond, _c, _comp);
                _w.Op(")"); _w.Sp(); _w.Op("{"); _w.Flush(wh.Va, indent);
                EmitStmt(wh.Body, indent + 1);
                _w.Op("}"); _w.Flush(0, indent);
                break;

            case StructSwitchStmt sw:
                _w.Kw("switch"); _w.Sp(); _w.Op("("); ExprWriter.Write(_w, sw.Value, _c, _comp); _w.Op(")"); _w.Sp(); _w.Op("{");
                _w.Flush(sw.Va, indent);
                foreach (var cse in sw.Cases)
                {
                    if (cse.Values.Count == 0) { _w.Kw("default"); _w.Op(_comp ? ": ;" : ":"); _w.Flush(0, indent + 1); }
                    foreach (var v in cse.Values)   // stack one `case N:` label per selector value
                    {
                        _w.Kw("case"); _w.Sp(); var (t, _) = ExprWriter.Num(v); _w.Num(t); _w.Op(_comp ? ": ;" : ":");
                        _w.Flush(0, indent + 1);
                    }
                    EmitStmt(cse.Body, indent + 2);
                }
                _w.Op("}"); _w.Flush(0, indent);
                break;

            case BreakStmt: _w.Kw("break"); Semi(); _w.Flush(0, indent); break;
            case ContinueStmt: _w.Kw("continue"); Semi(); _w.Flush(0, indent); break;
            case NopStmt: break;

            default:
                if (ExprWriter.WriteLeaf(_w, s, _c, _comp)) { Semi(); ExprWriter.Annotate(_w, s, _comments, _annotated); _w.Flush(s.Va, indent); }
                break;
        }
    }

    private void Semi() { if (_c) _w.Op(";"); }

    private static bool IsEmpty(Stmt s) => s is SeqStmt { Items.Count: 0 };
}

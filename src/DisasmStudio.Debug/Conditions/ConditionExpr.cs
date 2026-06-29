namespace DisasmStudio.Debug;

/// <summary>The data a <see cref="ConditionExpr"/> reads while evaluating: the stopped thread's registers
/// (by name, full registers only — sub-registers are masked here) and a memory reader (address, size →
/// little-endian value, or null if unreadable).</summary>
public readonly struct EvalContext
{
    public required RegisterSet Regs { get; init; }
    public required Func<ulong, int, ulong?> ReadMem { get; init; }
}

/// <summary>
/// A parsed breakpoint-condition expression — e.g. <c>rax == 5</c>, <c>ecx &lt; 0x10 &amp;&amp; ZF == 1</c>,
/// <c>[rsp+8] == 0xDEAD</c>. Dependency-free: a small tokenizer + precedence-climbing parser produce an
/// immutable node tree that <see cref="Evaluate"/> walks against an <see cref="EvalContext"/>.
///
/// Grammar (low→high precedence): <c>||</c> ; <c>&amp;&amp;</c> ; <c>|</c> ; <c>^</c> ; <c>&amp;</c> ;
/// <c>== !=</c> ; <c>&lt; &lt;= &gt; &gt;=</c> ; <c>&lt;&lt; &gt;&gt;</c> ; <c>+ -</c> ; <c>* / %</c> ;
/// unary <c>- ~ !</c> ; primary. Primary = number (hex <c>0x…</c> or decimal) | register | CPU flag |
/// <c>(expr)</c> | memory deref (<c>[expr]</c> = pointer size, or <c>byte|word|dword|qword [expr]</c>).
/// Comparisons are unsigned (values are addresses) and yield 0/1; divide-by-zero and unreadable memory
/// yield 0 so evaluation never throws on a hit.
/// </summary>
public sealed class ConditionExpr
{
    private readonly Node _root;
    public string Text { get; }

    private ConditionExpr(Node root, string text) { _root = root; Text = text; }

    public ulong Evaluate(EvalContext ctx) => _root.Eval(ctx);
    public bool EvaluateBool(EvalContext ctx) => _root.Eval(ctx) != 0;

    /// <summary>Parse <paramref name="text"/>. Empty/whitespace yields <paramref name="expr"/> == null with no
    /// error (an empty condition means "unconditional"). On a syntax error returns false with a message.</summary>
    public static bool TryParse(string? text, out ConditionExpr? expr, out string? error)
    {
        expr = null; error = null;
        if (string.IsNullOrWhiteSpace(text)) return true;
        try
        {
            var p = new Parser(Tokenize(text));
            Node node = p.ParseExpression();
            p.ExpectEnd();
            expr = new ConditionExpr(node, text.Trim());
            return true;
        }
        catch (ParseException ex) { error = ex.Message; return false; }
    }

    // ---- AST ----
    private abstract class Node { public abstract ulong Eval(EvalContext ctx); }

    private sealed class Num(ulong v) : Node { public override ulong Eval(EvalContext c) => v; }

    /// <summary>A register or sub-register: read <see cref="_full"/> (resolved per bitness) and mask/shift.</summary>
    private sealed class Reg(string full64, string? full32, int shift, ulong mask) : Node
    {
        public override ulong Eval(EvalContext c)
        {
            string? name = c.Regs.Is32 ? full32 : full64;
            if (name is null) return 0;                    // e.g. an x64-only register on a 32-bit target
            return (c.Regs[name] >> shift) & mask;
        }
        private readonly string full64 = full64;
        private readonly string? full32 = full32;
        private readonly int shift = shift;
        private readonly ulong mask = mask;
    }

    private sealed class Flag(int bit) : Node
    {
        public override ulong Eval(EvalContext c) => (c.Regs[c.Regs.Is32 ? "eflags" : "rflags"] >> bit) & 1;
        private readonly int bit = bit;
    }

    /// <summary><c>size &lt; 0</c> means pointer size (resolved from bitness at eval).</summary>
    private sealed class Mem(Node addr, int size) : Node
    {
        public override ulong Eval(EvalContext c)
        {
            int sz = size < 0 ? (c.Regs.Is32 ? 4 : 8) : size;
            return c.ReadMem(addr.Eval(c), sz) ?? 0;
        }
        private readonly Node addr = addr;
        private readonly int size = size;
    }

    private sealed class Unary(char op, Node x) : Node
    {
        public override ulong Eval(EvalContext c)
        {
            ulong v = x.Eval(c);
            return op switch { '-' => 0UL - v, '~' => ~v, _ => v == 0 ? 1UL : 0UL };  // '!'
        }
        private readonly char op = op;
        private readonly Node x = x;
    }

    private sealed class Bin(string op, Node l, Node r) : Node
    {
        public override ulong Eval(EvalContext c)
        {
            // Short-circuit the logicals.
            if (op == "&&") return (l.Eval(c) != 0 && r.Eval(c) != 0) ? 1UL : 0UL;
            if (op == "||") return (l.Eval(c) != 0 || r.Eval(c) != 0) ? 1UL : 0UL;
            ulong a = l.Eval(c), b = r.Eval(c);
            return op switch
            {
                "+" => a + b,
                "-" => a - b,
                "*" => a * b,
                "/" => b == 0 ? 0 : a / b,
                "%" => b == 0 ? 0 : a % b,
                "&" => a & b,
                "|" => a | b,
                "^" => a ^ b,
                "<<" => b >= 64 ? 0 : a << (int)b,
                ">>" => b >= 64 ? 0 : a >> (int)b,
                "==" => a == b ? 1UL : 0,
                "!=" => a != b ? 1UL : 0,
                "<" => a < b ? 1UL : 0,
                "<=" => a <= b ? 1UL : 0,
                ">" => a > b ? 1UL : 0,
                ">=" => a >= b ? 1UL : 0,
                _ => 0,
            };
        }
        private readonly string op = op;
        private readonly Node l = l;
        private readonly Node r = r;
    }

    // ---- tokenizer ----
    private enum TokKind { Num, Ident, Op, LParen, RParen, LBracket, RBracket, End }
    private readonly record struct Tok(TokKind Kind, string Text, ulong Value);

    private sealed class ParseException(string msg) : Exception(msg);

    private static List<Tok> Tokenize(string s)
    {
        var toks = new List<Tok>();
        int i = 0;
        while (i < s.Length)
        {
            char ch = s[i];
            if (char.IsWhiteSpace(ch)) { i++; continue; }

            if (ch == '(') { toks.Add(new(TokKind.LParen, "(", 0)); i++; continue; }
            if (ch == ')') { toks.Add(new(TokKind.RParen, ")", 0)); i++; continue; }
            if (ch == '[') { toks.Add(new(TokKind.LBracket, "[", 0)); i++; continue; }
            if (ch == ']') { toks.Add(new(TokKind.RBracket, "]", 0)); i++; continue; }

            // number: 0x… hex or decimal
            if (char.IsDigit(ch))
            {
                int start = i;
                if (ch == '0' && i + 1 < s.Length && (s[i + 1] is 'x' or 'X'))
                {
                    i += 2;
                    int hs = i;
                    while (i < s.Length && Uri.IsHexDigit(s[i])) i++;
                    if (i == hs) throw new ParseException("malformed hex literal");
                    // ulong.TryParse (not Convert.ToUInt64) so an over-large literal returns a clean parse error
                    // instead of throwing OverflowException out of TryParse.
                    if (!ulong.TryParse(s.AsSpan(hs, i - hs), System.Globalization.NumberStyles.HexNumber,
                                        System.Globalization.CultureInfo.InvariantCulture, out ulong hv))
                        throw new ParseException($"invalid or too-large hex literal '{s[start..i]}'");
                    toks.Add(new(TokKind.Num, s[start..i], hv));
                }
                else
                {
                    while (i < s.Length && char.IsDigit(s[i])) i++;
                    if (!ulong.TryParse(s[start..i], out ulong dv)) throw new ParseException($"invalid number '{s[start..i]}'");
                    toks.Add(new(TokKind.Num, s[start..i], dv));
                }
                continue;
            }

            // identifier: register / flag / size keyword
            if (char.IsLetter(ch) || ch == '_')
            {
                int start = i;
                while (i < s.Length && (char.IsLetterOrDigit(s[i]) || s[i] == '_')) i++;
                toks.Add(new(TokKind.Ident, s[start..i], 0));
                continue;
            }

            // operators (longest match first)
            string two = i + 1 < s.Length ? s.Substring(i, 2) : "";
            if (two is "&&" or "||" or "==" or "!=" or "<=" or ">=" or "<<" or ">>")
            {
                toks.Add(new(TokKind.Op, two, 0)); i += 2; continue;
            }
            if ("+-*/%&|^<>!~".IndexOf(ch) >= 0)
            {
                toks.Add(new(TokKind.Op, ch.ToString(), 0)); i++; continue;
            }
            throw new ParseException($"unexpected character '{ch}'");
        }
        toks.Add(new(TokKind.End, "", 0));
        return toks;
    }

    // ---- parser (recursive descent, precedence-climbing) ----
    private sealed class Parser(List<Tok> toks)
    {
        private int _i;
        private Tok Cur => toks[_i];
        private Tok Next() => toks[_i++];
        private bool IsOp(string op) => Cur.Kind == TokKind.Op && Cur.Text == op;

        public void ExpectEnd()
        {
            if (Cur.Kind != TokKind.End) throw new ParseException($"unexpected '{Cur.Text}'");
        }

        public Node ParseExpression() => ParseBinary(0);

        // Operator precedence tiers, lowest first.
        private static readonly string[][] Tiers =
        [
            ["||"], ["&&"], ["|"], ["^"], ["&"], ["==", "!="],
            ["<", "<=", ">", ">="], ["<<", ">>"], ["+", "-"], ["*", "/", "%"],
        ];

        private Node ParseBinary(int tier)
        {
            if (tier >= Tiers.Length) return ParseUnary();
            Node left = ParseBinary(tier + 1);
            while (Cur.Kind == TokKind.Op && Array.IndexOf(Tiers[tier], Cur.Text) >= 0)
            {
                string op = Next().Text;
                Node right = ParseBinary(tier + 1);
                left = new Bin(op, left, right);
            }
            return left;
        }

        private Node ParseUnary()
        {
            if (IsOp("-") || IsOp("~") || IsOp("!"))
            {
                char op = Next().Text[0];
                return new Unary(op, ParseUnary());
            }
            return ParsePrimary();
        }

        private Node ParsePrimary()
        {
            Tok t = Cur;
            switch (t.Kind)
            {
                case TokKind.Num:
                    Next();
                    return new Num(t.Value);

                case TokKind.LParen:
                {
                    Next();
                    Node e = ParseExpression();
                    if (Cur.Kind != TokKind.RParen) throw new ParseException("expected ')'");
                    Next();
                    return e;
                }

                case TokKind.LBracket:
                    return ParseMem(-1);   // pointer-size deref

                case TokKind.Ident:
                {
                    string id = t.Text;
                    // size-prefixed memory deref: byte/word/dword/qword [ptr] [ ... ]
                    if (SizeOf(id) is int sz)
                    {
                        Next();
                        if (Cur.Kind == TokKind.Ident && Cur.Text.Equals("ptr", StringComparison.OrdinalIgnoreCase)) Next();
                        if (Cur.Kind != TokKind.LBracket) throw new ParseException($"expected '[' after '{id}'");
                        return ParseMem(sz);
                    }
                    Next();
                    if (FlagBit(id) is int bit) return new Flag(bit);
                    if (Registers.TryGetValue(id.ToLowerInvariant(), out var rd))
                        return new Reg(rd.Full64, rd.Full32, rd.Shift, rd.Mask);
                    throw new ParseException($"unknown register or flag '{id}'");
                }

                default:
                    throw new ParseException(t.Kind == TokKind.End ? "unexpected end of expression" : $"unexpected '{t.Text}'");
            }
        }

        private Node ParseMem(int size)
        {
            Next();   // consume '['
            Node addr = ParseExpression();
            if (Cur.Kind != TokKind.RBracket) throw new ParseException("expected ']'");
            Next();
            return new Mem(addr, size);
        }
    }

    private static int? SizeOf(string id) => id.ToLowerInvariant() switch
    {
        "byte" => 1, "word" => 2, "dword" => 4, "qword" => 8, _ => null,
    };

    private static int? FlagBit(string id) => id.ToUpperInvariant() switch
    {
        "CF" => 0, "PF" => 2, "AF" => 4, "ZF" => 6, "SF" => 7, "TF" => 8, "IF" => 9, "DF" => 10, "OF" => 11,
        _ => null,
    };

    // ---- register name table ----
    private readonly record struct RegDesc(string Full64, string? Full32, int Shift, ulong Mask);

    private static readonly Dictionary<string, RegDesc> Registers = BuildRegisters();

    private static Dictionary<string, RegDesc> BuildRegisters()
    {
        var d = new Dictionary<string, RegDesc>(StringComparer.OrdinalIgnoreCase);

        // The four legacy GP registers with high-byte aliases.
        void Legacy(char letter, string r64, string e32)
        {
            d[r64] = new(r64, null, 0, ulong.MaxValue);
            d[e32] = new(r64, e32, 0, 0xFFFFFFFF);
            d[$"{letter}x"] = new(r64, e32, 0, 0xFFFF);
            d[$"{letter}l"] = new(r64, e32, 0, 0xFF);
            d[$"{letter}h"] = new(r64, e32, 8, 0xFF);
        }
        Legacy('a', "rax", "eax");
        Legacy('b', "rbx", "ebx");
        Legacy('c', "rcx", "ecx");
        Legacy('d', "rdx", "edx");

        // si/di/bp/sp: 16-bit name + REX low-byte (x64-only).
        void Index(string r64, string e32, string w16, string l8)
        {
            d[r64] = new(r64, null, 0, ulong.MaxValue);
            d[e32] = new(r64, e32, 0, 0xFFFFFFFF);
            d[w16] = new(r64, e32, 0, 0xFFFF);
            d[l8] = new(r64, null, 0, 0xFF);   // sil/dil/bpl/spl exist only with REX (x64)
        }
        Index("rsi", "esi", "si", "sil");
        Index("rdi", "edi", "di", "dil");
        Index("rbp", "ebp", "bp", "bpl");
        Index("rsp", "esp", "sp", "spl");

        // r8..r15 (x64-only): full + d/w/b.
        for (int n = 8; n <= 15; n++)
        {
            string r = $"r{n}";
            d[r] = new(r, null, 0, ulong.MaxValue);
            d[$"{r}d"] = new(r, null, 0, 0xFFFFFFFF);
            d[$"{r}w"] = new(r, null, 0, 0xFFFF);
            d[$"{r}b"] = new(r, null, 0, 0xFF);
        }

        // instruction pointer + flags (full register).
        d["rip"] = new("rip", null, 0, ulong.MaxValue);
        d["eip"] = new("rip", "eip", 0, 0xFFFFFFFF);
        d["rflags"] = new("rflags", "eflags", 0, ulong.MaxValue);
        d["eflags"] = new("rflags", "eflags", 0, 0xFFFFFFFF);

        // segment selectors.
        foreach (string seg in new[] { "cs", "ds", "es", "fs", "gs", "ss" })
            d[seg] = new(seg, seg, 0, 0xFFFF);

        return d;
    }
}

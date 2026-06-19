using Iced.Intel;

namespace DisasmStudio.Core.Disasm;

/// <summary>A coarse token class the UI maps to a soft colour. The trailing kinds are used by the
/// decompiler's IL / Pseudo-C output (a C type, a recovered variable, an inline comment).</summary>
public enum AsmTokenKind { Text, Mnemonic, Register, Number, Punctuation, Keyword, Prefix, Symbol, Type, Variable, Comment }

/// <summary>One coloured run of formatted assembly text.</summary>
public readonly record struct AsmToken(string Text, AsmTokenKind Kind);

/// <summary>Captures the formatter's output as classified token runs instead of one flat string.</summary>
internal sealed class TokenOutput : FormatterOutput
{
    public readonly List<AsmToken> Tokens = [];
    public void Reset() => Tokens.Clear();

    public override void Write(string text, FormatterTextKind kind) => Tokens.Add(new AsmToken(text, Map(kind)));

    private static AsmTokenKind Map(FormatterTextKind kind) => kind switch
    {
        FormatterTextKind.Mnemonic => AsmTokenKind.Mnemonic,
        FormatterTextKind.Keyword or FormatterTextKind.Directive or FormatterTextKind.Decorator => AsmTokenKind.Keyword,
        FormatterTextKind.Prefix => AsmTokenKind.Prefix,
        FormatterTextKind.Register => AsmTokenKind.Register,
        FormatterTextKind.Number => AsmTokenKind.Number,
        FormatterTextKind.Punctuation or FormatterTextKind.Operator => AsmTokenKind.Punctuation,
        FormatterTextKind.Function or FormatterTextKind.FunctionAddress or FormatterTextKind.Label
            or FormatterTextKind.LabelAddress or FormatterTextKind.Data or FormatterTextKind.SelectorValue => AsmTokenKind.Symbol,
        _ => AsmTokenKind.Text,
    };
}

/// <summary>Substitutes a known name for an operand address (function / loc_ / import).</summary>
public sealed class NameResolver(IReadOnlyDictionary<ulong, string> names) : ISymbolResolver
{
    public bool TryGetSymbol(in Instruction instruction, int operand, int instructionOperand,
        ulong address, int addressSize, out SymbolResult symbol)
    {
        if (names.TryGetValue(address, out var name))
        {
            symbol = new SymbolResult(address, name);
            return true;
        }
        symbol = default;
        return false;
    }
}

/// <summary>
/// Formats instructions into coloured token runs, with operand addresses replaced by names from
/// the analysis. A clean Intel syntax (lowercase, 0x hex) close to Binary Ninja's listing. The
/// shared formatter/output are not thread-safe — one per view/thread.
/// </summary>
public sealed class AsmFormatter
{
    private readonly Formatter _fmt;
    private readonly TokenOutput _out = new();

    public AsmFormatter(IReadOnlyDictionary<ulong, string>? names = null)
    {
        _fmt = new IntelFormatter(names is null ? null : new NameResolver(names));
        var o = _fmt.Options;
        o.UppercaseHex = false;
        o.HexPrefix = "0x";
        o.HexSuffix = "";
        o.SpaceAfterOperandSeparator = true;
        o.ShowSymbolAddress = false;
        o.BranchLeadingZeroes = false;
    }

    /// <summary>Format one instruction into reusable token runs (valid until the next call).</summary>
    public IReadOnlyList<AsmToken> Format(in Instruction instr)
    {
        _out.Reset();
        _fmt.Format(instr, _out);
        return _out.Tokens;
    }

    /// <summary>Format one instruction to a plain string.</summary>
    public string FormatText(in Instruction instr)
    {
        _out.Reset();
        _fmt.Format(instr, _out);
        var sb = new System.Text.StringBuilder();
        foreach (var t in _out.Tokens) sb.Append(t.Text);
        return sb.ToString();
    }
}

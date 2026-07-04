using DisasmStudio.Core.Disasm;
using DisasmStudio.Core.IL;

namespace DisasmStudio.Managed;

/// <summary>
/// A small, self-contained C#/ILAsm lexer that turns decompiler output text into coloured
/// <see cref="DecompLine"/>s reusing the shared <see cref="AsmTokenKind"/> palette. This is deliberately a
/// text-level tokenizer rather than a hook into ICSharpCode's syntax-tree writer: it is far more robust across
/// decompiler versions and gives near-identical colouring (keywords, comments, string/char literals, numbers).
/// Managed lines have no address, so every <see cref="DecompLine"/> uses VA 0 (the view renders a blank gutter).
/// </summary>
public static class CodeTokenizer
{
    public static IReadOnlyList<DecompLine> Tokenize(string text, bool il)
    {
        var keywords = il ? IlKeywords : CSharpKeywords;
        var lines = new List<DecompLine>();
        bool inBlockComment = false;
        bool inVerbatim = false;   // C# @"…" strings span lines

        foreach (var raw in SplitLines(text))
        {
            var toks = new List<AsmToken>();
            LexLine(raw, keywords, il, toks, ref inBlockComment, ref inVerbatim);
            lines.Add(new DecompLine(0, toks, 0));
        }
        return lines;
    }

    private static IEnumerable<string> SplitLines(string text)
    {
        // Normalise CRLF/CR/LF without allocating a split array for huge inputs.
        int start = 0;
        for (int i = 0; i < text.Length; i++)
        {
            char c = text[i];
            if (c == '\n') { yield return text.Substring(start, i - start).TrimEnd('\r'); start = i + 1; }
        }
        if (start <= text.Length) yield return text.Substring(start).TrimEnd('\r');
    }

    private static void LexLine(string s, HashSet<string> keywords, bool il, List<AsmToken> toks,
        ref bool inBlockComment, ref bool inVerbatim)
    {
        int i = 0, n = s.Length;

        while (i < n)
        {
            if (inBlockComment)
            {
                int end = s.IndexOf("*/", i, StringComparison.Ordinal);
                if (end < 0) { Emit(toks, s[i..], AsmTokenKind.Comment); return; }
                Emit(toks, s.Substring(i, end + 2 - i), AsmTokenKind.Comment);
                i = end + 2; inBlockComment = false; continue;
            }
            if (inVerbatim)
            {
                int j = i;
                while (j < n)
                {
                    if (s[j] == '"') { if (j + 1 < n && s[j + 1] == '"') { j += 2; continue; } break; }
                    j++;
                }
                if (j >= n) { Emit(toks, s[i..], AsmTokenKind.Symbol); return; }   // still open next line
                Emit(toks, s.Substring(i, j + 1 - i), AsmTokenKind.Symbol);
                i = j + 1; inVerbatim = false; continue;
            }

            char c = s[i];

            // whitespace run
            if (char.IsWhiteSpace(c)) { int j = i; while (j < n && char.IsWhiteSpace(s[j])) j++; Emit(toks, s[i..j], AsmTokenKind.Text); i = j; continue; }

            // comments
            if (c == '/' && i + 1 < n && s[i + 1] == '/') { Emit(toks, s[i..], AsmTokenKind.Comment); return; }
            if (c == '/' && i + 1 < n && s[i + 1] == '*')
            {
                int end = s.IndexOf("*/", i + 2, StringComparison.Ordinal);
                if (end < 0) { Emit(toks, s[i..], AsmTokenKind.Comment); inBlockComment = true; return; }
                Emit(toks, s.Substring(i, end + 2 - i), AsmTokenKind.Comment); i = end + 2; continue;
            }

            // verbatim / interpolated / plain string
            if (c == '@' && i + 1 < n && s[i + 1] == '"')
            {
                int j = i + 2;
                while (j < n) { if (s[j] == '"') { if (j + 1 < n && s[j + 1] == '"') { j += 2; continue; } break; } j++; }
                if (j >= n) { Emit(toks, s[i..], AsmTokenKind.Symbol); inVerbatim = true; return; }
                Emit(toks, s.Substring(i, j + 1 - i), AsmTokenKind.Symbol); i = j + 1; continue;
            }
            if (c == '"' || (c == '$' && i + 1 < n && s[i + 1] == '"'))
            {
                int j = c == '$' ? i + 2 : i + 1;
                while (j < n && s[j] != '"') { if (s[j] == '\\') j++; j++; }
                j = Math.Min(j + 1, n);
                Emit(toks, s.Substring(i, j - i), AsmTokenKind.Symbol); i = j; continue;
            }
            if (c == '\'')
            {
                int j = i + 1;
                while (j < n && s[j] != '\'') { if (s[j] == '\\') j++; j++; }
                j = Math.Min(j + 1, n);
                Emit(toks, s.Substring(i, j - i), AsmTokenKind.Symbol); i = j; continue;
            }

            // numbers (incl. hex, IL offsets, suffixes, underscores)
            if (char.IsDigit(c) || (c == '.' && i + 1 < n && char.IsDigit(s[i + 1])))
            {
                int j = i;
                while (j < n && (char.IsLetterOrDigit(s[j]) || s[j] == '.' || s[j] == '_' || s[j] == 'x' || s[j] == 'X')) j++;
                Emit(toks, s[i..j], AsmTokenKind.Number); i = j; continue;
            }

            // identifiers / keywords (IL directives begin with '.')
            if (char.IsLetter(c) || c == '_' || (il && c == '.'))
            {
                int j = i + ((il && c == '.') ? 1 : 0);
                while (j < n && (char.IsLetterOrDigit(s[j]) || s[j] == '_')) j++;
                if (j == i) j++;   // a lone '.' in IL that isn't a directive
                string word = s[i..j];
                var kind = keywords.Contains(word) ? AsmTokenKind.Keyword
                         : (il && word.StartsWith('.')) ? AsmTokenKind.Keyword
                         : AsmTokenKind.Text;
                Emit(toks, word, kind); i = j; continue;
            }

            // punctuation / operators (single char)
            Emit(toks, c.ToString(), AsmTokenKind.Punctuation); i++;
        }
    }

    private static void Emit(List<AsmToken> toks, string text, AsmTokenKind kind)
    {
        if (text.Length != 0) toks.Add(new AsmToken(text, kind));
    }

    private static readonly HashSet<string> CSharpKeywords = new(StringComparer.Ordinal)
    {
        "abstract","as","base","bool","break","byte","case","catch","char","checked","class","const","continue",
        "decimal","default","delegate","do","double","else","enum","event","explicit","extern","false","finally",
        "fixed","float","for","foreach","goto","if","implicit","in","int","interface","internal","is","lock","long",
        "namespace","new","null","object","operator","out","override","params","private","protected","public",
        "readonly","ref","return","sbyte","sealed","short","sizeof","stackalloc","static","string","struct","switch",
        "this","throw","true","try","typeof","uint","ulong","unchecked","unsafe","ushort","using","virtual","void",
        "volatile","while","var","get","set","value","add","remove","yield","async","await","nameof","when","where",
        "global","dynamic","partial","record","init","nint","nuint",
    };

    // ILAsm opcodes + the common directives (directives also caught by the leading-'.' rule above).
    private static readonly HashSet<string> IlKeywords = new(StringComparer.Ordinal)
    {
        "nop","ldarg","ldarga","ldloc","ldloca","stloc","starg","ldc","ldnull","ldstr","ldfld","ldflda","stfld",
        "ldsfld","ldsflda","stsfld","ldelem","ldelema","stelem","ldlen","newarr","newobj","call","calli","callvirt",
        "ret","br","brtrue","brfalse","beq","bne","bge","bgt","ble","blt","switch","add","sub","mul","div","rem",
        "and","or","xor","shl","shr","neg","not","conv","box","unbox","castclass","isinst","throw","rethrow","leave",
        "endfinally","endfilter","ldtoken","ldftn","ldvirtftn","initobj","cpobj","ldobj","stobj","sizeof","dup","pop",
        "cgt","clt","ceq","ldind","stind","volatile","tail","constrained","readonly","unaligned",
        "instance","void","managed","cil","hidebysig","specialname","rtspecialname","virtual","abstract","private",
        "public","family","assembly","static","extends","implements","default","valuetype","class","string","object",
        "int8","int16","int32","int64","uint8","uint16","uint32","uint64","float32","float64","bool","char","native",
    };
}

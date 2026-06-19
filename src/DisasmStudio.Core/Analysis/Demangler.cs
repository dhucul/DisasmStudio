using System.Runtime.InteropServices;
using System.Text;

namespace DisasmStudio.Core.Analysis;

/// <summary>
/// Demangles C++ symbol names to readable signatures. MSVC names (<c>?…</c>) go through the OS's
/// official <c>UnDecorateSymbolName</c>; Itanium names (<c>_Z…</c>, used by GCC/Clang/MinGW and ELF)
/// go through a compact managed demangler covering the common forms. Anything it can't parse is
/// returned unchanged, so the result is always either a clean name or the original. Results are cached.
/// </summary>
public static class Demangler
{
    private static readonly object _lock = new();
    private static readonly Dictionary<string, string> _cache = [];

    public static string Demangle(string name)
    {
        if (string.IsNullOrEmpty(name)) return name;
        bool msvc = name[0] == '?';
        bool itanium = name.StartsWith("_Z", StringComparison.Ordinal) || name.StartsWith("__Z", StringComparison.Ordinal);
        if (!msvc && !itanium) return name;

        lock (_lock)
        {
            if (_cache.TryGetValue(name, out var hit)) return hit;
            string result = (msvc ? Msvc(name) : Itanium(name)) ?? name;
            _cache[name] = result;
            return result;
        }
    }

    // ---- MSVC ----
    [DllImport("dbghelp.dll", CharSet = CharSet.Ansi, ExactSpelling = true)]
    private static extern int UnDecorateSymbolName(string name, StringBuilder output, int maxLen, uint flags);

    private static string? Msvc(string name)
    {
        if (!OperatingSystem.IsWindows()) return null;
        const uint flags = 0x0002 | 0x0004 | 0x0080 | 0x0200; // NO_MS_KEYWORDS|NO_FUNCTION_RETURNS|NO_ACCESS_SPECIFIERS|NO_MEMBER_TYPE
        try
        {
            var sb = new StringBuilder(4096);
            int n = UnDecorateSymbolName(name, sb, sb.Capacity, flags);
            string s = sb.ToString();
            return n > 0 && s.Length > 0 && s != name ? s : null;
        }
        catch { return null; }
    }

    // ---- Itanium ----
    private static string? Itanium(string name)
    {
        int start = name.StartsWith("__Z", StringComparison.Ordinal) ? 3 : 2;
        try
        {
            var p = new Itan(name, start);
            string n = p.Encoding();
            return string.IsNullOrEmpty(n) || p.Failed ? null : n;
        }
        catch { return null; }
    }

    /// <summary>A small recursive-descent Itanium demangler — common forms only; bails on the rest.</summary>
    private sealed class Itan(string s, int i)
    {
        private int _i = i;
        private readonly List<string> _subs = [];
        public bool Failed { get; private set; }

        private char Cur => _i < s.Length ? s[_i] : '\0';

        public string Encoding()
        {
            string name = Name();
            if (Failed) return "";
            // A bare function type may follow (parameter list).
            if (_i < s.Length)
            {
                var args = new List<string>();
                while (_i < s.Length && !Failed) { string t = Type(); if (t.Length == 0) break; args.Add(t); }
                if (args.Count == 1 && args[0] == "void") return name + "()";
                if (args.Count > 0) return name + "(" + string.Join(", ", args) + ")";
            }
            return name;
        }

        private string Name()
        {
            return Cur switch
            {
                'N' => Nested(),
                'S' => Substitution(),
                _ => Unqualified(),
            };
        }

        private string Nested()
        {
            _i++; // 'N'
            while (Cur is 'r' or 'V' or 'K') _i++;   // cv-qualifiers on the implicit this
            var parts = new List<string>();
            string acc = "";
            while (Cur != 'E' && Cur != '\0' && !Failed)
            {
                string comp = Cur == 'S' ? Substitution() : Cur == 'I' ? TemplateArgs() : Unqualified(parts.Count > 0 ? parts[^1] : null);
                if (Failed) return "";
                if (comp.StartsWith('<')) { if (parts.Count > 0) parts[^1] += comp; }   // template args attach to prev
                else parts.Add(comp);
                acc = string.Join("::", parts);
                _subs.Add(acc);
            }
            if (Cur == 'E') _i++;
            return acc;
        }

        private string Unqualified(string? enclosingClass = null)
        {
            char c = Cur;
            if (c == 'C' && _i + 1 < s.Length && s[_i + 1] is '1' or '2' or '3') { _i += 2; return enclosingClass ?? "{ctor}"; }
            if (c == 'D' && _i + 1 < s.Length && s[_i + 1] is '0' or '1' or '2') { _i += 2; return "~" + (enclosingClass ?? "{dtor}"); }
            if (char.IsDigit(c)) return SourceName();
            Failed = true;
            return "";
        }

        private string SourceName()
        {
            int n = 0;
            while (char.IsDigit(Cur)) { n = n * 10 + (Cur - '0'); _i++; }
            if (n <= 0 || _i + n > s.Length) { Failed = true; return ""; }
            string name = s.Substring(_i, n);
            _i += n;
            return name;
        }

        private string TemplateArgs()
        {
            _i++; // 'I'
            var args = new List<string>();
            while (Cur != 'E' && Cur != '\0' && !Failed) args.Add(Type());
            if (Cur == 'E') _i++;
            return "<" + string.Join(", ", args) + ">";
        }

        private string Substitution()
        {
            _i++; // 'S'
            switch (Cur)
            {
                case 't': _i++; return "std::" + (char.IsDigit(Cur) || Cur is 'N' or 'S' ? Name() : Unqualified());
                case 's': _i++; return "std::string";
                case 'a': _i++; return "std::allocator";
                case 'b': _i++; return "std::basic_string";
                case 'i': _i++; return "std::istream";
                case 'o': _i++; return "std::ostream";
                case 'd': _i++; return "std::iostream";
                case '_': _i++; return _subs.Count > 0 ? _subs[0] : "";
                default:
                    int n = 0; bool any = false;
                    while (Cur is (>= '0' and <= '9') or (>= 'A' and <= 'Z')) { int d = Cur <= '9' ? Cur - '0' : Cur - 'A' + 10; n = n * 36 + d; _i++; any = true; }
                    if (any && Cur == '_') { _i++; int idx = n + 1; return idx < _subs.Count ? _subs[idx] : ""; }
                    Failed = true; return "";
            }
        }

        private string Type()
        {
            char c = Cur;
            switch (c)
            {
                case 'P': _i++; return Type() + " *";
                case 'R': _i++; return Type() + " &";
                case 'O': _i++; return Type() + " &&";
                case 'K': _i++; return "const " + Type();
                case 'V': _i++; return "volatile " + Type();
                case 'r': _i++; return Type();
                case 'N': { string t = Nested(); _subs.Add(t); return t; }
                case 'S': { string t = Substitution(); return t; }
                case 'I': return TemplateArgs();
                case 'F': return FunctionType();
            }
            if (char.IsDigit(c)) { string t = SourceName(); _subs.Add(t); return t; }
            string b = Builtin(c);
            if (b.Length > 0) { _i++; return b; }
            Failed = true;
            return "";
        }

        private string FunctionType()
        {
            _i++; // 'F'
            var args = new List<string>();
            string ret = Type();
            while (Cur != 'E' && Cur != '\0' && !Failed) args.Add(Type());
            if (Cur == 'E') _i++;
            return $"{ret} (*)({string.Join(", ", args)})";
        }

        private static string Builtin(char c) => c switch
        {
            'v' => "void", 'b' => "bool", 'c' => "char", 'a' => "signed char", 'h' => "unsigned char",
            's' => "short", 't' => "unsigned short", 'i' => "int", 'j' => "unsigned int",
            'l' => "long", 'm' => "unsigned long", 'x' => "long long", 'y' => "unsigned long long",
            'n' => "__int128", 'o' => "unsigned __int128", 'f' => "float", 'd' => "double", 'e' => "long double",
            'w' => "wchar_t", 'z' => "...", 'D' => "", _ => "",
        };
    }
}

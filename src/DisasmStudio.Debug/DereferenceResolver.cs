using System.Text;

namespace DisasmStudio.Debug;

/// <summary>
/// x64dbg-style value annotation: given a register/stack/memory value, read the debuggee and describe
/// what it points to — a known symbol (<c>module.func</c> / <c>name</c>), a string, or a pointer to one
/// of those (rendered as a single hop). Used by the registers, stack and memory-dump panels.
/// </summary>
public sealed class DereferenceResolver(DebuggerEngine eng, IReadOnlyDictionary<ulong, string> names, IReadOnlyList<ModuleInfo> modules)
{
    private readonly int _ptr = eng.Is32 ? 4 : 8;

    public string Describe(ulong value)
    {
        if (value == 0) return "";
        if (SymbolFor(value) is string s) return s;
        if (TryString(value) is string str) return str;
        if (ReadPtr(value) is ulong p && p != 0)
        {
            if (SymbolFor(p) is string s2) return "-> " + s2;
            if (TryString(p) is string str2) return "-> " + str2;
        }
        return "";
    }

    private string? SymbolFor(ulong a)
    {
        if (names.TryGetValue(a, out var n)) return n;
        ModuleInfo? best = null;
        foreach (var m in modules) if (m.Base <= a && (best is null || m.Base > best.Base)) best = m;
        if (best is not null && eng.IsExecutable(a)) return $"{best.Name}+0x{a - best.Base:X}";
        return null;
    }

    private ulong? ReadPtr(ulong a)
    {
        var b = eng.ReadMemory(a, _ptr);
        if (b.Length < _ptr) return null;
        return _ptr == 8 ? BitConverter.ToUInt64(b, 0) : BitConverter.ToUInt32(b, 0);
    }

    private string? TryString(ulong a)
    {
        var b = eng.ReadMemory(a, 64);
        if (b.Length < 8) return null;

        int len = 0;
        while (len < b.Length && b[len] is >= 0x20 and < 0x7F) len++;
        if (len >= 4) return Quote(Encoding.ASCII.GetString(b, 0, Math.Min(len, 48)), len > 48, wide: false);

        int wl = 0;
        while (wl + 1 < b.Length && b[wl + 1] == 0 && b[wl] is >= 0x20 and < 0x7F) wl += 2;
        if (wl >= 8)
        {
            var sb = new StringBuilder();
            for (int i = 0; i < wl && i < 96; i += 2) sb.Append((char)b[i]);
            return Quote(sb.ToString(), wl > 96, wide: true);
        }
        return null;
    }

    private static string Quote(string s, bool trunc, bool wide) => $"{(wide ? "L" : "")}\"{s}{(trunc ? "…" : "")}\"";
}

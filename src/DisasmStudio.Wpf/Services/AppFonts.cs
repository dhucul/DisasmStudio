using System.Windows.Media;

namespace DisasmStudio.Wpf.Services;

/// <summary>Shared application typography with safe system fallbacks.</summary>
public static class AppFonts
{
    public static readonly FontFamily Ui =
        new("Segoe UI Variable Text, Segoe UI");

    // The no-ligature JetBrains family keeps disassembly bytes, addresses, and mnemonics
    // character-for-character while improving differentiation of 0/O, 1/l/I, and punctuation.
    public static readonly FontFamily Code =
        new("JetBrains Mono NL, JetBrains Mono, Cascadia Mono, Consolas");
}

using System.Windows.Media;
using DisasmStudio.Core.Disasm;

namespace DisasmStudio.Wpf.Services;

/// <summary>
/// A soft, low-saturation palette for the disassembly views — frozen brushes (cheap to reuse on
/// every render) tuned for long reading sessions on the slate-dark surfaces. Token colours stay
/// gentle so nothing fights for attention; structure (addresses, separators) is dim by design.
/// </summary>
public static class SyntaxTheme
{
    private static SolidColorBrush B(byte r, byte g, byte b)
    {
        var br = new SolidColorBrush(Color.FromRgb(r, g, b));
        br.Freeze();
        return br;
    }

    // Surfaces / structure
    public static readonly Brush Background = B(0x0E, 0x11, 0x16);
    public static readonly Brush GutterBg = B(0x12, 0x16, 0x1D);
    public static readonly Brush Separator = B(0x29, 0x31, 0x3D);
    public static readonly Brush Selection = B(0x24, 0x33, 0x49);
    public static readonly Brush CurrentLine = B(0x1B, 0x22, 0x30);

    // Columns
    public static readonly Brush Address = B(0x6B, 0x8F, 0xD6);   // soft periwinkle
    public static readonly Brush Bytes = B(0x5E, 0x6B, 0x7A);     // dim grey
    public static readonly Brush FuncName = B(0xD7, 0xBA, 0x7D);  // soft gold (function headers)

    // Token kinds (gentle, distinct hues)
    public static readonly Brush Mnemonic = B(0x9C, 0xB4, 0xE8);  // soft periwinkle-blue
    public static readonly Brush Register = B(0x8F, 0xBC, 0xBB);  // soft teal
    public static readonly Brush Number = B(0xD8, 0xB9, 0x89);    // muted gold
    public static readonly Brush Symbol = B(0x9B, 0xC9, 0x95);    // soft green (named targets)
    public static readonly Brush Keyword = B(0xC9, 0x9F, 0xD9);   // soft mauve
    public static readonly Brush Prefix = B(0xC9, 0x9F, 0xD9);
    public static readonly Brush Punctuation = B(0x79, 0x82, 0x8F); // muted grey
    public static readonly Brush Text = B(0xE6, 0xEA, 0xF0);      // primary text
    public static readonly Brush Comment = B(0x5E, 0x6B, 0x7A);   // dim grey-blue
    public static readonly Brush TypeName = B(0x6F, 0xB3, 0xA8);  // soft cyan-green (C types)
    public static readonly Brush Variable = B(0xC9, 0xD2, 0xDE);  // light slate (recovered vars)

    // Edge colours for the graph view (muted)
    public static readonly Brush EdgeTaken = B(0x7F, 0xA8, 0x7B);    // soft green (branch taken)
    public static readonly Brush EdgeFall = B(0x79, 0x82, 0x8F);     // grey (fall-through)
    public static readonly Brush EdgeJump = B(0x6B, 0x8F, 0xD6);     // blue (unconditional)
    public static readonly Brush EdgeSwitch = B(0xB4, 0x8E, 0xAD);   // soft violet (switch/jump-table case)
    public static readonly Brush BlockBg = B(0x16, 0x1B, 0x22);
    public static readonly Brush BlockBorder = B(0x3A, 0x44, 0x52);
    public static readonly Brush BlockHeader = B(0x1B, 0x22, 0x30);

    public static Brush BrushFor(AsmTokenKind kind) => kind switch
    {
        AsmTokenKind.Mnemonic => Mnemonic,
        AsmTokenKind.Register => Register,
        AsmTokenKind.Number => Number,
        AsmTokenKind.Symbol => Symbol,
        AsmTokenKind.Keyword => Keyword,
        AsmTokenKind.Prefix => Prefix,
        AsmTokenKind.Punctuation => Punctuation,
        AsmTokenKind.Type => TypeName,
        AsmTokenKind.Variable => Variable,
        AsmTokenKind.Comment => Comment,
        _ => Text,
    };
}

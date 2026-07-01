using System.Windows.Media;
using DisasmStudio.Core.Disasm;

namespace DisasmStudio.Wpf.Services;

/// <summary>
/// A soft, low-saturation palette for the disassembly views — frozen brushes (cheap to reuse on
/// every render) tuned for long reading sessions on the Arc-Dark surfaces. Token colours stay
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

    // Surfaces / structure (Arc-Dark cool greys)
    public static readonly Brush Background = B(0x2B, 0x2E, 0x39);   // deepest — view bg (matches the window)
    public static readonly Brush GutterBg = B(0x33, 0x37, 0x3F);     // line-number gutter
    public static readonly Brush Separator = B(0x45, 0x4C, 0x5C);    // column / function rules
    public static readonly Brush Selection = B(0x3A, 0x56, 0x78);    // blue-tinted selected row
    public static readonly Brush CurrentLine = B(0x38, 0x3C, 0x4A);  // current-line band
    public static readonly Brush CurrentIp = B(0x4A, 0x46, 0x34);    // amber row — the debuggee's current instruction
    public static readonly Brush BreakpointDot = B(0xE2, 0x4C, 0x56);   // arc red — software breakpoint marker
    public static readonly Brush HwBreakpointDot = B(0x7F, 0xD0, 0xE0); // cyan — hardware breakpoint marker
    public static readonly Brush CoveredInstr = B(0x2E, 0x4A, 0x3A);  // green — an executed (covered) instruction row

    // Columns
    public static readonly Brush Address = B(0x7F, 0xB0, 0xEA);   // arc blue
    public static readonly Brush Bytes = B(0x6B, 0x73, 0x85);     // dim grey-blue
    public static readonly Brush FuncName = B(0xE8, 0xA2, 0x5A);  // warm gold (function headers)

    // Token kinds (Arc-harmonized, distinct hues)
    public static readonly Brush Mnemonic = B(0x8F, 0xB6, 0xEE);  // blue
    public static readonly Brush Register = B(0x7F, 0xD0, 0xC4);  // teal
    public static readonly Brush Number = B(0xC7, 0x9B, 0xE0);    // violet
    public static readonly Brush Symbol = B(0x9F, 0xD0, 0x7A);    // green (named targets)
    public static readonly Brush Keyword = B(0x5F, 0xBF, 0xD6);   // cyan
    public static readonly Brush Prefix = B(0x5F, 0xBF, 0xD6);
    public static readonly Brush Punctuation = B(0x78, 0x80, 0x8F); // muted grey-blue
    public static readonly Brush Text = B(0xD3, 0xDA, 0xE3);      // primary text
    public static readonly Brush Comment = B(0x6E, 0x76, 0x86);   // dim grey-blue
    public static readonly Brush TypeName = B(0x66, 0xC9, 0xBC);  // cyan-green (C types)
    public static readonly Brush Variable = B(0xC9, 0xD0, 0xDA);  // light slate (recovered vars)

    // Edge colours for the graph view (Arc-harmonized)
    public static readonly Brush EdgeTaken = B(0x9F, 0xD0, 0x7A);    // green (branch taken)
    public static readonly Brush EdgeFall = B(0x78, 0x80, 0x8F);     // grey-blue (fall-through)
    public static readonly Brush EdgeJump = B(0x6F, 0xA8, 0xE8);     // blue (unconditional)
    public static readonly Brush EdgeSwitch = B(0xC7, 0x9B, 0xE0);   // violet (switch/jump-table case)
    public static readonly Brush BlockBg = B(0x38, 0x3C, 0x4A);
    public static readonly Brush BlockBorder = B(0x56, 0x5E, 0x70);
    public static readonly Brush BlockHeader = B(0x40, 0x45, 0x52);

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

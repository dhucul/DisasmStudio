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

    // Surfaces / structure (deepest Polar Night)
    public static readonly Brush Background = B(0x1B, 0x20, 0x28);   // deepest — view bg (matches the window)
    public static readonly Brush GutterBg = B(0x21, 0x27, 0x2F);     // line-number gutter
    public static readonly Brush Separator = B(0x40, 0x49, 0x59);    // column / function rules
    public static readonly Brush Selection = B(0x36, 0x49, 0x6A);    // blue-tinted selected row
    public static readonly Brush CurrentLine = B(0x27, 0x2D, 0x37);  // current-line band
    public static readonly Brush CurrentIp = B(0x52, 0x4B, 0x33);    // amber row — the debuggee's current instruction
    public static readonly Brush BreakpointDot = B(0xD8, 0x5F, 0x6A);   // bright red — software breakpoint marker
    public static readonly Brush HwBreakpointDot = B(0x93, 0xDC, 0xEE); // bright frost cyan — hardware breakpoint marker
    public static readonly Brush CoveredInstr = B(0x3C, 0x4D, 0x30);  // green — an executed (covered) instruction row

    // Columns
    public static readonly Brush Address = B(0x88, 0xAE, 0xDE);   // bright frost blue
    public static readonly Brush Bytes = B(0x6E, 0x7C, 0x97);     // dim grey-blue
    public static readonly Brush FuncName = B(0xF2, 0xD0, 0x8A);  // bright gold (function headers)

    // Token kinds (peak-vivid aurora / frost, distinct hues)
    public static readonly Brush Mnemonic = B(0x9C, 0xBE, 0xF2);  // bright blue
    public static readonly Brush Register = B(0x9B, 0xDA, 0xD7);  // bright teal
    public static readonly Brush Number = B(0xD4, 0x9A, 0xCE);    // bright purple
    public static readonly Brush Symbol = B(0xB9, 0xD9, 0x98);    // bright green (named targets)
    public static readonly Brush Keyword = B(0x93, 0xDC, 0xEE);   // bright frost cyan
    public static readonly Brush Prefix = B(0x93, 0xDC, 0xEE);
    public static readonly Brush Punctuation = B(0x78, 0x86, 0xA2); // muted grey-blue
    public static readonly Brush Text = B(0xF2, 0xF5, 0xFA);      // bright — primary text
    public static readonly Brush Comment = B(0x6B, 0x78, 0x94);   // dim grey-blue
    public static readonly Brush TypeName = B(0x90, 0xD6, 0xC9);  // bright cyan-green (C types)
    public static readonly Brush Variable = B(0xE4, 0xEA, 0xF3);  // light slate (recovered vars)

    // Edge colours for the graph view (peak-vivid aurora)
    public static readonly Brush EdgeTaken = B(0xB4, 0xDC, 0x90);    // bright green (branch taken)
    public static readonly Brush EdgeFall = B(0x78, 0x86, 0xA2);     // grey-blue (fall-through)
    public static readonly Brush EdgeJump = B(0x8A, 0xAE, 0xEC);     // bright blue (unconditional)
    public static readonly Brush EdgeSwitch = B(0xCD, 0x96, 0xC4);   // bright violet (switch/jump-table case)
    public static readonly Brush BlockBg = B(0x27, 0x2D, 0x37);
    public static readonly Brush BlockBorder = B(0x4F, 0x59, 0x6B);
    public static readonly Brush BlockHeader = B(0x34, 0x3C, 0x4A);

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

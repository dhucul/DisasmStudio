using System.Windows.Media;
using DisasmStudio.Core.Disasm;

namespace DisasmStudio.Wpf.Services;

/// <summary>
/// The disassembly views' syntax palette — a thin semantic mapping of token/structure roles onto the
/// shared <see cref="Palette"/>. Frozen brushes are cheap to reuse on every render. Chrome and
/// debugger signals use the full-strength theme colours; code tokens use a quieter, lower-chroma
/// hierarchy so important instructions and values lead, while raw bytes and comments recede.
/// </summary>
public static class SyntaxTheme
{
    // Surfaces / structure
    public static readonly Brush Background = Palette.BaseBrush;      // view bg (matches the window)
    public static readonly Brush GutterBg = Palette.MantleBrush;      // line-number gutter
    public static readonly Brush Separator = Palette.Surface1Brush;   // column / function rules
    public static readonly Brush Selection = Palette.SelectionBrush;  // lavender-tinted selected row
    public static readonly Brush CurrentLine = Palette.Surface0Brush; // current-line band
    public static readonly Brush CurrentIp = Palette.CurrentIpBrush;  // amber row — the debuggee's current instruction
    public static readonly Brush BreakpointDot = Palette.RedBrush;      // software breakpoint marker
    public static readonly Brush HwBreakpointDot = Palette.SkyBrush;    // hardware breakpoint marker
    public static readonly Brush CoveredInstr = Palette.CoveredBrush;   // an executed (covered) instruction row

    // Addresses and function names are important values; raw bytes are supporting detail.
    public static readonly Brush Address = B(0x87, 0xA9, 0xCE);
    public static readonly Brush Bytes = B(0x68, 0x7F, 0x96);
    public static readonly Brush FuncName = B(0xC1, 0x9A, 0x68);

    // Executable tokens remain comfortably prominent. Punctuation is secondary and
    // comments are muted, keeping dense listings readable without flattening the hierarchy.
    public static readonly Brush Mnemonic = B(0x86, 0xA7, 0xCC);
    public static readonly Brush Register = B(0x73, 0xAA, 0x9F);
    public static readonly Brush Number = B(0xC1, 0x9A, 0x68);
    public static readonly Brush Symbol = B(0x6F, 0xAE, 0x91);
    public static readonly Brush Keyword = B(0xAE, 0x9A, 0xC3);
    public static readonly Brush Prefix = B(0xAE, 0x9A, 0xC3);
    public static readonly Brush Punctuation = B(0x78, 0x8F, 0xA6);
    public static readonly Brush Text = B(0x9F, 0xB5, 0xCA);
    public static readonly Brush Comment = B(0x68, 0x7F, 0x96);
    public static readonly Brush TypeName = B(0x71, 0xA4, 0xB1);
    public static readonly Brush Variable = B(0x84, 0x9C, 0xAF);

    // Graph view: the debugger bands are brightened (rows sit over the lighter block surface), and the
    // current-IP row also gets a bright warm outline so it can't be missed against a covered run of rows.
    public static readonly Brush CurrentIpGraph = Palette.CurrentIpGraphBrush;
    public static readonly Brush CoveredInstrGraph = Palette.CoveredGraphBrush;
    public static readonly Pen CurrentIpGraphOutline = FrozenPen(Palette.PeachBrush, 1.5);

    // Edge colours for the graph view
    public static readonly Brush EdgeTaken = Palette.GreenBrush;     // branch taken
    public static readonly Brush EdgeFall = Palette.Overlay1Brush;   // fall-through
    public static readonly Brush EdgeJump = Palette.BlueBrush;       // unconditional
    public static readonly Brush EdgeSwitch = Palette.MauveBrush;    // switch/jump-table case
    public static readonly Brush BlockBg = Palette.Surface0Brush;
    public static readonly Brush BlockBorder = Palette.Surface2Brush;
    public static readonly Brush BlockHeader = Palette.Surface1Brush;

    private static Pen FrozenPen(Brush brush, double thickness)
    {
        var p = new Pen(brush, thickness);
        p.Freeze();
        return p;
    }

    private static Brush B(byte r, byte g, byte b)
    {
        var brush = new SolidColorBrush(Color.FromRgb(r, g, b));
        brush.Freeze();
        return brush;
    }

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

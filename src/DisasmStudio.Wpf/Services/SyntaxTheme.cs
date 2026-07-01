using System.Windows.Media;
using DisasmStudio.Core.Disasm;

namespace DisasmStudio.Wpf.Services;

/// <summary>
/// The disassembly views' syntax palette — a thin semantic mapping of token/structure roles onto the
/// shared <see cref="Palette"/> (the single flavour source). Frozen brushes, cheap to reuse on every
/// render; token colours stay gentle so nothing fights for attention. To recolour, edit Palette; to
/// re-map which token uses which hue, edit here.
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

    // Columns
    public static readonly Brush Address = Palette.BlueBrush;
    public static readonly Brush Bytes = Palette.Overlay1Brush;   // dim
    public static readonly Brush FuncName = Palette.YellowBrush;  // function headers

    // Token kinds (harmonized, distinct hues)
    public static readonly Brush Mnemonic = Palette.BlueBrush;
    public static readonly Brush Register = Palette.TealBrush;
    public static readonly Brush Number = Palette.PeachBrush;
    public static readonly Brush Symbol = Palette.GreenBrush;     // named targets
    public static readonly Brush Keyword = Palette.MauveBrush;
    public static readonly Brush Prefix = Palette.MauveBrush;
    public static readonly Brush Punctuation = Palette.Overlay2Brush;
    public static readonly Brush Text = Palette.TextBrush;
    public static readonly Brush Comment = Palette.Overlay0Brush;
    public static readonly Brush TypeName = Palette.SkyBrush;         // C types
    public static readonly Brush Variable = Palette.Subtext1Brush;    // recovered vars

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

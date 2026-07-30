using System;
using System.Windows.Media;

namespace DisasmStudio.Wpf.Services;

/// <summary>
/// The single source of truth for the app's Arctic Circuit colour theme.
///
/// To retune the theme, edit only the token block below plus the hand-tuned debugger bands.
/// Everything else is derived (accent tints are computed by blending)
/// and every consumer reads from here: the chrome dictionary (<c>Themes/Dark.xaml</c> via
/// <c>{x:Static}</c>), <see cref="SyntaxTheme"/>, <c>Controls/HexView</c>, and the code-built dialogs.
/// The role → token mapping lives in those consumers and is stable across flavours; see
/// <c>catppuccin.md</c> for the full mapping.
/// </summary>
public static class Palette
{
    private static Color C(byte r, byte g, byte b) => Color.FromRgb(r, g, b);

    // ─────────────────────────  ARCTIC CIRCUIT TOKENS  ─────────────────────────
    //  Layered navy surfaces provide the structure. Icy cyan marks navigation and selection;
    //  periwinkle carries addresses, while mint is reserved for successful/live-debug state.
    public static readonly Color Rosewater = C(0xF0, 0xCD, 0xD1);
    public static readonly Color Flamingo  = C(0xF0, 0xA4, 0xAE);
    public static readonly Color Pink      = C(0xE6, 0x8F, 0xDB);
    public static readonly Color Mauve     = C(0xB9, 0x94, 0xF6);
    public static readonly Color Red       = C(0xFF, 0x6B, 0x7A);
    public static readonly Color Maroon    = C(0xE9, 0x78, 0x89);
    public static readonly Color Peach     = C(0xF4, 0xB8, 0x60);
    public static readonly Color Yellow    = C(0xF0, 0xCE, 0x72);
    public static readonly Color Green     = C(0x56, 0xD6, 0xA7);
    public static readonly Color Teal      = C(0x55, 0xD8, 0xC1);
    public static readonly Color Sky       = C(0x45, 0xD7, 0xF0);
    public static readonly Color Sapphire  = C(0x5E, 0xBB, 0xE6);
    public static readonly Color Blue      = C(0x7F, 0xA7, 0xFF);
    public static readonly Color Lavender  = C(0xA0, 0xA7, 0xFF);
    // Neutral typography follows a deliberate hierarchy over Base:
    // primary (~8.1:1), secondary (~5.4:1), muted (~4.1:1), disabled (~3.2:1).
    // None of these use pure white or black.
    public static readonly Color Text         = C(0x9F, 0xB5, 0xCA);
    public static readonly Color Subtext1     = C(0x7E, 0x95, 0xAB);
    public static readonly Color Subtext0     = C(0x68, 0x7F, 0x96);
    public static readonly Color Overlay2     = C(0x74, 0x8B, 0xA2);
    public static readonly Color Overlay1     = C(0x60, 0x76, 0x8C);
    public static readonly Color Overlay0     = C(0x58, 0x6D, 0x82);
    public static readonly Color TextDisabled = C(0x58, 0x6D, 0x82);
    public static readonly Color Surface2  = C(0x1C, 0x2E, 0x45);
    public static readonly Color Surface1  = C(0x18, 0x28, 0x3B);
    public static readonly Color Surface0  = C(0x16, 0x24, 0x37);
    public static readonly Color Base      = C(0x11, 0x1C, 0x2B);
    public static readonly Color Mantle    = C(0x0E, 0x17, 0x23);
    public static readonly Color Crust     = C(0x09, 0x11, 0x1B);

    // Hand-tuned debugger bands (cyan / mint over the dark base).
    public static readonly Color CurrentIpBand = C(0x16, 0x4A, 0x63);
    public static readonly Color CoveredBand   = C(0x19, 0x3F, 0x38);
    // Brighter variants for the graph view, where rows sit over the lighter block surface (Surface0)
    // instead of Base — the base bands are near-invisible there, so these lift the luminance/chroma.
    public static readonly Color CurrentIpBandGraph = C(0x1D, 0x60, 0x7B);
    public static readonly Color CoveredBandGraph   = C(0x22, 0x55, 0x48);

    // The single UI accent.
    public static readonly Color Accent = Sky;
    // ───────────────────────────  end swap point  ───────────────────────────

    // Derived accent / semantic tints — computed, so a flavour swap needs no edits here.
    public static readonly Color AccentHover   = Mix(Accent, Colors.White, 0.25);
    public static readonly Color AccentPressed = Mix(Accent, Base, 0.30);
    public static readonly Color AccentSoft    = Mix(Base, Accent, 0.20);
    public static readonly Color Selection     = Mix(Base, Accent, 0.28);
    public static readonly Color SuccessSoft   = Mix(Base, Green, 0.16);
    public static readonly Color WarnSoft      = Mix(Base, Peach, 0.14);
    public static readonly Color DangerSoft    = Mix(Base, Red, 0.16);
    // Descriptive text stays quiet; important addresses, values, warnings, and state
    // labels sit above it without reaching the intensity of the full-strength accents.
    public static readonly Color FontMuted       = C(0x68, 0x7F, 0x96);
    public static readonly Color PanelAccentText = C(0x87, 0xA9, 0xCE);
    public static readonly Color PanelWarmText   = C(0xC1, 0x9A, 0x68);
    public static readonly Color SuccessText     = C(0x67, 0xB9, 0x9C);
    public static readonly Color WarnText        = C(0xD4, 0xA1, 0x5D);
    public static readonly Color DangerText      = C(0xE5, 0x8A, 0x94);

    private static Color Mix(Color a, Color b, double t)
    {
        byte L(byte x, byte y) => (byte)Math.Round(x * (1 - t) + y * t);
        return Color.FromRgb(L(a.R, b.R), L(a.G, b.G), L(a.B, b.B));
    }

    // ─────────────────────────  Frozen brushes for code consumers  ─────────────────────────
    private static SolidColorBrush F(Color c) { var b = new SolidColorBrush(c); b.Freeze(); return b; }

    public static readonly SolidColorBrush TextBrush     = F(Text);
    public static readonly SolidColorBrush Subtext1Brush = F(Subtext1);
    public static readonly SolidColorBrush TextDisabledBrush = F(TextDisabled);
    public static readonly SolidColorBrush Overlay2Brush = F(Overlay2);
    public static readonly SolidColorBrush Overlay1Brush = F(Overlay1);
    public static readonly SolidColorBrush Overlay0Brush = F(Overlay0);
    public static readonly SolidColorBrush BaseBrush     = F(Base);
    public static readonly SolidColorBrush MantleBrush   = F(Mantle);
    public static readonly SolidColorBrush CrustBrush    = F(Crust);
    public static readonly SolidColorBrush Surface0Brush = F(Surface0);
    public static readonly SolidColorBrush Surface1Brush = F(Surface1);
    public static readonly SolidColorBrush Surface2Brush = F(Surface2);
    public static readonly SolidColorBrush AccentBrush   = F(Accent);
    public static readonly SolidColorBrush FontMutedBrush = F(FontMuted);
    public static readonly SolidColorBrush PanelAccentTextBrush = F(PanelAccentText);
    public static readonly SolidColorBrush PanelWarmTextBrush = F(PanelWarmText);
    public static readonly SolidColorBrush SuccessTextBrush = F(SuccessText);
    public static readonly SolidColorBrush WarnTextBrush = F(WarnText);
    public static readonly SolidColorBrush DangerTextBrush = F(DangerText);
    public static readonly SolidColorBrush BlueBrush     = F(Blue);
    public static readonly SolidColorBrush SkyBrush      = F(Sky);
    public static readonly SolidColorBrush TealBrush     = F(Teal);
    public static readonly SolidColorBrush GreenBrush    = F(Green);
    public static readonly SolidColorBrush YellowBrush   = F(Yellow);
    public static readonly SolidColorBrush PeachBrush    = F(Peach);
    public static readonly SolidColorBrush RedBrush      = F(Red);
    public static readonly SolidColorBrush MauveBrush    = F(Mauve);
    public static readonly SolidColorBrush SelectionBrush = F(Selection);
    public static readonly SolidColorBrush CurrentIpBrush = F(CurrentIpBand);
    public static readonly SolidColorBrush CoveredBrush  = F(CoveredBand);
    public static readonly SolidColorBrush CurrentIpGraphBrush = F(CurrentIpBandGraph);
    public static readonly SolidColorBrush CoveredGraphBrush   = F(CoveredBandGraph);

    /// <summary>Hex-view selection wash — the accent at ~40% alpha.</summary>
    public static readonly SolidColorBrush SelOverlayBrush =
        Freeze(new SolidColorBrush(Color.FromArgb(0x66, Accent.R, Accent.G, Accent.B)));

    /// <summary>Hex-view "changed since last step" wash — red at ~40% alpha, so it composes
    /// with the selection / edit washes while debugging.</summary>
    public static readonly SolidColorBrush ChangedByteBrush =
        Freeze(new SolidColorBrush(Color.FromArgb(0x66, Red.R, Red.G, Red.B)));

    /// <summary>Solid soft-red tint (Base↔Red) for a "changed since last step" cell in the
    /// register / stack grids, where a solid fill reads cleaner than a translucent wash.</summary>
    public static readonly SolidColorBrush DangerSoftBrush = F(DangerSoft);

    private static SolidColorBrush Freeze(SolidColorBrush b) { b.Freeze(); return b; }
}

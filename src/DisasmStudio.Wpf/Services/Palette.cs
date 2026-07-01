using System;
using System.Windows.Media;

namespace DisasmStudio.Wpf.Services;

/// <summary>
/// The single source of truth for the app's colour theme (Catppuccin Frappé).
///
/// To switch flavour, edit ONLY the token block below — the 26 named Catppuccin colours plus the
/// two hand-tuned debugger bands. Everything else is derived (accent tints are computed by blending)
/// and every consumer reads from here: the chrome dictionary (<c>Themes/Dark.xaml</c> via
/// <c>{x:Static}</c>), <see cref="SyntaxTheme"/>, <c>Controls/HexView</c>, and the code-built dialogs.
/// The role → token mapping lives in those consumers and is stable across flavours; see
/// <c>catppuccin.md</c> for the full mapping.
/// </summary>
public static class Palette
{
    private static Color C(byte r, byte g, byte b) => Color.FromRgb(r, g, b);

    // ─────────────────────────  FLAVOUR TOKENS — the swap point  ─────────────────────────
    //  Catppuccin Frappé (https://github.com/catppuccin/catppuccin). Swap these to change
    //  flavour (e.g. Mocha: Base #1E1E2E / Surface0 #313244 / Text #CDD6F4 / Lavender #B4BEFE …).
    public static readonly Color Rosewater = C(0xF2, 0xD5, 0xCF);
    public static readonly Color Flamingo  = C(0xEE, 0xBE, 0xBE);
    public static readonly Color Pink      = C(0xF4, 0xB8, 0xE4);
    public static readonly Color Mauve     = C(0xCA, 0x9E, 0xE6);
    public static readonly Color Red       = C(0xE7, 0x82, 0x84);
    public static readonly Color Maroon    = C(0xEA, 0x99, 0x9C);
    public static readonly Color Peach     = C(0xEF, 0x9F, 0x76);
    public static readonly Color Yellow    = C(0xE5, 0xC8, 0x90);
    public static readonly Color Green     = C(0xA6, 0xD1, 0x89);
    public static readonly Color Teal      = C(0x81, 0xC8, 0xBE);
    public static readonly Color Sky       = C(0x99, 0xD1, 0xDB);
    public static readonly Color Sapphire  = C(0x85, 0xC1, 0xDC);
    public static readonly Color Blue      = C(0x8C, 0xAA, 0xEE);
    public static readonly Color Lavender  = C(0xBA, 0xBB, 0xF1);
    public static readonly Color Text      = C(0xC6, 0xD0, 0xF5);
    public static readonly Color Subtext1  = C(0xB5, 0xBF, 0xE2);
    public static readonly Color Subtext0  = C(0xA5, 0xAD, 0xCE);
    public static readonly Color Overlay2  = C(0x94, 0x9C, 0xBB);
    public static readonly Color Overlay1  = C(0x83, 0x8B, 0xA7);
    public static readonly Color Overlay0  = C(0x73, 0x79, 0x94);
    public static readonly Color Surface2  = C(0x62, 0x68, 0x80);
    public static readonly Color Surface1  = C(0x51, 0x57, 0x6D);
    public static readonly Color Surface0  = C(0x41, 0x45, 0x59);
    public static readonly Color Base      = C(0x30, 0x34, 0x46);
    public static readonly Color Mantle    = C(0x29, 0x2C, 0x3C);
    public static readonly Color Crust     = C(0x23, 0x26, 0x34);

    // Hand-tuned debugger bands (warm amber / green over the dark base; retune per flavour).
    public static readonly Color CurrentIpBand = C(0x4E, 0x4A, 0x35);
    public static readonly Color CoveredBand   = C(0x38, 0x4A, 0x3C);
    // Brighter variants for the graph view, where rows sit over the lighter block surface (Surface0)
    // instead of Base — the base bands are near-invisible there, so these lift the luminance/chroma.
    public static readonly Color CurrentIpBandGraph = C(0x5E, 0x57, 0x3E);
    public static readonly Color CoveredBandGraph   = C(0x46, 0x66, 0x4C);

    // The single UI accent (re-point here for a non-Lavender accent).
    public static readonly Color Accent = Lavender;
    // ───────────────────────────  end swap point  ───────────────────────────

    // Derived accent / semantic tints — computed, so a flavour swap needs no edits here.
    public static readonly Color AccentHover   = Mix(Accent, Colors.White, 0.25);
    public static readonly Color AccentPressed = Mix(Accent, Base, 0.30);
    public static readonly Color AccentSoft    = Mix(Base, Accent, 0.20);
    public static readonly Color Selection     = Mix(Base, Accent, 0.28);
    public static readonly Color SuccessSoft   = Mix(Base, Green, 0.16);
    public static readonly Color WarnSoft      = Mix(Base, Peach, 0.14);
    public static readonly Color DangerSoft    = Mix(Base, Red, 0.16);

    private static Color Mix(Color a, Color b, double t)
    {
        byte L(byte x, byte y) => (byte)Math.Round(x * (1 - t) + y * t);
        return Color.FromRgb(L(a.R, b.R), L(a.G, b.G), L(a.B, b.B));
    }

    // ─────────────────────────  Frozen brushes for code consumers  ─────────────────────────
    private static SolidColorBrush F(Color c) { var b = new SolidColorBrush(c); b.Freeze(); return b; }

    public static readonly SolidColorBrush TextBrush     = F(Text);
    public static readonly SolidColorBrush Subtext1Brush = F(Subtext1);
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

    private static SolidColorBrush Freeze(SolidColorBrush b) { b.Freeze(); return b; }
}

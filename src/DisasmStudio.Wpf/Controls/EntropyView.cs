using System;
using System.Globalization;
using System.Windows;
using System.Windows.Input;
using System.Windows.Media;
using DisasmStudio.Wpf.Services;
using DisasmStudio.Wpf.ViewModels;

namespace DisasmStudio.Wpf.Controls;

/// <summary>
/// The Entropy tab's graph: byte-entropy (Shannon, 0…8 bits/byte) plotted against file offset, left→right.
/// The area under the curve is heat-coloured — blue (low) → green → yellow → red (≈8, the hallmark of
/// compressed / encrypted / packed data). Horizontal gridlines mark 0/2/4/6/8; faint dashed vertical
/// dividers mark section boundaries. Hovering reports the offset, value, and containing section. Pure
/// vector drawing (crisp at any DPI), after <see cref="MemoryMapStrip"/>'s approach.
/// </summary>
public sealed class EntropyView : FrameworkElement
{
    private EntropyData? _data;

    private const double LeftPad = 30, RightPad = 8, TopPad = 8, BottomPad = 6;

    private readonly Typeface _typeface =
        new(new FontFamily("Cascadia Mono, Consolas"), FontStyles.Normal, FontWeights.Normal, FontStretches.Normal);
    private const double FontSize = 10.0;

    /// <summary>Replace the plotted data (null clears) and repaint.</summary>
    public void SetData(EntropyData? data)
    {
        _data = data;
        ToolTip = null;
        InvalidateVisual();
    }

    // ── Heat ramp: cached frozen brushes, blue (low) → green → yellow → peach → red (high) ──
    private static readonly (double T, Color C)[] Stops =
    [
        (0.00, Palette.Blue), (0.45, Palette.Green), (0.65, Palette.Yellow),
        (0.82, Palette.Peach), (1.00, Palette.Red),
    ];
    private const int Buckets = 64;
    private static readonly SolidColorBrush[] HeatBrushes = BuildHeat();

    private static SolidColorBrush[] BuildHeat()
    {
        var arr = new SolidColorBrush[Buckets + 1];
        for (int i = 0; i <= Buckets; i++)
        {
            var b = new SolidColorBrush(HeatColor(i / (double)Buckets));
            b.Freeze();
            arr[i] = b;
        }
        return arr;
    }

    private static Color HeatColor(double t)
    {
        t = Math.Clamp(t, 0, 1);
        for (int i = 1; i < Stops.Length; i++)
            if (t <= Stops[i].T)
            {
                var (t0, c0) = Stops[i - 1];
                var (t1, c1) = Stops[i];
                double u = t1 > t0 ? (t - t0) / (t1 - t0) : 0;
                return Lerp(c0, c1, u);
            }
        return Stops[^1].C;
    }

    private static Color Lerp(Color a, Color b, double t)
    {
        byte L(byte x, byte y) => (byte)Math.Round(x * (1 - t) + y * t);
        return Color.FromRgb(L(a.R, b.R), L(a.G, b.G), L(a.B, b.B));
    }

    private static Brush HeatBrush(double frac) => HeatBrushes[(int)Math.Round(Math.Clamp(frac, 0, 1) * Buckets)];

    protected override void OnRender(DrawingContext dc)
    {
        double w = ActualWidth, h = ActualHeight;
        dc.DrawRectangle(Palette.BaseBrush, null, new Rect(0, 0, w, h));   // full-bleed → whole control is hit-testable
        var d = _data;
        if (d is null || d.Blocks.Length == 0 || d.FileLength <= 0 ||
            w <= LeftPad + RightPad + 4 || h <= TopPad + BottomPad + 4)
            return;

        double dpi = VisualTreeHelper.GetDpi(this).PixelsPerDip;
        double plotL = LeftPad, plotT = TopPad, plotR = w - RightPad, plotB = h - BottomPad;
        double plotW = plotR - plotL, plotH = plotB - plotT;
        long len = d.FileLength;

        // Heat-filled columns: one per device pixel, height ∝ entropy, colour ∝ entropy. Build the curve's
        // top edge as a geometry in the same pass so it can be stroked crisply over the fill.
        var topGeo = new StreamGeometry();
        using (var ctx = topGeo.Open())
        {
            bool started = false;
            int cols = (int)Math.Floor(plotW);
            for (int px = 0; px < cols; px++)
            {
                double xFrac = (px + 0.5) / plotW;
                long off = (long)(xFrac * len);
                int bi = (int)Math.Clamp(off / d.BlockSize, 0, d.Blocks.Length - 1);
                double frac = d.Blocks[bi] / 8.0;
                double colH = frac * plotH;
                double x = plotL + px, yTop = plotB - colH;
                dc.DrawRectangle(HeatBrush(frac), null, new Rect(x, yTop, 1.0, colH));
                if (!started) { ctx.BeginFigure(new Point(x, yTop), false, false); started = true; }
                else ctx.LineTo(new Point(x, yTop), true, false);
            }
        }
        topGeo.Freeze();

        // Gridlines + Y labels at 0/2/4/6/8 (over the fill so they read).
        var gridPen = new Pen(Palette.Surface2Brush, 0.6);
        for (int e = 0; e <= 8; e += 2)
        {
            double y = plotB - (e / 8.0) * plotH;
            dc.DrawLine(gridPen, new Point(plotL, y), new Point(plotR, y));
            var ft = new FormattedText(e.ToString(CultureInfo.InvariantCulture), CultureInfo.InvariantCulture,
                FlowDirection.LeftToRight, _typeface, FontSize, Palette.Overlay1Brush, dpi);
            dc.DrawText(ft, new Point(plotL - ft.Width - 4, y - ft.Height / 2));
        }

        dc.DrawGeometry(null, new Pen(Palette.Overlay0Brush, 1), topGeo);   // crisp curve edge

        // Section dividers + labels (drawn in file-offset space so they line up with the plot).
        var divPen = new Pen(Palette.Overlay0Brush, 0.6) { DashStyle = new DashStyle([2, 2], 0) };
        var bounds = d.Bounds;
        for (int i = 0; i < bounds.Count; i++)
        {
            double x = plotL + (double)bounds[i].Start / len * plotW;
            if (x < plotL) x = plotL;
            if (x > plotR) continue;
            dc.DrawLine(divPen, new Point(x, plotT), new Point(x, plotB));

            double nextX = i + 1 < bounds.Count ? plotL + (double)bounds[i + 1].Start / len * plotW : plotR;
            double avail = Math.Max(0, Math.Min(nextX, plotR) - x - 3);
            if (avail >= 16)
            {
                var ft = new FormattedText(bounds[i].Name, CultureInfo.InvariantCulture, FlowDirection.LeftToRight,
                    _typeface, FontSize, Palette.Subtext1Brush, dpi)
                { MaxTextWidth = avail, MaxLineCount = 1, Trimming = TextTrimming.CharacterEllipsis };
                dc.DrawText(ft, new Point(x + 2, plotT + 1));
            }
        }
    }

    protected override void OnMouseMove(MouseEventArgs e)
    {
        base.OnMouseMove(e);
        var d = _data;
        double plotL = LeftPad, plotR = ActualWidth - RightPad;
        if (d is null || d.Blocks.Length == 0 || d.FileLength <= 0 || plotR <= plotL) { ToolTip = null; return; }

        double x = e.GetPosition(this).X;
        if (x < plotL || x > plotR) { ToolTip = null; return; }
        double frac = (x - plotL) / (plotR - plotL);
        long off = (long)Math.Clamp(frac * d.FileLength, 0, d.FileLength - 1);
        int bi = (int)Math.Clamp(off / d.BlockSize, 0, d.Blocks.Length - 1);
        string sec = SectionAt(d, off);
        ToolTip = $"0x{off:X}   {d.Blocks[bi]:F2} bits/byte" + (sec.Length > 0 ? $"   ({sec})" : "");
    }

    private static string SectionAt(EntropyData d, long off)
    {
        foreach (var (name, start, end) in d.Bounds)
            if (off >= start && off < end) return name;
        return "";
    }
}

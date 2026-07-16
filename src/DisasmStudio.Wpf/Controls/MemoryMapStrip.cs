using System;
using System.Collections.Generic;
using System.Globalization;
using System.Windows;
using System.Windows.Input;
using System.Windows.Media;
using DisasmStudio.Wpf.Services;
using DisasmStudio.Wpf.ViewModels;

namespace DisasmStudio.Wpf.Controls;

/// <summary>
/// The Memory Map's vertical address-space strip: one coloured block per region (section / header /
/// &lt;gap&gt;), stacked top = lowest VA → bottom = highest, sized proportionally to each region's byte
/// span. Blocks are RWX-coloured — green = executable, peach = writable, blue = read-only data,
/// grey = header, dim = gap. Click a block to select + navigate; the host keeps it in sync with the
/// companion table. Pure vector drawing (crisp at any DPI), after <see cref="HexView"/>'s approach.
/// </summary>
public sealed class MemoryMapStrip : FrameworkElement
{
    private IReadOnlyList<MemoryMapItem> _rows = [];
    private int _selected = -1;
    private int _hoverRow = -1;

    private const double MinRowPx = 5;    // a real region is never thinner than this, so it stays clickable
    private const double MinGapPx = 2;    // a gap may be thinner

    private readonly Typeface _typeface =
        new(new FontFamily("Cascadia Mono, Consolas"), FontStyles.Normal, FontWeights.Normal, FontStretches.Normal);
    private const double FontSize = 10.0;

    /// <summary>Raised (with the row index) when a block is clicked; the host navigates + selects the table row.</summary>
    public event Action<int>? RegionActivated;

    /// <summary>Replace the strip's regions (on file load / clear) and repaint.</summary>
    public void SetRegions(IReadOnlyList<MemoryMapItem> rows)
    {
        _rows = rows ?? [];
        _selected = -1;
        _hoverRow = -1;
        InvalidateVisual();
    }

    /// <summary>The highlighted block, kept in sync with the table's selected row (-1 = none).</summary>
    public int SelectedIndex
    {
        get => _selected;
        set
        {
            int v = value < 0 || value >= _rows.Count ? -1 : value;
            if (v == _selected) return;
            _selected = v;
            InvalidateVisual();
        }
    }

    private static Brush Fill(MemKind k) => k switch
    {
        MemKind.Code     => Palette.GreenBrush,
        MemKind.Writable => Palette.PeachBrush,
        MemKind.ReadOnly => Palette.BlueBrush,
        MemKind.Header   => Palette.Overlay2Brush,
        _                => Palette.Surface1Brush,   // gap — dim, reads as empty space
    };

    // Per-row vertical layout for the current height: each block's top + height. Proportional to byte span,
    // with a per-row floor so thin sections stay visible/clickable; sums exactly to the available height.
    private (double[] Tops, double[] Heights) Layout(double availH)
    {
        int n = _rows.Count;
        var tops = new double[n];
        var heights = new double[n];
        if (n == 0 || availH <= 0) return (tops, heights);

        double totalSize = 0, minSum = 0;
        for (int i = 0; i < n; i++)
        {
            totalSize += _rows[i].SizeBytes;
            minSum += _rows[i].IsGap ? MinGapPx : MinRowPx;
        }

        double y = 0;
        if (totalSize <= 0 || minSum >= availH)
        {
            // Degenerate (no span, or too many rows to honour the floors): split the height evenly.
            double h = availH / n;
            for (int i = 0; i < n; i++) { tops[i] = y; heights[i] = h; y += h; }
            return (tops, heights);
        }

        double flexible = availH - minSum;   // shared out proportionally to each region's byte span
        for (int i = 0; i < n; i++)
        {
            double min = _rows[i].IsGap ? MinGapPx : MinRowPx;
            double h = min + flexible * (_rows[i].SizeBytes / totalSize);
            tops[i] = y;
            heights[i] = h;
            y += h;
        }
        return (tops, heights);
    }

    protected override void OnRender(DrawingContext dc)
    {
        double w = ActualWidth, h = ActualHeight;
        dc.DrawRectangle(Palette.BaseBrush, null, new Rect(0, 0, w, h));   // full-bleed → the whole control is hit-testable
        if (_rows.Count == 0 || w <= 0 || h <= 0) return;

        double dpi = VisualTreeHelper.GetDpi(this).PixelsPerDip;
        var (tops, heights) = Layout(h);
        var selPen = new Pen(Palette.AccentBrush, 2);

        for (int i = 0; i < _rows.Count; i++)
        {
            var row = _rows[i];
            double top = tops[i];
            double blockH = Math.Max(1, heights[i] - 1);   // leave a 1px gutter below → visible separation
            dc.DrawRectangle(Fill(row.Kind), null, new Rect(0, top, w, blockH));

            // Label the block with its name when it's tall enough (and not a gap).
            if (!row.IsGap && blockH >= 11)
            {
                var ft = new FormattedText(row.Name, CultureInfo.InvariantCulture, FlowDirection.LeftToRight,
                    _typeface, FontSize, Palette.CrustBrush, dpi)
                {
                    MaxTextWidth = Math.Max(0, w - 6),
                    MaxLineCount = 1,
                    Trimming = TextTrimming.CharacterEllipsis,
                };
                dc.DrawText(ft, new Point(4, top + (blockH - ft.Height) / 2));
            }

            if (i == _selected)
                dc.DrawRectangle(null, selPen, new Rect(1, top + 1, Math.Max(0, w - 2), Math.Max(0, blockH - 2)));
        }
    }

    protected override void OnMouseLeftButtonDown(MouseButtonEventArgs e)
    {
        base.OnMouseLeftButtonDown(e);
        int i = RowAt(e.GetPosition(this).Y);
        if (i < 0) return;
        SelectedIndex = i;
        RegionActivated?.Invoke(i);
    }

    protected override void OnMouseMove(MouseEventArgs e)
    {
        base.OnMouseMove(e);
        int i = RowAt(e.GetPosition(this).Y);
        if (i == _hoverRow) return;
        _hoverRow = i;
        ToolTip = i < 0 ? null : $"{_rows[i].Name}   {_rows[i].Start}-{_rows[i].End}   {_rows[i].Perms}".TrimEnd();
    }

    private int RowAt(double y)
    {
        if (_rows.Count == 0) return -1;
        var (tops, heights) = Layout(ActualHeight);
        for (int i = 0; i < _rows.Count; i++)
            if (y >= tops[i] && y < tops[i] + heights[i]) return i;
        return -1;
    }
}

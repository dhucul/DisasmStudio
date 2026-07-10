using System;
using System.Globalization;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;

namespace DisasmStudio.Wpf.Controls;

/// <summary>
/// Shows a <see cref="TextBlock"/>'s <b>full</b> text as a tooltip, but only when it is
/// actually trimmed with an ellipsis. Wired in via a trigger on the implicit TextBlock
/// style (and the <c>GridCellText</c> cell style), so every list item / grid cell that
/// cuts off long text - Strings, Imports, Exports, the function list, ... - gets
/// "hover a cut-off row to read all of it", with no tooltip on text that already fits.
/// </summary>
/// <remarks>
/// The trim test runs lazily in <see cref="FrameworkElement.ToolTipOpening"/> (only on
/// hover, never during scroll) and measures the string with a <see cref="FormattedText"/>
/// rather than re-measuring the live element, so it never disturbs a virtualized list's
/// layout. The tooltip content is a plain string, rendered by the app-wide themed/wrapping
/// <c>ToolTip</c> style.
/// </remarks>
public static class TrimmedToolTip
{
    public static readonly DependencyProperty EnabledProperty =
        DependencyProperty.RegisterAttached(
            "Enabled", typeof(bool), typeof(TrimmedToolTip),
            new PropertyMetadata(false, OnEnabledChanged));

    public static void SetEnabled(DependencyObject o, bool value) => o.SetValue(EnabledProperty, value);
    public static bool GetEnabled(DependencyObject o) => (bool)o.GetValue(EnabledProperty);

    private static void OnEnabledChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        if (d is not TextBlock tb) return;
        if ((bool)e.NewValue)
        {
            // ToolTipOpening only fires when a tooltip exists; a placeholder is enough
            // (its content is replaced on open). Keep it up long enough to read a long value.
            ToolTipService.SetShowDuration(tb, 60000);
            if (tb.ToolTip == null) tb.ToolTip = string.Empty;
            tb.ToolTipOpening += OnToolTipOpening;
        }
        else
        {
            tb.ToolTipOpening -= OnToolTipOpening;
        }
    }

    private static void OnToolTipOpening(object sender, ToolTipEventArgs e)
    {
        var tb = (TextBlock)sender;
        if (!IsTrimmed(tb)) { e.Handled = true; return; }  // fits fully -> suppress the tooltip
        tb.ToolTip = tb.Text;                              // full value; themed + wrapped globally
    }

    private static bool IsTrimmed(TextBlock tb)
    {
        if (tb.TextTrimming == TextTrimming.None || string.IsNullOrEmpty(tb.Text)) return false;
        double available = tb.ActualWidth - tb.Padding.Left - tb.Padding.Right;
        if (available <= 0) return false;

        double pixelsPerDip;
        try { pixelsPerDip = VisualTreeHelper.GetDpi(tb).PixelsPerDip; }
        catch { pixelsPerDip = 1.0; }

        var formatted = new FormattedText(
            tb.Text, CultureInfo.CurrentUICulture, tb.FlowDirection,
            new Typeface(tb.FontFamily, tb.FontStyle, tb.FontWeight, tb.FontStretch),
            tb.FontSize, Brushes.Black, pixelsPerDip);

        return formatted.WidthIncludingTrailingWhitespace > available + 0.5;
    }
}

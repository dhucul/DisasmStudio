using System.Globalization;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Input;
using System.Windows.Media;
using DisasmStudio.Core.Disasm;
using DisasmStudio.Core.IL;
using DisasmStudio.Managed;
using DisasmStudio.Wpf.Services;

namespace DisasmStudio.Wpf.Controls;

/// <summary>
/// A lightweight read-only source viewer. Opens a text file (.cs, .il, …) and renders it with the same
/// DPI-correct, on-demand row rendering and syntax palette the decompiler views use — so a C# file opens as
/// readable, coloured source with line numbers instead of being disassembled as if it were machine code.
/// Colouring is via the shared <see cref="CodeTokenizer"/>; only visible rows are drawn, so large files stay
/// responsive. Ctrl+C (or the context menu) copies the whole file.
/// </summary>
public sealed class SourceViewerWindow : Window
{
    private readonly Surface _surface;
    private readonly ScrollBar _scroll;
    private IReadOnlyList<DecompLine> _lines = [];
    private string _rawText = "";
    private long _top;
    private long _caret = -1;

    private readonly Typeface _typeface =
        new(new FontFamily("Cascadia Mono, Consolas"), FontStyles.Normal, FontWeights.Normal, FontStretches.Normal);
    private const double CodeFontSize = 13.0;
    private double _rowHeight = 16;
    private double _charWidth = 8;
    private int _lineNoDigits = 4;

    public SourceViewerWindow(string path)
    {
        Title = "Source — " + Path.GetFileName(path);
        Width = 900;
        Height = 700;
        Background = SyntaxTheme.Background;

        var grid = new Grid();
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        _surface = new Surface(this);
        Grid.SetColumn(_surface, 0);
        grid.Children.Add(_surface);
        _scroll = new ScrollBar { Orientation = Orientation.Vertical, SmallChange = 1 };
        _scroll.Scroll += (_, e) => { _top = (long)Math.Max(0, e.NewValue); _surface.InvalidateVisual(); };
        Grid.SetColumn(_scroll, 1);
        grid.Children.Add(_scroll);
        Content = grid;

        var menu = new ContextMenu();
        var copy = new MenuItem { Header = "Copy all" };
        copy.Click += (_, _) => CopyAll();
        menu.Items.Add(copy);
        _surface.ContextMenu = menu;

        MeasureFont();
        Load(path);
    }

    private void Load(string path)
    {
        try { _rawText = File.ReadAllText(path); }
        catch (Exception ex) { _rawText = "// Could not read file: " + ex.Message; }

        string ext = Path.GetExtension(path).ToLowerInvariant();
        bool il = ext == ".il";
        bool code = il || ext is ".cs" or ".c" or ".cpp" or ".cc" or ".cxx" or ".h" or ".hpp" or ".java" or ".vb";
        _lines = code ? CodeTokenizer.Tokenize(_rawText, il) : PlainLines(_rawText);
        _lineNoDigits = Math.Max(3, _lines.Count.ToString().Length);
        ConfigureScroll();
        _surface.InvalidateVisual();
    }

    private static IReadOnlyList<DecompLine> PlainLines(string text)
    {
        var lines = new List<DecompLine>();
        foreach (var raw in text.Replace("\r\n", "\n").Replace("\r", "\n").Split('\n'))
            lines.Add(new DecompLine(0, [new AsmToken(raw, AsmTokenKind.Text)], 0));
        return lines;
    }

    private void CopyAll()
    {
        try { Clipboard.SetText(_rawText); } catch { /* clipboard can be transiently locked */ }
    }

    // ---- geometry / scrolling ----

    private int VisibleRows => Math.Max(1, (int)(_surface.ActualHeight / _rowHeight));
    private double GutterX => 6;
    private double ContentX => GutterX + (_lineNoDigits + 2) * _charWidth;

    private void MeasureFont()
    {
        double dpi = VisualTreeHelper.GetDpi(this).PixelsPerDip;
        var ft = new FormattedText("0", CultureInfo.InvariantCulture, FlowDirection.LeftToRight,
            _typeface, CodeFontSize, Brushes.White, dpi);
        _charWidth = ft.WidthIncludingTrailingWhitespace;
        _rowHeight = Math.Ceiling(ft.Height) + 4;
    }

    private void ConfigureScroll()
    {
        _scroll.Minimum = 0;
        _scroll.Maximum = Math.Max(0, _lines.Count - VisibleRows);
        _scroll.LargeChange = VisibleRows;
        _scroll.ViewportSize = VisibleRows;
        _scroll.Value = _top;
    }

    private void ScrollByLines(long delta)
    {
        _top = Math.Clamp(_top + delta, 0, Math.Max(0, _lines.Count - 1));
        _scroll.Value = _top;
        _surface.InvalidateVisual();
    }

    private void MoveCaret(long line)
    {
        if (_lines.Count == 0) return;
        _caret = Math.Clamp(line, 0, _lines.Count - 1);
        if (_caret < _top) _top = _caret;
        else if (_caret >= _top + VisibleRows) _top = _caret - VisibleRows + 1;
        _top = Math.Clamp(_top, 0, Math.Max(0, _lines.Count - 1));
        _scroll.Value = _top;
        _surface.InvalidateVisual();
    }

    // ---- rendering ----

    private void Render(DrawingContext dc, double width, double height)
    {
        dc.DrawRectangle(SyntaxTheme.Background, null, new Rect(0, 0, width, height));
        dc.DrawRectangle(SyntaxTheme.GutterBg, null, new Rect(0, 0, ContentX - _charWidth, height));
        if (_lines.Count == 0) return;

        double dpi = VisualTreeHelper.GetDpi(this).PixelsPerDip;
        int rows = (int)(height / _rowHeight) + 1;
        for (int r = 0; r < rows; r++)
        {
            long idx = _top + r;
            if (idx >= _lines.Count) break;
            double y = r * _rowHeight;
            var line = _lines[(int)idx];

            if (idx == _caret)
                dc.DrawRectangle(SyntaxTheme.CurrentLine, null, new Rect(ContentX - _charWidth, y, width - (ContentX - _charWidth), _rowHeight));

            Draw(dc, (idx + 1).ToString(), GutterX, y, SyntaxTheme.Address, dpi);   // 1-based line number

            double x = ContentX;
            foreach (var tok in line.Tokens)
                x = Draw(dc, tok.Text, x, y, SyntaxTheme.BrushFor(tok.Kind), dpi);
        }

        double dx = Math.Round(ContentX - _charWidth) - 0.5;
        dc.DrawLine(new Pen(SyntaxTheme.Separator, 1), new Point(dx, 0), new Point(dx, height));
    }

    private double Draw(DrawingContext dc, string text, double x, double y, Brush brush, double dpi)
    {
        var ft = new FormattedText(text, CultureInfo.InvariantCulture, FlowDirection.LeftToRight,
            _typeface, CodeFontSize, brush, dpi);
        dc.DrawText(ft, new Point(x, y + 1));
        return x + ft.WidthIncludingTrailingWhitespace;
    }

    private sealed class Surface : FrameworkElement
    {
        private readonly SourceViewerWindow _owner;
        public Surface(SourceViewerWindow owner) { _owner = owner; ClipToBounds = true; Focusable = true; }

        protected override void OnRenderSizeChanged(SizeChangedInfo info) { base.OnRenderSizeChanged(info); _owner.ConfigureScroll(); }
        protected override void OnDpiChanged(DpiScale oldDpi, DpiScale newDpi) { _owner.MeasureFont(); _owner.ConfigureScroll(); InvalidateVisual(); }
        protected override void OnMouseWheel(MouseWheelEventArgs e) { _owner.ScrollByLines(-Math.Sign(e.Delta) * 3); e.Handled = true; }

        protected override void OnMouseLeftButtonDown(MouseButtonEventArgs e)
        {
            Focus();
            _owner.MoveCaret(_owner._top + (long)(e.GetPosition(this).Y / _owner._rowHeight));
            e.Handled = true;
        }

        protected override void OnKeyDown(KeyEventArgs e)
        {
            if (e.Key == Key.C && (Keyboard.Modifiers & ModifierKeys.Control) != 0) { _owner.CopyAll(); e.Handled = true; return; }
            switch (e.Key)
            {
                case Key.Down: _owner.MoveCaret(_owner._caret + 1); break;
                case Key.Up: _owner.MoveCaret(_owner._caret - 1); break;
                case Key.PageDown: _owner.MoveCaret(_owner._caret + _owner.VisibleRows); break;
                case Key.PageUp: _owner.MoveCaret(_owner._caret - _owner.VisibleRows); break;
                case Key.Home: _owner._top = 0; _owner._scroll.Value = 0; break;
                case Key.End: _owner._top = Math.Max(0, _owner._lines.Count - _owner.VisibleRows); _owner._scroll.Value = _owner._top; break;
                default: return;
            }
            InvalidateVisual();
            e.Handled = true;
        }

        protected override void OnRender(DrawingContext dc) => _owner.Render(dc, ActualWidth, ActualHeight);
    }

    /// <summary>Extensions this viewer handles — opening one of these shows source text instead of disassembly.</summary>
    public static bool IsSourceFile(string path)
    {
        string ext = Path.GetExtension(path).ToLowerInvariant();
        return ext is ".cs" or ".il" or ".c" or ".cpp" or ".cc" or ".cxx" or ".h" or ".hpp" or ".java" or ".vb"
                   or ".txt" or ".json" or ".xml" or ".md" or ".log" or ".ini" or ".config" or ".csv" or ".yml" or ".yaml";
    }
}

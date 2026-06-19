using System.Globalization;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Input;
using System.Windows.Media;
using DisasmStudio.Core.Analysis;
using DisasmStudio.Core.Disasm;
using DisasmStudio.Core.IL;
using DisasmStudio.Wpf.Services;

namespace DisasmStudio.Wpf.Controls;

/// <summary>
/// The decompiler pane: shows the focused function at one of four levels — Low IL, Medium IL, High IL
/// and Pseudo-C — chosen by the selector bar at the top. Like the linear and graph views it draws
/// directly with DPI-correct <see cref="FormattedText"/> and the shared <see cref="SyntaxTheme"/>
/// brushes. Decompilation is built on a background thread (so a large function never freezes the UI)
/// and cached per function, mirroring how the CFG is built lazily on first view. Clicking a line
/// syncs the other panes; double-clicking a call follows the callee.
/// </summary>
public sealed class DecompilerView : Grid
{
    private readonly Surface _surface;
    private readonly ScrollBar _scroll;
    private readonly Button[] _levelButtons;

    private AnalysisResult? _result;
    private Disassembler? _dis;
    private DecompiledFunction? _dc;
    private IReadOnlyList<DecompLine> _lines = [];
    private ILLevel _level = ILLevel.PseudoC;

    private readonly Dictionary<ulong, DecompiledFunction> _cache = [];
    private ulong _shownFn;
    private int _buildSeq;

    private long _top;
    private long _caret = -1;

    private readonly Typeface _typeface =
        new(new FontFamily("Cascadia Mono, Consolas"), FontStyles.Normal, FontWeights.Normal, FontStretches.Normal);
    private const double FontSize = 13.0;
    private const int IndentChars = 4;
    private double _rowHeight = 16;
    private double _charWidth = 8;
    private int _addrDigits = 8;

    public event Action<ulong>? NavigateRequested;
    public event Action<ulong>? SelectionChanged;

    private static readonly (ILLevel Level, string Label)[] Levels =
    [
        (ILLevel.LowIL, "Low IL"), (ILLevel.MediumIL, "Medium IL"),
        (ILLevel.HighIL, "High IL"), (ILLevel.PseudoC, "Pseudo-C"),
    ];

    public DecompilerView()
    {
        RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });

        // Level selector bar.
        var bar = new Border
        {
            Background = (Brush)Application.Current.Resources["Surface"],
            BorderBrush = (Brush)Application.Current.Resources["Outline"],
            BorderThickness = new Thickness(0, 0, 0, 1),
            Padding = new Thickness(6, 4, 6, 4),
        };
        var strip = new StackPanel { Orientation = Orientation.Horizontal };
        _levelButtons = new Button[Levels.Length];
        for (int i = 0; i < Levels.Length; i++)
        {
            var lvl = Levels[i].Level;
            var btn = new Button { Content = Levels[i].Label, Margin = new Thickness(0, 0, 6, 0) };
            btn.Click += (_, _) => SetLevel(lvl);
            _levelButtons[i] = btn;
            strip.Children.Add(btn);
        }
        bar.Child = strip;
        SetRow(bar, 0);
        Children.Add(bar);

        var host = new Grid();
        host.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        host.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        _surface = new Surface(this);
        SetColumn(_surface, 0);
        host.Children.Add(_surface);
        _scroll = new ScrollBar { Orientation = Orientation.Vertical, SmallChange = 1 };
        _scroll.Scroll += (_, e) => { _top = (long)Math.Max(0, e.NewValue); _surface.InvalidateVisual(); };
        SetColumn(_scroll, 1);
        host.Children.Add(_scroll);
        SetRow(host, 1);
        Children.Add(host);

        MeasureFont();
        UpdateLevelButtons();
    }

    /// <summary>Show <paramref name="function"/> in the decompiler, building (and caching) it if needed.</summary>
    public void SetFunction(AnalysisResult result, Function function)
    {
        _result = result;
        _dis ??= new Disassembler(result.Image);
        _addrDigits = Math.Max(8, result.Image.MaxVa.ToString("X").Length);

        if (_cache.TryGetValue(function.Va, out var cached)) { _shownFn = function.Va; Show(cached); return; }

        // Build the CFG on the UI thread (shared mutable state), then lift/structure/emit in the background.
        if (!function.BlocksBuilt) CfgBuilder.Build(result.Image, function, result.JumpTables);

        _shownFn = function.Va;
        int seq = ++_buildSeq;
        ShowBuilding(function);

        var fn = function;
        Task.Run(() => Decompiler.Decompile(fn, result)).ContinueWith(t =>
        {
            var dc = t.IsCompletedSuccessfully ? t.Result : null;
            Dispatcher.Invoke(() =>
            {
                if (seq != _buildSeq) return;        // user moved on to another function
                if (dc is null) return;
                _cache[fn.Va] = dc;
                Show(dc);
            });
        });
    }

    public void Clear()
    {
        _dc = null;
        _dis = null;          // a new file means a new image; the decoder is rebuilt on next SetFunction
        _lines = [];
        _cache.Clear();
        _shownFn = 0;
        _caret = -1;
        _top = 0;
        ConfigureScroll();
        _surface.InvalidateVisual();
    }

    private void Show(DecompiledFunction dc)
    {
        _dc = dc;
        _lines = dc.Lines(_level);
        _top = 0;
        _caret = -1;
        ConfigureScroll();
        _surface.InvalidateVisual();
    }

    private void ShowBuilding(Function fn)
    {
        _dc = null;
        _lines = [new DecompLine(fn.Va, [new AsmToken($"// decompiling {fn.Name}…", AsmTokenKind.Comment)], 0)];
        _top = 0;
        _caret = -1;
        ConfigureScroll();
        _surface.InvalidateVisual();
    }

    private void SetLevel(ILLevel level)
    {
        _level = level;
        UpdateLevelButtons();
        if (_dc is not null) { _lines = _dc.Lines(_level); _top = 0; _caret = -1; ConfigureScroll(); }
        _surface.InvalidateVisual();
    }

    private void UpdateLevelButtons()
    {
        for (int i = 0; i < _levelButtons.Length; i++)
        {
            bool on = Levels[i].Level == _level;
            _levelButtons[i].FontWeight = on ? FontWeights.SemiBold : FontWeights.Normal;
            _levelButtons[i].Foreground = on
                ? (Brush)Application.Current.Resources["Accent"]
                : (Brush)Application.Current.Resources["TextSecondary"];
        }
    }

    // ---- geometry / scrolling ----

    private int VisibleRows => Math.Max(1, (int)(_surface.ActualHeight / _rowHeight));
    private double AddrX => 6;
    private double ContentX => AddrX + (_addrDigits + 2) * _charWidth;

    private void MeasureFont()
    {
        double dpi = VisualTreeHelper.GetDpi(this).PixelsPerDip;
        var ft = new FormattedText("0", CultureInfo.InvariantCulture, FlowDirection.LeftToRight,
            _typeface, FontSize, Brushes.White, dpi);
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
        ulong va = _lines[(int)_caret].Va;
        if (va != 0) SelectionChanged?.Invoke(va);
        _surface.InvalidateVisual();
    }

    private void Activate(long line)
    {
        if (line < 0 || line >= _lines.Count) return;
        ulong va = _lines[(int)line].Va;
        if (va == 0) return;
        // Follow a direct call/branch to its target; otherwise just sync to this line's address.
        if (_dis is not null && _dis.TryDecodeAt(va, out var ins)
            && FlowAnalysis.DirectBranchTarget(ins) is ulong t && _result?.Image.IsMappedVa(t) == true)
            NavigateRequested?.Invoke(t);
        else
            NavigateRequested?.Invoke(va);
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

            if (line.Va != 0)
                Draw(dc, line.Va.ToString("X" + _addrDigits), AddrX, y, SyntaxTheme.Address, dpi);

            double x = ContentX + line.Indent * IndentChars * _charWidth;
            foreach (var tok in line.Tokens)
                x = Draw(dc, tok.Text, x, y, SyntaxTheme.BrushFor(tok.Kind), dpi);
        }

        double dx = Math.Round(ContentX - _charWidth) - 0.5;
        dc.DrawLine(new Pen(SyntaxTheme.Separator, 1), new Point(dx, 0), new Point(dx, height));
    }

    private double Draw(DrawingContext dc, string text, double x, double y, Brush brush, double dpi)
    {
        var ft = new FormattedText(text, CultureInfo.InvariantCulture, FlowDirection.LeftToRight,
            _typeface, FontSize, brush, dpi);
        dc.DrawText(ft, new Point(x, y + 1));
        return x + ft.WidthIncludingTrailingWhitespace;
    }

    private sealed class Surface : FrameworkElement
    {
        private readonly DecompilerView _owner;
        public Surface(DecompilerView owner) { _owner = owner; ClipToBounds = true; Focusable = true; }

        protected override void OnRenderSizeChanged(SizeChangedInfo info) { base.OnRenderSizeChanged(info); _owner.ConfigureScroll(); }
        protected override void OnDpiChanged(DpiScale oldDpi, DpiScale newDpi) { _owner.MeasureFont(); _owner.ConfigureScroll(); InvalidateVisual(); }
        protected override void OnMouseWheel(MouseWheelEventArgs e) { _owner.ScrollByLines(-Math.Sign(e.Delta) * 3); e.Handled = true; }

        protected override void OnMouseLeftButtonDown(MouseButtonEventArgs e)
        {
            Focus();
            long line = _owner._top + (long)(e.GetPosition(this).Y / _owner._rowHeight);
            _owner.MoveCaret(line);
            if (e.ClickCount == 2) _owner.Activate(line);
            e.Handled = true;
        }

        protected override void OnKeyDown(KeyEventArgs e)
        {
            switch (e.Key)
            {
                case Key.Down: _owner.MoveCaret(_owner._caret + 1); break;
                case Key.Up: _owner.MoveCaret(_owner._caret - 1); break;
                case Key.PageDown: _owner.MoveCaret(_owner._caret + _owner.VisibleRows); break;
                case Key.PageUp: _owner.MoveCaret(_owner._caret - _owner.VisibleRows); break;
                case Key.Enter: _owner.Activate(_owner._caret); break;
                default: return;
            }
            e.Handled = true;
        }

        protected override void OnRender(DrawingContext dc) => _owner.Render(dc, ActualWidth, ActualHeight);
    }
}

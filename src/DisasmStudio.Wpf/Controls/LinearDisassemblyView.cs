using System.Globalization;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Input;
using System.Windows.Media;
using DisasmStudio.Core.Analysis;
using DisasmStudio.Core.Disasm;
using DisasmStudio.Wpf.Services;
using Iced.Intel;

namespace DisasmStudio.Wpf.Controls;

/// <summary>
/// The linear disassembly listing. Like the hex view it draws directly (no ItemsControl) and only
/// decodes/formats the rows currently on screen, so it scrolls smoothly over a many-million-line
/// image. Named addresses (functions, loc_ labels) get their own header line; the line↔content map
/// is computed with binary search so an arbitrary scrollbar jump is O(log n) — nothing is
/// materialised up front. Crisp at any 4K/5K scale via DPI-correct text + pixel-snapped separators.
/// </summary>
public sealed class LinearDisassemblyView : Grid
{
    private readonly Surface _surface;
    private readonly ScrollBar _scroll;

    private AnalysisResult? _result;
    private Disassembler? _dis;
    private AsmFormatter? _fmt;

    // Label lines (function starts + named locs), as parallel sorted arrays.
    private long[] _labelInstrLines = [];
    private ulong[] _labelVa = [];

    private long _topDisplay;       // first visible display line
    private long _caretInstr = -1;  // selected instruction index, or -1

    private readonly Typeface _typeface =
        new(new FontFamily("Cascadia Mono, Consolas"), FontStyles.Normal, FontWeights.Normal, FontStretches.Normal);
    private const double FontSize = 13.0;
    private double _rowHeight = 16;
    private double _charWidth = 8;
    private int _addrDigits = 8;

    public event Action<ulong>? NavigateRequested;
    public event Action? GoToRequested;
    public event Action<ulong>? SelectionChanged;
    public event Action<ulong>? ShowXrefsRequested;
    public event Action<ulong>? OpenInGraphRequested;

    public LinearDisassemblyView()
    {
        ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

        _surface = new Surface(this);
        SetColumn(_surface, 0);
        Children.Add(_surface);

        _scroll = new ScrollBar { Orientation = Orientation.Vertical, SmallChange = 1 };
        _scroll.Scroll += OnScroll;
        SetColumn(_scroll, 1);
        Children.Add(_scroll);

        BuildContextMenu();
        MeasureFont();
    }

    public void SetResult(AnalysisResult? result)
    {
        _result = result;
        _caretInstr = -1;
        _topDisplay = 0;
        if (result is null) { _dis = null; _fmt = null; _labelInstrLines = []; _labelVa = []; }
        else
        {
            _dis = new Disassembler(result.Image);
            _fmt = new AsmFormatter(result.Names);
            _addrDigits = Math.Max(8, result.Image.MaxVa.ToString("X").Length);
            BuildLabelLines(result);
        }
        ConfigureScroll();
        _surface.InvalidateVisual();
    }

    /// <summary>Centre the view on a VA and select that instruction.</summary>
    public void GoToVa(ulong va)
    {
        if (_result is null) return;
        long line = _result.Linear.IndexOf(va);
        _caretInstr = line;
        long disp = DisplayIndexOfInstr(line);
        long firstThird = Math.Max(0, VisibleRows / 3);
        _topDisplay = Math.Clamp(disp - firstThird, 0, Math.Max(0, DisplayCount - 1));
        SyncScrollValue();
        _surface.Focus();
        _surface.InvalidateVisual();
        SelectionChanged?.Invoke(va);
    }

    // ---- label-line index ----
    private void BuildLabelLines(AnalysisResult result)
    {
        var lines = new List<long>();
        var vas = new List<ulong>();
        // Code labels = named, executable addresses that land exactly on an instruction.
        var seen = new HashSet<long>();
        foreach (var (va, _) in result.Names)
        {
            if (!result.Image.IsExecutableVa(va)) continue;
            long line = result.Linear.IndexOf(va);
            if (result.Linear.VaAt(line) != va) continue; // not an instruction boundary
            if (!seen.Add(line)) continue;
            lines.Add(line);
            vas.Add(va);
        }
        // Sort both by line.
        var order = Enumerable.Range(0, lines.Count).OrderBy(i => lines[i]).ToArray();
        _labelInstrLines = order.Select(i => lines[i]).ToArray();
        _labelVa = order.Select(i => vas[i]).ToArray();
    }

    private long DisplayCount => _result is null ? 0 : _result.Linear.Count + _labelInstrLines.Length;

    /// <summary>Count of label lines whose instruction line is &lt;= j.</summary>
    private long LabelsUpTo(long j)
    {
        long lo = 0, hi = _labelInstrLines.Length;
        while (lo < hi) { long mid = (lo + hi) >> 1; if (_labelInstrLines[mid] <= j) lo = mid + 1; else hi = mid; }
        return lo;
    }

    private long DisplayIndexOfInstr(long j) => j + LabelsUpTo(j);

    /// <summary>Resolve a display line to either a label header or an instruction.</summary>
    private (bool IsLabel, long InstrLine) ContentAt(long display)
    {
        if (_result is null) return (false, 0);
        long n = _result.Linear.Count;
        // Smallest instruction index j with DisplayIndexOfInstr(j) >= display.
        long lo = 0, hi = n - 1, found = n - 1;
        while (lo <= hi)
        {
            long mid = (lo + hi) >> 1;
            if (DisplayIndexOfInstr(mid) >= display) { found = mid; hi = mid - 1; }
            else lo = mid + 1;
        }
        long di = DisplayIndexOfInstr(found);
        if (di == display) return (false, found);
        return (true, found); // the label line that sits just before instruction `found`
    }

    private int VisibleRows => Math.Max(1, (int)(_surface.ActualHeight / _rowHeight));

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
        if (_result is null) { _scroll.Maximum = 0; return; }
        _scroll.Minimum = 0;
        _scroll.Maximum = Math.Max(0, DisplayCount - VisibleRows);
        _scroll.LargeChange = VisibleRows;
        _scroll.ViewportSize = VisibleRows;
        SyncScrollValue();
    }

    private void SyncScrollValue() => _scroll.Value = _topDisplay;

    private void OnScroll(object sender, ScrollEventArgs e)
    {
        _topDisplay = (long)Math.Max(0, e.NewValue);
        _surface.InvalidateVisual();
    }

    private void ScrollByLines(long delta)
    {
        _topDisplay = Math.Clamp(_topDisplay + delta, 0, Math.Max(0, DisplayCount - 1));
        SyncScrollValue();
        _surface.InvalidateVisual();
    }

    // ---- geometry ----
    private double GutterW => 3.5 * _charWidth;
    private double AddrX => GutterW + 4;
    private double BytesX => AddrX + (_addrDigits + 2) * _charWidth;
    private double DisasmX => BytesX + 25 * _charWidth;

    private void MoveCaret(long newInstr)
    {
        if (_result is null) return;
        _caretInstr = Math.Clamp(newInstr, 0, _result.Linear.Count - 1);
        EnsureCaretVisible();
        _surface.InvalidateVisual();
        SelectionChanged?.Invoke(_result.Linear.VaAt(_caretInstr));
    }

    private void EnsureCaretVisible()
    {
        long caretDisp = DisplayIndexOfInstr(_caretInstr);
        if (caretDisp < _topDisplay) _topDisplay = caretDisp;
        else if (caretDisp >= _topDisplay + VisibleRows) _topDisplay = caretDisp - VisibleRows + 1;
        _topDisplay = Math.Clamp(_topDisplay, 0, Math.Max(0, DisplayCount - 1));
        SyncScrollValue();
    }

    private void FollowCaret()
    {
        if (_result is null || _dis is null || _caretInstr < 0) return;
        ulong va = _result.Linear.VaAt(_caretInstr);
        if (!_dis.TryDecodeAt(va, out var instr)) return;
        if (FlowAnalysis.DirectBranchTarget(instr) is ulong t && _result.Image.IsMappedVa(t))
            NavigateRequested?.Invoke(t);
    }

    private ulong CaretVa => _result is not null && _caretInstr >= 0 ? _result.Linear.VaAt(_caretInstr) : 0;

    // ---- hit testing ----
    private void OnClick(Point p)
    {
        if (_result is null) return;
        long display = _topDisplay + (long)(p.Y / _rowHeight);
        if (display >= DisplayCount) return;
        var (_, instrLine) = ContentAt(display);
        _caretInstr = instrLine;
        _surface.InvalidateVisual();
        SelectionChanged?.Invoke(_result.Linear.VaAt(instrLine));
    }

    // ---- rendering ----
    private void Render(DrawingContext dc, double width, double height)
    {
        dc.DrawRectangle(SyntaxTheme.Background, null, new Rect(0, 0, width, height));
        dc.DrawRectangle(SyntaxTheme.GutterBg, null, new Rect(0, 0, GutterW, height));
        if (_result is null || _dis is null || _fmt is null) return;

        double dpi = VisualTreeHelper.GetDpi(this).PixelsPerDip;
        int rows = (int)(height / _rowHeight) + 1;
        var snap = new GuidelineSet();

        for (int r = 0; r < rows; r++)
        {
            long display = _topDisplay + r;
            if (display >= DisplayCount) break;
            double y = r * _rowHeight;
            var (isLabel, instrLine) = ContentAt(display);
            ulong va = _result.Linear.VaAt(instrLine);

            if (isLabel)
            {
                DrawLabel(dc, va, y, width, dpi);
                continue;
            }

            bool isCaret = instrLine == _caretInstr;
            if (isCaret)
                dc.DrawRectangle(SyntaxTheme.Selection, null, new Rect(GutterW, y, width - GutterW, _rowHeight));

            DrawInstruction(dc, va, y, dpi);
        }

        DrawBranchArrows(dc, rows);
    }

    private void DrawLabel(DrawingContext dc, ulong va, double y, double width, double dpi)
    {
        bool isFunc = _result!.FunctionByVa.ContainsKey(va);
        // Pixel-snapped 1px separator above a function header.
        double ly = Math.Round(y) + 0.5;
        dc.DrawLine(new Pen(SyntaxTheme.Separator, 1), new Point(GutterW, ly), new Point(width, ly));

        string name = _result.NameFor(va) ?? $"loc_{va:X}";
        var brush = isFunc ? SyntaxTheme.FuncName : SyntaxTheme.Symbol;
        Draw(dc, name + ":", AddrX, y, brush, dpi);
    }

    private void DrawInstruction(DrawingContext dc, ulong va, double y, double dpi)
    {
        Draw(dc, va.ToString("X" + _addrDigits), AddrX, y, SyntaxTheme.Address, dpi);

        if (!_dis!.TryDecodeAt(va, out var instr))
        {
            Draw(dc, "??", DisasmX, y, SyntaxTheme.Comment, dpi);
            return;
        }

        // Bytes (up to 8 shown).
        var bytes = _result!.Image.ReadBytesAtVa(va, Math.Min(instr.Length, 8));
        var hex = new System.Text.StringBuilder();
        foreach (var b in bytes) hex.Append(b.ToString("x2")).Append(' ');
        if (instr.Length > 8) hex.Append('+');
        Draw(dc, hex.ToString(), BytesX, y, SyntaxTheme.Bytes, dpi);

        // Disassembly tokens.
        double x = DisasmX;
        foreach (var tok in _fmt!.Format(instr))
            x = Draw(dc, tok.Text, x, y, SyntaxTheme.BrushFor(tok.Kind), dpi);

        // Inline comment (referenced string, etc.).
        if (_result.Comments.TryGetValue(va, out var comment))
            Draw(dc, "   ; " + comment, x + _charWidth, y, SyntaxTheme.Comment, dpi);
    }

    private void DrawBranchArrows(DrawingContext dc, int rows)
    {
        if (_result is null || _dis is null) return;
        double midGutter = GutterW - _charWidth;
        var pen = new Pen(SyntaxTheme.EdgeJump, 1) { EndLineCap = PenLineCap.Triangle };

        for (int r = 0; r < rows; r++)
        {
            long display = _topDisplay + r;
            if (display >= DisplayCount) break;
            var (isLabel, instrLine) = ContentAt(display);
            if (isLabel) continue;
            ulong va = _result.Linear.VaAt(instrLine);
            if (!_dis.TryDecodeAt(va, out var instr)) continue;
            if (FlowAnalysis.DirectBranchTarget(instr) is not ulong target) continue;
            if (instr.FlowControl == FlowControl.Call) continue; // arrows for jumps only

            long targetInstr = _result.Linear.IndexOf(target);
            if (_result.Linear.VaAt(targetInstr) != target) continue;
            long targetDisp = DisplayIndexOfInstr(targetInstr);
            long visTop = _topDisplay, visBot = _topDisplay + rows;
            if (targetDisp < visTop || targetDisp >= visBot) continue;

            double y0 = (display - _topDisplay) * _rowHeight + _rowHeight / 2;
            double y1 = (targetDisp - _topDisplay) * _rowHeight + _rowHeight / 2;
            double xElbow = Math.Max(2, midGutter - Math.Min(8, Math.Abs(r)) );
            dc.DrawLine(pen, new Point(midGutter, y0), new Point(xElbow, y0));
            dc.DrawLine(pen, new Point(xElbow, y0), new Point(xElbow, y1));
            dc.DrawLine(pen, new Point(xElbow, y1), new Point(midGutter, y1));
        }
    }

    private double Draw(DrawingContext dc, string text, double x, double y, Brush brush, double dpi)
    {
        var ft = new FormattedText(text, CultureInfo.InvariantCulture, FlowDirection.LeftToRight,
            _typeface, FontSize, brush, dpi);
        dc.DrawText(ft, new Point(x, y + 1));
        return x + ft.WidthIncludingTrailingWhitespace;
    }

    private void BuildContextMenu()
    {
        var menu = new ContextMenu();
        var xref = new MenuItem { Header = "Show xrefs to this address" };
        xref.Click += (_, _) => { if (CaretVa != 0) ShowXrefsRequested?.Invoke(CaretVa); };
        var graph = new MenuItem { Header = "Open function in graph" };
        graph.Click += (_, _) => { if (CaretVa != 0) OpenInGraphRequested?.Invoke(CaretVa); };
        var follow = new MenuItem { Header = "Follow target", InputGestureText = "Enter" };
        follow.Click += (_, _) => FollowCaret();
        menu.Items.Add(follow);
        menu.Items.Add(xref);
        menu.Items.Add(graph);
        _surface.ContextMenu = menu;
    }

    private sealed class Surface : FrameworkElement
    {
        private readonly LinearDisassemblyView _owner;
        public Surface(LinearDisassemblyView owner) { _owner = owner; ClipToBounds = true; Focusable = true; }

        protected override void OnRenderSizeChanged(SizeChangedInfo info) { base.OnRenderSizeChanged(info); _owner.ConfigureScroll(); }
        protected override void OnDpiChanged(DpiScale oldDpi, DpiScale newDpi) { _owner.MeasureFont(); _owner.ConfigureScroll(); InvalidateVisual(); }

        protected override void OnMouseWheel(MouseWheelEventArgs e) { _owner.ScrollByLines(-Math.Sign(e.Delta) * 3); e.Handled = true; }

        protected override void OnMouseLeftButtonDown(MouseButtonEventArgs e)
        {
            Focus();
            _owner.OnClick(e.GetPosition(this));
            if (e.ClickCount == 2) _owner.FollowCaret();
            e.Handled = true;
        }

        protected override void OnMouseRightButtonDown(MouseButtonEventArgs e)
        {
            Focus();
            _owner.OnClick(e.GetPosition(this));
        }

        protected override void OnKeyDown(KeyEventArgs e)
        {
            if (_owner._result is null) return;
            switch (e.Key)
            {
                case Key.Down: _owner.MoveCaret(_owner._caretInstr + 1); break;
                case Key.Up: _owner.MoveCaret(_owner._caretInstr - 1); break;
                case Key.PageDown: _owner.MoveCaret(_owner._caretInstr + _owner.VisibleRows); break;
                case Key.PageUp: _owner.MoveCaret(_owner._caretInstr - _owner.VisibleRows); break;
                case Key.Home: _owner.MoveCaret(0); break;
                case Key.End: _owner.MoveCaret(_owner._result.Linear.Count - 1); break;
                case Key.Enter: _owner.FollowCaret(); break;
                case Key.G when (Keyboard.Modifiers & ModifierKeys.Control) != 0: _owner.GoToRequested?.Invoke(); break;
                default: return;
            }
            e.Handled = true;
        }

        protected override void OnRender(DrawingContext dc) => _owner.Render(dc, ActualWidth, ActualHeight);
    }
}

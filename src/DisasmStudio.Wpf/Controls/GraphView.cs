using System.Globalization;
using System.Windows;
using System.Windows.Input;
using System.Windows.Media;
using DisasmStudio.Core.Analysis;
using DisasmStudio.Core.Disasm;
using DisasmStudio.Wpf.Services;

namespace DisasmStudio.Wpf.Controls;

/// <summary>
/// A per-function control-flow graph: basic blocks as rounded cards of token-coloured instructions,
/// connected by colour-coded edges (taken / fall-through / jump). Bounded to one function, so cost
/// is independent of total file size. Pan by dragging, zoom with Ctrl+wheel about the cursor,
/// fit-to-view on load. Clicking a block syncs the linear view.
/// </summary>
public sealed class GraphView : FrameworkElement
{
    private AnalysisResult? _result;
    private Function? _function;
    private readonly List<BasicBlock> _blocks = [];
    private readonly Dictionary<ulong, BasicBlock> _byStart = [];
    private readonly Dictionary<ulong, List<Line>> _lines = [];

    private double _scale = 1.0;
    private Vector _offset;
    private Point _lastDrag;
    private bool _dragging;
    private IInstructionDecoder? _decoder;   // live decoder while debugging
    private ulong _ipVa;                      // debuggee's current instruction

    // A view change (fit-to-graph in disassembler mode, or focus-on-current-block in debugger mode) is
    // applied once the graph has a real size — the tab may not be laid out when it's requested.
    private enum Pend { None, Fit, Focus }
    private Pend _pend;
    private ulong _pendVa;
    private bool _pendResetZoom;
    private const double DebugZoom = 1.0;    // readable zoom for debugger follow (don't shrink to fit)

    private readonly Typeface _typeface =
        new(new FontFamily("Cascadia Mono, Consolas"), FontStyles.Normal, FontWeights.Normal, FontStretches.Normal);
    private const double FontSize = 12.5;
    private double _rowHeight = 15;
    private double _charWidth = 7.5;
    private const double Pad = 8;
    private const double HeaderH = 18;

    public event Action<ulong>? BlockSelected;

    private sealed record Line(ulong Va, string Text, AsmToken[] Tokens, double Width, string? Comment);

    public GraphView()
    {
        ClipToBounds = true;
        Focusable = true;
        MeasureFont();
    }

    public void SetFunction(AnalysisResult result, Function function, IInstructionDecoder? decoder = null, bool autoFit = true)
    {
        _result = result;
        _function = function;
        _decoder = decoder;
        if (!function.BlocksBuilt) CfgBuilder.Build(result.Image, function, result.JumpTables, decoder);

        _blocks.Clear();
        _byStart.Clear();
        _lines.Clear();
        _blocks.AddRange(function.Blocks);
        foreach (var b in _blocks) _byStart[b.Start] = b;

        BuildLines(result);
        Layout();
        // Disassembler mode fits the whole function; debugger mode leaves the view to the follow logic
        // (SetCurrentIp), which keeps a readable zoom on the current block instead of shrinking to fit.
        _pend = autoFit ? Pend.Fit : Pend.None;
        ApplyPending();
        InvalidateVisual();
    }

    private void ApplyPending()
    {
        if (_pend == Pend.None || ActualWidth <= 0 || ActualHeight <= 0) return;   // defer until sized
        if (_pend == Pend.Fit) FitToView();
        else
        {
            if (_pendResetZoom) _scale = DebugZoom;
            // centre on the IP's block; if the IP isn't in this function (browsing another), centre its entry
            var b = _blocks.FirstOrDefault(x => _pendVa >= x.Start && _pendVa < x.End) ?? _blocks.FirstOrDefault();
            if (b is not null) CenterOn(b);
        }
        _pend = Pend.None;
    }

    private void CenterOn(BasicBlock b)
    {
        double cx = b.X + b.Width / 2, cy = b.Y + b.Height / 2;
        _offset = new Vector(ActualWidth / 2 - cx * _scale, ActualHeight / 2 - cy * _scale);
    }

    protected override void OnRenderSizeChanged(SizeChangedInfo info)
    {
        base.OnRenderSizeChanged(info);
        if (_pend != Pend.None) { ApplyPending(); InvalidateVisual(); }   // apply the pending view once a real size exists
    }

    public void Clear()
    {
        _function = null;
        _decoder = null;
        _ipVa = 0;
        _pend = Pend.None;   // drop any deferred fit/focus so it can't fire against empty blocks
        _blocks.Clear();
        _byStart.Clear();
        _lines.Clear();
        InvalidateVisual();
    }

    /// <summary>Follow the debuggee's current instruction: highlight and centre its block.
    /// <paramref name="resetZoom"/> (set when moving to a different function) restores a readable zoom;
    /// while stepping inside a function it stays false so the user's manual zoom is preserved.</summary>
    public void SetCurrentIp(ulong va, bool resetZoom = false)
    {
        _ipVa = va;
        _pend = Pend.Focus; _pendVa = va; _pendResetZoom = resetZoom;
        ApplyPending();
        InvalidateVisual();
    }

    private void MeasureFont()
    {
        double dpi = VisualTreeHelper.GetDpi(this).PixelsPerDip;
        var ft = new FormattedText("0", CultureInfo.InvariantCulture, FlowDirection.LeftToRight,
            _typeface, FontSize, Brushes.White, dpi);
        _charWidth = ft.WidthIncludingTrailingWhitespace;
        _rowHeight = Math.Ceiling(ft.Height) + 2;
    }

    private void BuildLines(AnalysisResult result)
    {
        double dpi = VisualTreeHelper.GetDpi(this).PixelsPerDip;
        IInstructionDecoder dis = _decoder ?? new Disassembler(result.Image);
        var fmt = new AsmFormatter(result.Names);

        foreach (var block in _blocks)
        {
            var list = new List<Line>(block.InstrVas.Count);
            foreach (var va in block.InstrVas)
            {
                if (!dis.TryDecodeAt(va, out var instr)) continue;
                var tokens = fmt.Format(instr).ToArray();
                string text = va.ToString("X8") + "  " + string.Concat(tokens.Select(t => t.Text));
                result.Comments.TryGetValue(va, out var comment);
                string measured = comment is null ? text : text + "   ; " + comment;
                var ft = new FormattedText(measured, CultureInfo.InvariantCulture, FlowDirection.LeftToRight,
                    _typeface, FontSize, Brushes.White, dpi);
                list.Add(new Line(va, text, tokens, ft.WidthIncludingTrailingWhitespace, comment));
            }
            _lines[block.Start] = list;
        }
    }

    // ---- layout (simple BFS layering) ----
    private void Layout()
    {
        if (_blocks.Count == 0 || _function is null) return;

        // Size each block from its lines.
        foreach (var b in _blocks)
        {
            var lines = _lines[b.Start];
            double w = 60;
            foreach (var l in lines) w = Math.Max(w, l.Width);
            b.Width = w + Pad * 2;
            b.Height = HeaderH + Math.Max(1, lines.Count) * _rowHeight + Pad;
        }

        // Rank = BFS distance from the entry block.
        var rank = new Dictionary<ulong, int>();
        var queue = new Queue<ulong>();
        ulong entry = _byStart.ContainsKey(_function.Va) ? _function.Va : _blocks[0].Start;
        rank[entry] = 0;
        queue.Enqueue(entry);
        while (queue.Count > 0)
        {
            ulong s = queue.Dequeue();
            int next = rank[s] + 1;
            foreach (var e in _byStart[s].Out)
            {
                if (!_byStart.ContainsKey(e.ToBlockStart)) continue;
                if (rank.TryAdd(e.ToBlockStart, next)) queue.Enqueue(e.ToBlockStart);
            }
        }
        int fallback = 0;
        foreach (var b in _blocks) if (!rank.ContainsKey(b.Start)) rank[b.Start] = ++fallback + 100;

        // Group by rank, lay rows top-to-bottom, centre each row.
        var byRank = _blocks.GroupBy(b => rank[b.Start]).OrderBy(g => g.Key).ToList();
        const double hGap = 36, vGap = 44;
        double y = 20;
        double maxRowWidth = byRank.Select(g => g.Sum(b => b.Width) + (g.Count() - 1) * hGap).DefaultIfEmpty(0).Max();
        foreach (var grp in byRank)
        {
            var row = grp.OrderBy(b => b.Start).ToList();
            double rowWidth = row.Sum(b => b.Width) + (row.Count - 1) * hGap;
            double x = 20 + (maxRowWidth - rowWidth) / 2;
            double rowHeight = row.Max(b => b.Height);
            foreach (var b in row) { b.X = x; b.Y = y; x += b.Width + hGap; }
            y += rowHeight + vGap;
        }
    }

    private void FitToView()
    {
        if (_blocks.Count == 0 || ActualWidth <= 0) { _scale = 1; _offset = default; return; }
        double minX = _blocks.Min(b => b.X), minY = _blocks.Min(b => b.Y);
        double maxX = _blocks.Max(b => b.X + b.Width), maxY = _blocks.Max(b => b.Y + b.Height);
        double gw = maxX - minX + 40, gh = maxY - minY + 40;
        _scale = Math.Min(1.5, Math.Min(ActualWidth / gw, ActualHeight / gh));
        if (_scale <= 0 || double.IsInfinity(_scale)) _scale = 1;
        _offset = new Vector((ActualWidth - gw * _scale) / 2 - minX * _scale + 20 * _scale,
                             20 - minY * _scale);
    }

    // ---- rendering ----
    protected override void OnRender(DrawingContext dc)
    {
        dc.DrawRectangle(SyntaxTheme.Background, null, new Rect(0, 0, ActualWidth, ActualHeight));
        if (_blocks.Count == 0) return;

        double dpi = VisualTreeHelper.GetDpi(this).PixelsPerDip;
        dc.PushTransform(new TranslateTransform(_offset.X, _offset.Y));
        dc.PushTransform(new ScaleTransform(_scale, _scale));

        DrawEdges(dc);
        foreach (var b in _blocks) DrawBlock(dc, b, dpi);

        dc.Pop();
        dc.Pop();
    }

    private void DrawEdges(DrawingContext dc)
    {
        foreach (var b in _blocks)
        {
            double sx = b.X + b.Width / 2, sy = b.Y + b.Height;
            foreach (var e in b.Out)
            {
                if (!_byStart.TryGetValue(e.ToBlockStart, out var t)) continue;
                double tx = t.X + t.Width / 2, ty = t.Y;
                var brush = e.Kind switch
                {
                    EdgeKind.Taken => SyntaxTheme.EdgeTaken,
                    EdgeKind.Jump => SyntaxTheme.EdgeJump,
                    EdgeKind.Switch => SyntaxTheme.EdgeSwitch,
                    _ => SyntaxTheme.EdgeFall,
                };
                var pen = new Pen(brush, 1.4);
                double midY = ty > sy ? (sy + ty) / 2 : sy + 24;
                var fig = new PathFigure { StartPoint = new Point(sx, sy) };
                fig.Segments.Add(new LineSegment(new Point(sx, midY), true));
                fig.Segments.Add(new LineSegment(new Point(tx, midY), true));
                fig.Segments.Add(new LineSegment(new Point(tx, ty), true));
                var geo = new PathGeometry();
                geo.Figures.Add(fig);
                dc.DrawGeometry(null, pen, geo);
                // Arrowhead into the target.
                dc.DrawLine(pen, new Point(tx, ty), new Point(tx - 4, ty - 6));
                dc.DrawLine(pen, new Point(tx, ty), new Point(tx + 4, ty - 6));
            }
        }
    }

    private void DrawBlock(DrawingContext dc, BasicBlock b, double dpi)
    {
        var rect = new Rect(b.X, b.Y, b.Width, b.Height);
        bool isIpBlock = _ipVa != 0 && b.Start <= _ipVa && _ipVa < b.End;
        var border = isIpBlock ? new Pen(SyntaxTheme.FuncName, 2) : new Pen(SyntaxTheme.BlockBorder, 1);
        dc.DrawRoundedRectangle(SyntaxTheme.BlockBg, border, rect, 5, 5);
        dc.DrawRoundedRectangle(SyntaxTheme.BlockHeader, null, new Rect(b.X, b.Y, b.Width, HeaderH), 5, 5);

        string header = _result?.NameFor(b.Start) ?? $"loc_{b.Start:X}";
        DrawText(dc, header, b.X + Pad, b.Y + 1, SyntaxTheme.FuncName, dpi);

        double y = b.Y + HeaderH + 1;
        foreach (var line in _lines[b.Start])
        {
            if (_ipVa != 0 && line.Va == _ipVa)
                dc.DrawRectangle(SyntaxTheme.CurrentIp, null, new Rect(b.X + 1, y, b.Width - 2, _rowHeight));
            double x = b.X + Pad;
            // Address prefix.
            int split = line.Text.IndexOf("  ", StringComparison.Ordinal);
            string addr = split > 0 ? line.Text[..split] : "";
            x = DrawText(dc, addr + "  ", x, y, SyntaxTheme.Address, dpi);
            foreach (var tok in line.Tokens)
                x = DrawText(dc, tok.Text, x, y, SyntaxTheme.BrushFor(tok.Kind), dpi);
            if (line.Comment is not null)
                DrawText(dc, "   ; " + line.Comment, x, y, SyntaxTheme.Comment, dpi);
            y += _rowHeight;
        }
    }

    private double DrawText(DrawingContext dc, string text, double x, double y, Brush brush, double dpi)
    {
        var ft = new FormattedText(text, CultureInfo.InvariantCulture, FlowDirection.LeftToRight,
            _typeface, FontSize, brush, dpi);
        dc.DrawText(ft, new Point(x, y));
        return x + ft.WidthIncludingTrailingWhitespace;
    }

    // ---- interaction ----
    private Point ToGraph(Point screen) => new((screen.X - _offset.X) / _scale, (screen.Y - _offset.Y) / _scale);

    protected override void OnMouseWheel(MouseWheelEventArgs e)
    {
        // Mouse wheel zooms the graph about the cursor (Shift+wheel pans vertically instead).
        if ((Keyboard.Modifiers & ModifierKeys.Shift) != 0)
        {
            _offset -= new Vector(0, Math.Sign(e.Delta) * 60);
        }
        else
        {
            Point screen = e.GetPosition(this);
            Point g = ToGraph(screen);                                   // graph point under the cursor
            _scale = Math.Clamp(_scale * (e.Delta > 0 ? 1.15 : 1 / 1.15), 0.12, 6.0);
            _offset = new Vector(screen.X - g.X * _scale, screen.Y - g.Y * _scale); // keep it under the cursor
        }
        InvalidateVisual();
        e.Handled = true;
    }

    protected override void OnMouseLeftButtonDown(MouseButtonEventArgs e)
    {
        Focus();
        _lastDrag = e.GetPosition(this);
        _dragging = true;
        CaptureMouse();

        var g = ToGraph(_lastDrag);
        foreach (var b in _blocks)
            if (g.X >= b.X && g.X <= b.X + b.Width && g.Y >= b.Y && g.Y <= b.Y + b.Height)
            { BlockSelected?.Invoke(b.Start); break; }
    }

    protected override void OnMouseMove(MouseEventArgs e)
    {
        if (!_dragging) return;
        var p = e.GetPosition(this);
        _offset += p - _lastDrag;
        _lastDrag = p;
        InvalidateVisual();
    }

    protected override void OnMouseLeftButtonUp(MouseButtonEventArgs e)
    {
        if (_dragging) { _dragging = false; ReleaseMouseCapture(); }
    }

    protected override void OnDpiChanged(DpiScale oldDpi, DpiScale newDpi)
    {
        MeasureFont();
        if (_result is not null && _function is not null) { BuildLines(_result); Layout(); }
        InvalidateVisual();
    }
}

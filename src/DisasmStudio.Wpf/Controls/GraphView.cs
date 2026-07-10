using System.Globalization;
using System.Windows;
using System.Windows.Controls;
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
    private ulong _selVa;                     // last-clicked instruction (target of F2/F9 toggle)
    private ulong _menuVa;                    // instruction under the last right-click (context-menu target)

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
    /// <summary>Toggle a software breakpoint at the address (gutter dot, right-click → Toggle breakpoint, or F2/F9).
    /// Wired to the same handler as the linear view so both share one breakpoint set.</summary>
    public event Action<ulong>? BreakpointToggleRequested;
    /// <summary>Rename the symbol at the right-clicked instruction (right-click → Rename).</summary>
    public event Action<ulong>? RenameRequested;
    /// <summary>Set/clear an inline comment at the right-clicked instruction (right-click → Set comment).</summary>
    public event Action<ulong>? CommentRequested;
    /// <summary>Toggle a bookmark at the right-clicked instruction (right-click → Toggle bookmark).</summary>
    public event Action<ulong>? BookmarkToggleRequested;
    /// <summary>Toggle the conditional jump at the address so it goes the other way — flips the deciding CPU flags
    /// while stopped on it in the debugger, or a static what-if otherwise; the edges recolour green ("taken") /
    /// red ("not taken") (right-click → Toggle jump, or Space).</summary>
    public event Action<ulong>? ToggleJumpRequested;

    /// <summary>Predicate the renderer uses to tint executed (traced) instruction rows — mirrors the
    /// linear view's coverage overlay so the graph shows the same trace highlights.</summary>
    public Func<ulong, bool>? IsInstrHit { get; set; }
    /// <summary>Predicate the renderer uses to mark instruction rows that have a breakpoint.</summary>
    public Func<ulong, bool>? IsBreakpointAt { get; set; }
    /// <summary>Predicate the renderer uses to colour a hardware breakpoint's dot differently from a software one.</summary>
    public Func<ulong, bool>? IsHardwareBreakpointAt { get; set; }
    /// <summary>Per-jump colour mark: true = green ("taken"), false = red ("not taken"), null = untoggled. Recolours
    /// that block's Taken/FallThrough edges; flipped by the "Toggle jump" action.</summary>
    public Func<ulong, bool?>? JumpMark { get; set; }

    /// <summary>Repaint without rebuilding layout — e.g. when the coverage/trace set grows during a run.</summary>
    public void Refresh() => InvalidateVisual();

    /// <summary>Rebuild the block lines + layout (operand names/comments are baked into the tokens at build
    /// time, so a user rename/comment needs a rebuild, not just a repaint).</summary>
    public void Rebuild()
    {
        if (_result is not null && _function is not null) { BuildLines(_result); Layout(); InvalidateVisual(); }
    }

    private sealed record Line(ulong Va, string Text, AsmToken[] Tokens, double Width, string? Comment);

    public GraphView()
    {
        ClipToBounds = true;
        Focusable = true;
        BuildContextMenu();
        MeasureFont();
    }

    private void BuildContextMenu()
    {
        var menu = new ContextMenu();
        var rename = new MenuItem { Header = "Rename…" };
        rename.Click += (_, _) => { if (_menuVa != 0) RenameRequested?.Invoke(_menuVa); };
        var comment = new MenuItem { Header = "Set comment…" };
        comment.Click += (_, _) => { if (_menuVa != 0) CommentRequested?.Invoke(_menuVa); };
        var bookmark = new MenuItem { Header = "Toggle bookmark" };
        bookmark.Click += (_, _) => { if (_menuVa != 0) BookmarkToggleRequested?.Invoke(_menuVa); };
        var toggleBp = new MenuItem { Header = "Toggle breakpoint", InputGestureText = "F2 / F9" };
        toggleBp.Click += (_, _) => { if (_menuVa != 0) BreakpointToggleRequested?.Invoke(_menuVa); };
        var toggleJump = new MenuItem { Header = "Toggle jump", InputGestureText = "Space" };
        toggleJump.Click += (_, _) => { if (_menuVa != 0 && IsCondJumpAt(_menuVa)) ToggleJumpRequested?.Invoke(_menuVa); };
        menu.Opened += (_, _) =>
        {
            bool has = _menuVa != 0;
            rename.IsEnabled = comment.IsEnabled = bookmark.IsEnabled = toggleBp.IsEnabled = has;
            // "Toggle jump" flips a conditional jump's edge colours between green and red; enabled on any
            // conditional jump (click it repeatedly to toggle back and forth).
            toggleJump.IsEnabled = has && IsCondJumpAt(_menuVa);
        };
        menu.Items.Add(rename);
        menu.Items.Add(comment);
        menu.Items.Add(bookmark);
        menu.Items.Add(new Separator());
        menu.Items.Add(toggleBp);
        menu.Items.Add(toggleJump);
        ContextMenu = menu;
    }

    /// <summary>True when <paramref name="va"/> terminates a block with a Taken edge — i.e. it's a conditional
    /// jump, the only kind the "Toggle jump" colour mark applies to.</summary>
    private bool IsCondJumpAt(ulong va)
    {
        foreach (var b in _blocks)
            if (b.InstrVas.Count > 0 && b.InstrVas[^1] == va)
                foreach (var e in b.Out)
                    if (e.Kind == EdgeKind.Taken) return true;
        return false;
    }

    public void SetFunction(AnalysisResult result, Function function, IInstructionDecoder? decoder = null, bool autoFit = true)
    {
        _result = result;
        _function = function;
        _decoder = decoder;
        if (!function.BlocksBuilt)
            CfgBuilder.Build(result.Image, function, result.JumpTables, NeutralDisasm.For(result.Image, result.Names, decoder));

        _blocks.Clear();
        _byStart.Clear();
        _lines.Clear();
        _selVa = 0;
        _menuVa = 0;
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
        _selVa = 0;
        _menuVa = 0;
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

    /// <summary>Highlight <paramref name="va"/> as the selected instruction so the graph mirrors the linear
    /// view's caret — the two stay in step as you click/arrow around, not only on a debugger stop. When
    /// <paramref name="center"/> is set, scroll that instruction's block into view at the current zoom. Assumes
    /// the containing function is already loaded (the host calls <see cref="SetFunction"/> first when it changes).</summary>
    public void SetSelected(ulong va, bool center)
    {
        _selVa = va;
        if (center && va != 0 && _blocks.Any(b => va >= b.Start && va < b.End))
        {
            _pend = Pend.Focus; _pendVa = va; _pendResetZoom = false;
            ApplyPending();
        }
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
        INeutralDisassembler dis = NeutralDisasm.For(result.Image, result.Names, _decoder);

        foreach (var block in _blocks)
        {
            var list = new List<Line>(block.InstrVas.Count);
            foreach (var va in block.InstrVas)
            {
                var tokens = dis.Format(va).ToArray();
                if (tokens.Length == 0) continue;
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
        ulong entry = _byStart.ContainsKey(_function.EntryVa) ? _function.EntryVa : _blocks[0].Start;
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
            // When the user has toggled this block's terminating jump, colour its two outgoing edges by the mark:
            // green for the branch it's marked toward, red for the other. Otherwise use the static colours.
            bool? jt = b.InstrVas.Count > 0 ? JumpMark?.Invoke(b.InstrVas[^1]) : null;
            foreach (var e in b.Out)
            {
                if (!_byStart.TryGetValue(e.ToBlockStart, out var t)) continue;
                double tx = t.X + t.Width / 2, ty = t.Y;
                var brush = jt is bool taken && e.Kind is EdgeKind.Taken or EdgeKind.FallThrough
                    ? ((e.Kind == EdgeKind.Taken) == taken ? SyntaxTheme.EdgeTaken : Palette.RedBrush)
                    : e.Kind switch
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
            var row = new Rect(b.X + 1, y, b.Width - 2, _rowHeight);
            // Coverage tint first, so the current-IP band paints on top of it (matches the linear view).
            if (IsInstrHit?.Invoke(line.Va) == true)
                dc.DrawRectangle(SyntaxTheme.CoveredInstrGraph, null, row);
            // Current instruction: a brighter amber band plus a warm outline — the plain band is near-
            // invisible over the block's lighter surface, so the outline makes the row unmistakable.
            if (_ipVa != 0 && line.Va == _ipVa)
                dc.DrawRectangle(SyntaxTheme.CurrentIpGraph, SyntaxTheme.CurrentIpGraphOutline, row);
            else if (_selVa != 0 && line.Va == _selVa)   // selected instruction (F2/F9 target) — don't cover the IP
                dc.DrawRectangle(SyntaxTheme.Selection, null, row);
            // Breakpoint marker in the block's left padding (the graph has no gutter column).
            if (IsBreakpointAt?.Invoke(line.Va) == true)
            {
                var dot = IsHardwareBreakpointAt?.Invoke(line.Va) == true ? SyntaxTheme.HwBreakpointDot : SyntaxTheme.BreakpointDot;
                dc.DrawEllipse(dot, null, new Point(b.X + 4, y + _rowHeight / 2), 3, 3);
            }
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

    /// <summary>The instruction VA under a screen point (inside a block's instruction rows), or 0 if none.</summary>
    private ulong InstrAt(Point screen)
    {
        var g = ToGraph(screen);
        foreach (var b in _blocks)
        {
            if (g.X < b.X || g.X > b.X + b.Width || g.Y < b.Y || g.Y > b.Y + b.Height) continue;
            if (g.Y < b.Y + HeaderH + 1) return 0;   // click is in the block header, not on an instruction row
            var lines = _lines[b.Start];
            int idx = (int)((g.Y - (b.Y + HeaderH + 1)) / _rowHeight);
            return idx >= 0 && idx < lines.Count ? lines[idx].Va : 0;
        }
        return 0;
    }

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
        ulong clicked = InstrAt(_lastDrag);   // exact instruction under the cursor (0 on a block header)
        _selVa = clicked;                     // remember it so F2/F9 can toggle a breakpoint on it
        foreach (var b in _blocks)
            if (g.X >= b.X && g.X <= b.X + b.Width && g.Y >= b.Y && g.Y <= b.Y + b.Height)
            { BlockSelected?.Invoke(clicked != 0 ? clicked : b.Start); break; }   // sync linear to the exact line
        InvalidateVisual();   // reflect the new selection highlight
    }

    protected override void OnMouseRightButtonDown(MouseButtonEventArgs e)
    {
        // Record the instruction under the cursor so the (auto-shown) context menu toggles a breakpoint there.
        // Don't set e.Handled — WPF still needs to open the ContextMenu on right-button-up.
        Focus();
        _menuVa = InstrAt(e.GetPosition(this));
    }

    protected override void OnKeyDown(KeyEventArgs e)
    {
        switch (e.Key)
        {
            case Key.F2 or Key.F9: if (_selVa != 0) BreakpointToggleRequested?.Invoke(_selVa); break;
            case Key.Space: if (_selVa != 0 && IsCondJumpAt(_selVa)) ToggleJumpRequested?.Invoke(_selVa); break;
            default: return;
        }
        e.Handled = true;
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

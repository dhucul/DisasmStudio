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
    private long _caretInstr = -1;  // caret instruction index, or -1
    private long _selAnchor = -1;   // selection anchor; range = [min,max] of anchor & caret
    private bool _dragging;
    private bool _draggingDivider;
    private double _disasmGapChars = 28;   // bytes→disasm gap in chars; draggable via the column divider

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
        _selAnchor = -1;
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
        _selAnchor = line;
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
    private double DisasmX => BytesX + _disasmGapChars * _charWidth;

    private bool NearDivider(double x) => Math.Abs(x - DisasmX) <= 5;

    /// <summary>How many opcode bytes fit in the bytes column at the current divider width.</summary>
    private int BytesColMax() => Math.Max(1, (int)((DisasmX - BytesX - _charWidth) / (3 * _charWidth)));

    private void SetDisasmGap(double mouseX)
    {
        _disasmGapChars = Math.Clamp((mouseX - BytesX) / _charWidth, 26, 160);
        _surface.InvalidateVisual();
    }

    private void MoveCaret(long newInstr, bool extend = false)
    {
        if (_result is null) return;
        _caretInstr = Math.Clamp(newInstr, 0, _result.Linear.Count - 1);
        if (!extend || _selAnchor < 0) _selAnchor = _caretInstr;   // collapse selection unless extending
        EnsureCaretVisible();
        _surface.InvalidateVisual();
        SelectionChanged?.Invoke(_result.Linear.VaAt(_caretInstr));
    }

    /// <summary>Selected instruction-line range [Lo, Hi], or (-1,-1) when nothing is selected.</summary>
    private (long Lo, long Hi) SelRange()
    {
        if (_caretInstr < 0) return (-1, -1);
        long a = _selAnchor < 0 ? _caretInstr : _selAnchor;
        return (Math.Min(a, _caretInstr), Math.Max(a, _caretInstr));
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
        if (_result.Linear.IsDataAt(_caretInstr)) return;   // data line — nothing to follow
        ulong va = _result.Linear.VaAt(_caretInstr);
        if (!_dis.TryDecodeAt(va, out var instr)) return;
        if (FlowAnalysis.DirectBranchTarget(instr) is ulong t && _result.Image.IsMappedVa(t))
            NavigateRequested?.Invoke(t);
    }

    private ulong CaretVa => _result is not null && _caretInstr >= 0 ? _result.Linear.VaAt(_caretInstr) : 0;

    // ---- hit testing ----
    private void OnClick(Point p, bool extend = false)
    {
        if (_result is null) return;
        long display = Math.Clamp(_topDisplay + (long)(p.Y / _rowHeight), 0, Math.Max(0, DisplayCount - 1));
        var (_, instrLine) = ContentAt(display);
        _caretInstr = instrLine;
        if (!extend || _selAnchor < 0) _selAnchor = instrLine;   // shift-click extends; plain click collapses
        _surface.InvalidateVisual();
        SelectionChanged?.Invoke(_result.Linear.VaAt(instrLine));
    }

    /// <summary>Extend the selection to the line under the cursor (drag), auto-scrolling at the edges.</summary>
    private void DragTo(Point p)
    {
        if (_result is null) return;
        if (p.Y < 0) ScrollByLines(-1);
        else if (p.Y >= _surface.ActualHeight) ScrollByLines(1);
        double cy = Math.Clamp(p.Y, 0, Math.Max(0, _surface.ActualHeight - 1));
        OnClick(new Point(p.X, cy), extend: true);
    }

    private void SelectAll()
    {
        if (_result is null || _result.Linear.Count == 0) return;
        _selAnchor = 0;
        _caretInstr = _result.Linear.Count - 1;
        _surface.InvalidateVisual();
    }

    /// <summary>Copy the selected lines (address + disassembly / data + comment) to the clipboard, as text.</summary>
    private void CopySelection()
    {
        if (_result is null || _dis is null || _fmt is null) return;
        var (lo, hi) = SelRange();
        if (lo < 0) return;
        long cap = Math.Min(hi, lo + 200_000);   // bound a runaway select-all copy
        var sb = new System.Text.StringBuilder();
        for (long line = lo; line <= cap; line++) sb.AppendLine(LineToText(line));
        try { Clipboard.SetText(sb.ToString()); } catch { /* clipboard busy */ }
    }

    private string LineToText(long line)
    {
        ulong va = _result!.Linear.VaAt(line);
        string addr = va.ToString("X" + _addrDigits);
        if (_result.Linear.IsDataAt(line))
        {
            long rawLen = line + 1 < _result.Linear.Count ? (long)(_result.Linear.VaAt(line + 1) - va) : 1;
            var bytes = _result.Image.ReadBytesAtVa(va, (int)Math.Clamp(rawLen, 1, 256));
            var (d, v, _) = ClassifyData(va, bytes);
            return $"{addr}  {Hex(bytes)}  {d}{v}";
        }
        if (!_dis!.TryDecodeAt(va, out var instr)) return $"{addr}  ??";
        string text = _fmt!.FormatText(instr);
        if (_result.Comments.TryGetValue(va, out var c)) text += "   ; " + c;
        return $"{addr}  {Hex(_result.Image.ReadBytesAtVa(va, instr.Length))}  {text}";
    }

    private static string Hex(byte[] b) => string.Join(" ", b.Select(x => x.ToString("x2")));

    // ---- rendering ----
    private void Render(DrawingContext dc, double width, double height)
    {
        dc.DrawRectangle(SyntaxTheme.Background, null, new Rect(0, 0, width, height));
        dc.DrawRectangle(SyntaxTheme.GutterBg, null, new Rect(0, 0, GutterW, height));
        if (_result is null || _dis is null || _fmt is null) return;

        double dpi = VisualTreeHelper.GetDpi(this).PixelsPerDip;
        int rows = (int)(height / _rowHeight) + 1;
        var (selLo, selHi) = SelRange();

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

            if (selLo >= 0 && instrLine >= selLo && instrLine <= selHi)
                dc.DrawRectangle(SyntaxTheme.Selection, null, new Rect(GutterW, y, width - GutterW, _rowHeight));

            if (_result.Linear.IsDataAt(instrLine)) DrawData(dc, instrLine, va, y, dpi);
            else DrawInstruction(dc, va, y, dpi);
        }

        DrawBranchArrows(dc, rows);

        // Draggable column divider between the bytes and disassembly columns.
        double dx = Math.Round(DisasmX) - 2.5;
        dc.DrawLine(new Pen(SyntaxTheme.Separator, 1), new Point(dx, 0), new Point(dx, height));
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

        // Bytes — as many as fit in the (draggable) bytes column; '+' if more remain.
        int maxBytes = BytesColMax();
        var bytes = _result!.Image.ReadBytesAtVa(va, Math.Min(instr.Length, maxBytes));
        var hex = new System.Text.StringBuilder();
        foreach (var b in bytes) hex.Append(b.ToString("x2")).Append(' ');
        if (instr.Length > maxBytes) hex.Append('+');
        Draw(dc, hex.ToString(), BytesX, y, SyntaxTheme.Bytes, dpi);

        // Disassembly tokens.
        double x = DisasmX;
        foreach (var tok in _fmt!.Format(instr))
            x = Draw(dc, tok.Text, x, y, SyntaxTheme.BrushFor(tok.Kind), dpi);

        // Inline comment (referenced string, etc.).
        if (_result.Comments.TryGetValue(va, out var comment))
            Draw(dc, "   ; " + comment, x + _charWidth, y, SyntaxTheme.Comment, dpi);
    }

    // A data run (padding / jump table / literal) classified out of the code: render as a string,
    // an aligned pointer (dd/dq, named if known), or a db byte row.
    private void DrawData(DrawingContext dc, long line, ulong va, double y, double dpi)
    {
        Draw(dc, va.ToString("X" + _addrDigits), AddrX, y, SyntaxTheme.Address, dpi);

        long rawLen = line + 1 < _result!.Linear.Count ? (long)(_result.Linear.VaAt(line + 1) - va) : 1;
        int len = (int)Math.Clamp(rawLen, 1, 256);
        var bytes = _result.Image.ReadBytesAtVa(va, len);
        if (bytes.Length == 0) { Draw(dc, "??", DisasmX, y, SyntaxTheme.Comment, dpi); return; }

        int maxBytes = BytesColMax();
        var hexCol = new System.Text.StringBuilder();
        for (int i = 0; i < bytes.Length && i < maxBytes; i++) hexCol.Append(bytes[i].ToString("x2")).Append(' ');
        if (bytes.Length > maxBytes) hexCol.Append('+');
        Draw(dc, hexCol.ToString(), BytesX, y, SyntaxTheme.Bytes, dpi);

        var (directive, value, valueBrush) = ClassifyData(va, bytes);
        double x = Draw(dc, directive, DisasmX, y, SyntaxTheme.Keyword, dpi);
        Draw(dc, value, x, y, valueBrush, dpi);
    }

    /// <summary>Decide how a data run renders: db "string" / dd|dq pointer (named if known) / db byte row.</summary>
    private (string Directive, string Value, Brush Brush) ClassifyData(ulong va, byte[] bytes)
    {
        if (Array.TrueForAll(bytes, b => b == 0xCC))   // int3 alignment padding
            return ("int3", bytes.Length > 1 ? $"  × {bytes.Length}" : "", SyntaxTheme.Comment);

        if ((bytes.Length == 4 || bytes.Length == 8) &&
            _result!.Image.IsMappedVa(bytes.Length == 8 ? BitConverter.ToUInt64(bytes, 0) : BitConverter.ToUInt32(bytes, 0)))
        {
            ulong v = bytes.Length == 8 ? BitConverter.ToUInt64(bytes, 0) : BitConverter.ToUInt32(bytes, 0);
            string? name = _result.NameFor(v);
            return (bytes.Length == 8 ? "dq " : "dd ", name ?? $"0x{v:X}", name is not null ? SyntaxTheme.Symbol : SyntaxTheme.Number);
        }
        if (TryFormatString(bytes, out string str)) return ("db ", str, SyntaxTheme.Symbol);

        var sb = new System.Text.StringBuilder();
        for (int i = 0; i < bytes.Length && i < 16; i++) { if (i > 0) sb.Append(", "); sb.Append("0x").Append(bytes[i].ToString("X2")); }
        if (bytes.Length > 16) sb.Append(", …");
        return ("db ", sb.ToString(), SyntaxTheme.Bytes);
    }

    private static bool TryFormatString(byte[] b, out string text)
    {
        text = "";
        bool ascii = b.Length >= 3;
        for (int i = 0; ascii && i < b.Length; i++)
            if (b[i] is not (>= 0x20 and < 0x7F or 0x09) && !(b[i] == 0 && i == b.Length - 1)) ascii = false;
        if (ascii) { text = Quote(b, wide: false); return true; }

        if (b.Length >= 6 && b.Length % 2 == 0)
        {
            bool wide = true;
            for (int i = 0; wide && i < b.Length; i += 2)
                if (b[i + 1] != 0 || b[i] is not (>= 0x20 and < 0x7F or 0x09 or 0)) wide = false;
            if (wide) { text = Quote(b, wide: true); return true; }
        }
        return false;
    }

    private static string Quote(byte[] b, bool wide)
    {
        var sb = new System.Text.StringBuilder(wide ? "L\"" : "\"");
        for (int i = 0; i < b.Length; i += wide ? 2 : 1)
        {
            byte c = b[i];
            if (c == 0) break;
            sb.Append(c is >= 0x20 and < 0x7F ? (char)c : '.');
        }
        sb.Append('"');
        return sb.ToString();
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
            if (isLabel || _result.Linear.IsDataAt(instrLine)) continue;
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
        var copy = new MenuItem { Header = "Copy", InputGestureText = "Ctrl+C" };
        copy.Click += (_, _) => CopySelection();
        var selectAll = new MenuItem { Header = "Select all", InputGestureText = "Ctrl+A" };
        selectAll.Click += (_, _) => SelectAll();
        var xref = new MenuItem { Header = "Show xrefs to this address" };
        xref.Click += (_, _) => { if (CaretVa != 0) ShowXrefsRequested?.Invoke(CaretVa); };
        var graph = new MenuItem { Header = "Open function in graph" };
        graph.Click += (_, _) => { if (CaretVa != 0) OpenInGraphRequested?.Invoke(CaretVa); };
        var follow = new MenuItem { Header = "Follow target", InputGestureText = "Enter" };
        follow.Click += (_, _) => FollowCaret();
        menu.Items.Add(copy);
        menu.Items.Add(selectAll);
        menu.Items.Add(new Separator());
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
            var p = e.GetPosition(this);
            if (_owner.NearDivider(p.X))   // grab the column divider instead of selecting
            {
                _owner._draggingDivider = true;
                CaptureMouse();
                e.Handled = true;
                return;
            }
            _owner.OnClick(p, extend: (Keyboard.Modifiers & ModifierKeys.Shift) != 0);
            if (e.ClickCount == 2) _owner.FollowCaret();
            else { _owner._dragging = true; CaptureMouse(); }
            e.Handled = true;
        }

        protected override void OnMouseMove(MouseEventArgs e)
        {
            var p = e.GetPosition(this);
            if (_owner._draggingDivider && e.LeftButton == MouseButtonState.Pressed) { _owner.SetDisasmGap(p.X); return; }
            if (_owner._dragging && e.LeftButton == MouseButtonState.Pressed) { _owner.DragTo(p); return; }
            Cursor = _owner.NearDivider(p.X) ? Cursors.SizeWE : Cursors.Arrow;
        }

        protected override void OnMouseLeftButtonUp(MouseButtonEventArgs e)
        {
            if (_owner._draggingDivider) { _owner._draggingDivider = false; ReleaseMouseCapture(); }
            if (_owner._dragging) { _owner._dragging = false; ReleaseMouseCapture(); }
        }

        protected override void OnMouseRightButtonDown(MouseButtonEventArgs e)
        {
            Focus();
            // Don't collapse an existing multi-line selection when right-clicking inside it.
            var (lo, hi) = _owner.SelRange();
            long line = _owner._topDisplay + (long)(e.GetPosition(this).Y / _owner._rowHeight);
            var (_, instr) = _owner.ContentAt(Math.Clamp(line, 0, Math.Max(0, _owner.DisplayCount - 1)));
            if (!(lo >= 0 && instr >= lo && instr <= hi)) _owner.OnClick(e.GetPosition(this));
        }

        protected override void OnKeyDown(KeyEventArgs e)
        {
            if (_owner._result is null) return;
            bool ext = (Keyboard.Modifiers & ModifierKeys.Shift) != 0;
            bool ctrl = (Keyboard.Modifiers & ModifierKeys.Control) != 0;
            switch (e.Key)
            {
                case Key.Down: _owner.MoveCaret(_owner._caretInstr + 1, ext); break;
                case Key.Up: _owner.MoveCaret(_owner._caretInstr - 1, ext); break;
                case Key.PageDown: _owner.MoveCaret(_owner._caretInstr + _owner.VisibleRows, ext); break;
                case Key.PageUp: _owner.MoveCaret(_owner._caretInstr - _owner.VisibleRows, ext); break;
                case Key.Home: _owner.MoveCaret(0, ext); break;
                case Key.End: _owner.MoveCaret(_owner._result.Linear.Count - 1, ext); break;
                case Key.Enter: _owner.FollowCaret(); break;
                case Key.C when ctrl: _owner.CopySelection(); break;
                case Key.A when ctrl: _owner.SelectAll(); break;
                case Key.G when ctrl: _owner.GoToRequested?.Invoke(); break;
                default: return;
            }
            e.Handled = true;
        }

        protected override void OnRender(DrawingContext dc) => _owner.Render(dc, ActualWidth, ActualHeight);
    }
}

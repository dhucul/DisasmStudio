using System.Globalization;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Input;
using System.Windows.Media;
using DisasmStudio.Core.Analysis;
using DisasmStudio.Core.Disasm;
using DisasmStudio.Wpf.Services;

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
    private INeutralDisassembler? _dis;
    private ulong _ipVa;   // debuggee's current instruction (0 = not debugging)

    // Label lines (function starts + named locs), as parallel sorted arrays.
    private long[] _labelInstrLines = [];
    private ulong[] _labelVa = [];

    // Collapsible section regions (editor-style folding): each section / the PE header that's present in the
    // listing can collapse to a single header row via the [+]/[−] gutter marker. _hidden holds the hidden
    // display-row ranges for the currently-collapsed regions; it's empty (identity mapping) until you collapse.
    private (ulong Va, long StartLine, long EndLine, string Name)[] _regions = [];
    private readonly HashSet<ulong> _collapsed = [];
    private (long Start, long End)[] _hidden = [];   // sorted, non-overlapping display-row ranges

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
    public event Action<ulong>? OpenInDecompilerRequested;
    public event Action<ulong>? SaveAsmRequested;
    public event Action<ulong>? PatchRequested;
    public event Action<ulong>? BreakpointToggleRequested;
    /// <summary>Set a hardware breakpoint / watchpoint at the address (right-click → Hardware breakpoint…).</summary>
    public event Action<ulong>? HardwareBreakpointRequested;
    /// <summary>Edit the condition / hit-count / enabled state of the breakpoint at the address.</summary>
    public event Action<ulong>? EditBreakpointRequested;
    public event Action<ulong>? RunToCursorRequested;
    public event Action? RunToReturnRequested;
    public event Action<ulong>? CaptureFunctionRequested;
    /// <summary>A transient one-line status message (e.g. why "Follow target" did nothing).</summary>
    public event Action<string>? StatusRequested;

    /// <summary>Set the debuggee's current instruction (highlighted + centred); 0 clears it.</summary>
    public void SetCurrentIp(ulong va) { _ipVa = va; if (va != 0) GoToVa(va); else _surface.InvalidateVisual(); }
    /// <summary>Predicate the gutter uses to mark addresses that have a breakpoint.</summary>
    public Func<ulong, bool>? IsBreakpointAt { get; set; }
    /// <summary>Predicate the gutter uses to colour a hardware breakpoint's dot differently from a software one.</summary>
    public Func<ulong, bool>? IsHardwareBreakpointAt { get; set; }
    /// <summary>Predicate the renderer uses to tint instructions that have executed (coverage overlay).</summary>
    public Func<ulong, bool>? IsInstrHit { get; set; }

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

    /// <summary>Repaint (e.g. a data byte changed underneath, no index change).</summary>
    public void Refresh() => _surface.InvalidateVisual();

    /// <summary>Rebuild labels and repaint after the result's index was spliced (local patch repair),
    /// keeping the current scroll/caret rather than resetting like <see cref="SetResult"/>.</summary>
    public void RefreshAfterPatch()
    {
        if (_result is null) return;
        BuildLabelLines(_result);
        BuildRegions(_result);
        ConfigureScroll();
        _surface.InvalidateVisual();
    }

    public void SetResult(AnalysisResult? result) => SetResult(result, null);

    /// <summary>Show <paramref name="result"/>, decoding through <paramref name="decoder"/> (the live
    /// process-memory decoder while debugging) or the static file decoder when null.</summary>
    public void SetResult(AnalysisResult? result, IInstructionDecoder? decoder)
    {
        // Collapse state is per-document: drop it when the image changes (a new file / the debug swap), but
        // keep it across a same-image re-analysis (loading or unloading a section) so folds aren't lost.
        if (!ReferenceEquals(result?.Image, _result?.Image)) _collapsed.Clear();
        _result = result;
        _caretInstr = -1;
        _selAnchor = -1;
        _topDisplay = 0;
        if (result is null) { _dis = null; _labelInstrLines = []; _labelVa = []; }
        else
        {
            _dis = NeutralDisasm.For(result.Image, result.Names, decoder);
            _addrDigits = Math.Max(8, result.Image.MaxVa.ToString("X").Length);
            BuildLabelLines(result);
            BuildRegions(result);
        }
        ConfigureScroll();
        _surface.InvalidateVisual();
    }

    /// <summary>Centre the view on a VA and select that instruction.</summary>
    public void GoToVa(ulong va)
    {
        if (_result is null || _result.Linear.Count == 0) return;
        long line = _result.Linear.IndexOf(va);
        _caretInstr = line;
        _selAnchor = line;
        // If the target sits inside a collapsed region, expand it so the jump is actually visible.
        int rc = RegionContaining(line);
        if (rc >= 0 && line > _regions[rc].StartLine && _collapsed.Contains(_regions[rc].Va))
        { _collapsed.Remove(_regions[rc].Va); RebuildHidden(); ConfigureScroll(); }
        long disp = DisplayIndexOfInstr(line);
        long vis = ToVisible(disp);
        if (vis < 0) vis = 0;   // defensive: target still hidden → top
        long firstThird = Math.Max(0, VisibleRows / 3);
        _topDisplay = Math.Clamp(vis - firstThird, 0, Math.Max(0, VisibleCount - 1));
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
        // A label is any named address that lands exactly on a line in the listing — code symbols
        // (sub_/loc_/imports) and the data landmarks for a folded-in section or the PE header (HEADER, .rdata…).
        var seen = new HashSet<long>();
        foreach (var (va, _) in result.Names)
        {
            long line = result.Linear.IndexOf(va);
            if (result.Linear.VaAt(line) != va) continue; // not a line boundary in the listing
            if (!seen.Add(line)) continue;
            lines.Add(line);
            vas.Add(va);
        }
        // Sort both by line.
        var order = Enumerable.Range(0, lines.Count).OrderBy(i => lines[i]).ToArray();
        _labelInstrLines = order.Select(i => lines[i]).ToArray();
        _labelVa = order.Select(i => vas[i]).ToArray();
    }

    // ---- collapsible section regions ----
    private void BuildRegions(AnalysisResult result)
    {
        var list = new List<(ulong, long, long, string)>();
        long n = result.Linear.Count;

        void Add(ulong startVa, ulong endVa, string name)
        {
            if (n == 0) return;
            long sl = result.Linear.IndexOf(startVa);
            if (result.Linear.VaAt(sl) != startVa) return;             // section not present in the listing
            long el = result.Linear.IndexOf(endVa);
            if (el < n && result.Linear.VaAt(el) < endVa) el++;        // make end exclusive (first line at/after endVa)
            el = Math.Min(el, n);
            if (el > sl + 1) list.Add((startVa, sl, el, name));         // need ≥1 content line to be worth collapsing
        }

        if (result.Image.HeaderRegion is { FileSize: > 0 } h) Add(h.StartVa, h.StartVa + (ulong)h.FileSize, "HEADER");
        foreach (var s in result.Image.Sections)
            if (s.FileSize > 0)
                Add(s.StartVa, s.StartVa + (s.VirtualSize > 0 ? Math.Min(s.VirtualSize, (ulong)s.FileSize) : (ulong)s.FileSize), s.Name);

        list.Sort((a, b) => a.Item2.CompareTo(b.Item2));
        _regions = list.ToArray();
        _collapsed.RemoveWhere(va => !Array.Exists(_regions, r => r.Va == va));   // drop stale collapse state
        RebuildHidden();
    }

    /// <summary>Recompute the hidden display-row ranges for the currently-collapsed regions. A collapsed region
    /// keeps its first row (rendered as the summary) and hides the rest: (header+1 .. region end).</summary>
    private void RebuildHidden()
    {
        if (_collapsed.Count == 0) { _hidden = []; return; }
        var ranges = new List<(long, long)>();
        foreach (var (va, sl, el, _) in _regions)
        {
            if (!_collapsed.Contains(va)) continue;
            long dStart = DisplayIndexOfInstr(sl) + 1;   // keep the header row at sl, hide everything after it
            long dEnd = DisplayIndexOfInstr(el);
            if (dEnd > dStart) ranges.Add((dStart, dEnd));
        }
        ranges.Sort((a, b) => a.Item1.CompareTo(b.Item1));
        _hidden = ranges.ToArray();
    }

    private long HiddenTotal { get { long t = 0; foreach (var (s, e) in _hidden) t += e - s; return t; } }

    /// <summary>Visible display rows (total display rows minus the rows hidden inside collapsed regions).</summary>
    private long VisibleCount => Math.Max(0, DisplayCount - HiddenTotal);

    /// <summary>Map a visible row index to the underlying display-row index (skips collapsed ranges).</summary>
    private long ToDisplay(long visible)
    {
        long d = visible;
        foreach (var (s, e) in _hidden) { if (s <= d) d += e - s; else break; }
        return d;
    }

    /// <summary>Map a display-row index to its visible index, or -1 if that row is hidden in a collapsed region.</summary>
    private long ToVisible(long display)
    {
        long sub = 0;
        foreach (var (s, e) in _hidden)
        {
            if (e <= display) sub += e - s;
            else if (s <= display) return -1;   // inside a collapsed range
            else break;
        }
        return display - sub;
    }

    /// <summary>The collapsible region whose header (first) line is exactly <paramref name="instrLine"/>, or null.</summary>
    private int RegionStartAt(long instrLine)
    {
        for (int i = 0; i < _regions.Length; i++) if (_regions[i].StartLine == instrLine) return i;
        return -1;
    }

    /// <summary>Index of the region whose content range [Start, End) contains <paramref name="instrLine"/>, or -1.</summary>
    private int RegionContaining(long instrLine)
    {
        for (int i = 0; i < _regions.Length; i++)
            if (instrLine >= _regions[i].StartLine && instrLine < _regions[i].EndLine) return i;
        return -1;
    }

    private void ToggleCollapse(ulong va)
    {
        // Anchor the content currently at the top so the viewport doesn't jump when a region above it
        // collapses/expands (the visible-row index would otherwise point at different content).
        long topLine = _result is not null ? ContentAt(ToDisplay(_topDisplay)).InstrLine : 0;

        if (!_collapsed.Add(va)) _collapsed.Remove(va);
        RebuildHidden();

        long anchorVis = ToVisible(DisplayIndexOfInstr(topLine));
        if (anchorVis < 0)   // the anchor line is now hidden → use its region's header
        {
            int rc = RegionContaining(topLine);
            anchorVis = rc >= 0 ? ToVisible(DisplayIndexOfInstr(_regions[rc].StartLine)) : 0;
        }
        _topDisplay = Math.Clamp(Math.Max(0, anchorVis), 0, Math.Max(0, VisibleCount - 1));
        ConfigureScroll();
        _surface.InvalidateVisual();
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
        if (_result is null || _result.Linear.Count == 0) return (false, 0);
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
        _scroll.Maximum = Math.Max(0, VisibleCount - VisibleRows);
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
        _topDisplay = Math.Clamp(_topDisplay + delta, 0, Math.Max(0, VisibleCount - 1));
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
        if (_result is null || _result.Linear.Count == 0) return;   // empty index: Clamp(_,0,-1) would throw
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
        long caretVis = ToVisible(DisplayIndexOfInstr(_caretInstr));
        if (caretVis < 0)
        {
            // Keyboard nav moved the caret into a collapsed region — expand it so the caret stays visible
            // (otherwise the selection would silently traverse hidden lines).
            int rc = RegionContaining(_caretInstr);
            if (rc >= 0 && _collapsed.Remove(_regions[rc].Va)) { RebuildHidden(); ConfigureScroll(); }
            caretVis = ToVisible(DisplayIndexOfInstr(_caretInstr));
            if (caretVis < 0) return;
        }
        if (caretVis < _topDisplay) _topDisplay = caretVis;
        else if (caretVis >= _topDisplay + VisibleRows) _topDisplay = caretVis - VisibleRows + 1;
        _topDisplay = Math.Clamp(_topDisplay, 0, Math.Max(0, VisibleCount - 1));
        SyncScrollValue();
    }

    private void FollowCaret()
    {
        if (_result is null || _dis is null || _caretInstr < 0) return;
        if (_result.Linear.IsDataAt(_caretInstr)) { StatusRequested?.Invoke("Follow: data line — nothing to follow."); return; }
        ulong va = _result.Linear.VaAt(_caretInstr);
        if (!_dis.TryDecode(va, out var instr)) { StatusRequested?.Invoke("Follow: this line can't be decoded."); return; }
        if (instr.DirectTarget is ulong t)
        {
            if (_result.Image.IsMappedVa(t)) { NavigateRequested?.Invoke(t); StatusRequested?.Invoke($"Followed → {NameOrAddr(t)}"); }
            else StatusRequested?.Invoke($"Follow: target {t:X} is outside the loaded image.");
            return;
        }
        StatusRequested?.Invoke(instr.Flow is FlowKind.IndirectJump or FlowKind.IndirectCall
            ? "Follow: indirect target — can't be resolved statically (run the debugger to follow it live)."
            : "Follow: no branch or call on this line.");
    }

    /// <summary>The direct branch/call target under the caret, or null when this line has nothing to follow
    /// (data, an indirect/non-branch instruction, or a target outside the image).</summary>
    private ulong? CaretFollowTarget()
    {
        if (_result is null || _dis is null || _caretInstr < 0 || _result.Linear.IsDataAt(_caretInstr)) return null;
        ulong va = _result.Linear.VaAt(_caretInstr);
        if (!_dis.TryDecode(va, out var instr)) return null;
        return instr.DirectTarget is ulong t && _result.Image.IsMappedVa(t) ? t : null;
    }

    private string NameOrAddr(ulong va) => _result?.NameFor(va) is { Length: > 0 } n ? n : va.ToString("X" + _addrDigits);

    private ulong CaretVa => _result is not null && _caretInstr >= 0 ? _result.Linear.VaAt(_caretInstr) : 0;

    // ---- hit testing ----
    private void OnClick(Point p, bool extend = false)
    {
        if (_result is null) return;
        long display = ToDisplay(Math.Clamp(_topDisplay + (long)(p.Y / _rowHeight), 0, Math.Max(0, VisibleCount - 1)));
        var (isLabel, instrLine) = ContentAt(display);

        // Click on the [+]/[−] gutter marker of a section header row → collapse/expand instead of selecting.
        if (!extend && !isLabel && p.X <= GutterW)
        {
            int ri = RegionStartAt(instrLine);
            if (ri >= 0) { ToggleCollapse(_regions[ri].Va); return; }
        }

        _caretInstr = instrLine;
        if (!extend || _selAnchor < 0) _selAnchor = instrLine;   // shift-click extends; plain click collapses
        _surface.InvalidateVisual();
        SelectionChanged?.Invoke(_result.Linear.VaAt(instrLine));
    }

    /// <summary>True if <paramref name="p"/> falls in the left gutter margin on a code line — the breakpoint
    /// strip, where a click toggles a breakpoint (Visual Studio–style). Outputs that instruction line. Section
    /// headers (collapse markers), label rows and data lines are not breakpoint rows, so folding/selection on
    /// them is unaffected.</summary>
    private bool InBreakpointGutter(Point p, out long instrLine)
    {
        instrLine = -1;
        if (_result is null || _dis is null || p.X > GutterW) return false;
        long display = ToDisplay(Math.Clamp(_topDisplay + (long)(p.Y / _rowHeight), 0, Math.Max(0, VisibleCount - 1)));
        var (isLabel, line) = ContentAt(display);
        if (isLabel || RegionStartAt(line) >= 0 || line < 0 || line >= _result.Linear.Count || _result.Linear.IsDataAt(line)) return false;
        instrLine = line;
        return true;
    }

    private void ToggleBreakpointAtLine(long instrLine)
    {
        if (_result is null) return;
        _caretInstr = instrLine;
        if (_selAnchor < 0) _selAnchor = instrLine;
        _surface.InvalidateVisual();
        ulong va = _result.Linear.VaAt(instrLine);
        BreakpointToggleRequested?.Invoke(va);
        SelectionChanged?.Invoke(va);
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
        if (_result is null || _dis is null) return;
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
            string dataText = $"{addr}  {Hex(bytes)}  {d}{v}";
            if (_result.Comments.TryGetValue(va, out var dcm)) dataText += "   ; " + dcm;
            return dataText;
        }
        if (!_dis!.TryDecode(va, out var instr)) return $"{addr}  ??";
        string text = string.Concat(_dis.Format(va).Select(t => t.Text));
        if (_result.Comments.TryGetValue(va, out var c)) text += "   ; " + c;
        return $"{addr}  {Hex(_result.Image.ReadBytesAtVa(va, instr.Length))}  {text}";
    }

    private static string Hex(byte[] b) => string.Join(" ", b.Select(x => x.ToString("x2")));

    // ---- rendering ----
    private void Render(DrawingContext dc, double width, double height)
    {
        dc.DrawRectangle(SyntaxTheme.Background, null, new Rect(0, 0, width, height));
        dc.DrawRectangle(SyntaxTheme.GutterBg, null, new Rect(0, 0, GutterW, height));
        if (_result is null || _dis is null) return;

        double dpi = VisualTreeHelper.GetDpi(this).PixelsPerDip;
        int rows = (int)(height / _rowHeight) + 1;
        var (selLo, selHi) = SelRange();

        for (int r = 0; r < rows; r++)
        {
            long visible = _topDisplay + r;
            if (visible >= VisibleCount) break;
            long display = ToDisplay(visible);
            double y = r * _rowHeight;
            var (isLabel, instrLine) = ContentAt(display);
            ulong va = _result.Linear.VaAt(instrLine);

            if (isLabel)
            {
                DrawLabel(dc, va, y, width, dpi);
                continue;
            }

            // Collapsible section header row: draw the [+]/[−] gutter marker, and when collapsed render a
            // one-line summary in place of the section's content.
            int ri = RegionStartAt(instrLine);
            if (ri >= 0)
            {
                bool collapsed = _collapsed.Contains(_regions[ri].Va);
                Draw(dc, collapsed ? "[+]" : "[-]", 2, y, SyntaxTheme.Comment, dpi);
                if (collapsed)
                {
                    long hiddenLines = _regions[ri].EndLine - _regions[ri].StartLine - 1;
                    Draw(dc, $"{va.ToString("X" + _addrDigits)}  ", AddrX, y, SyntaxTheme.Address, dpi);
                    Draw(dc, $"{_regions[ri].Name}  —  {hiddenLines:N0} lines collapsed (click [+])", DisasmX, y, SyntaxTheme.Comment, dpi);
                    continue;
                }
            }

            // Coverage tint first, so the current-IP amber and the selection paint on top of it.
            if (IsInstrHit?.Invoke(va) == true)
                dc.DrawRectangle(SyntaxTheme.CoveredInstr, null, new Rect(GutterW, y, width - GutterW, _rowHeight));
            if (_ipVa != 0 && va == _ipVa)
                dc.DrawRectangle(SyntaxTheme.CurrentIp, null, new Rect(GutterW, y, width - GutterW, _rowHeight));
            if (IsBreakpointAt?.Invoke(va) == true)
            {
                var dot = IsHardwareBreakpointAt?.Invoke(va) == true ? SyntaxTheme.HwBreakpointDot : SyntaxTheme.BreakpointDot;
                dc.DrawEllipse(dot, null, new Point(GutterW - _charWidth, y + _rowHeight / 2), 4, 4);
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

        if (!_dis!.TryDecode(va, out var instr))
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
        foreach (var tok in _dis.Format(va))
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
        x = Draw(dc, value, x, y, valueBrush, dpi);

        // Inline comment (PE header field name, section banner, referenced string, …).
        if (_result.Comments.TryGetValue(va, out var comment))
            Draw(dc, "   ; " + comment, x + _charWidth, y, SyntaxTheme.Comment, dpi);
    }

    /// <summary>Decide how a data run renders: int3 padding / db "string" / a sized scalar dw|dd|dq
    /// (pointers named if known) / a db byte row.</summary>
    private (string Directive, string Value, Brush Brush) ClassifyData(ulong va, byte[] bytes)
    {
        if (Array.TrueForAll(bytes, b => b == 0xCC))   // int3 alignment padding
            return ("int3", bytes.Length > 1 ? $"  × {bytes.Length}" : "", SyntaxTheme.Comment);

        // ARM firmware is full of numeric tables whose bytes fall in the printable range; requiring a run
        // longer than a word keeps a lone printable dword rendering as dd instead of a spurious 4-char string.
        int minStr = _result!.Image.IsArm ? 5 : 3;
        if (TryFormatString(bytes, minStr, out string str)) return ("db ", str, SyntaxTheme.Symbol);

        // A 1/2/4/8-byte run renders as a sized scalar; 4/8-byte values that point into the image are named.
        switch (bytes.Length)
        {
            case 8 or 4:
            {
                ulong v = bytes.Length == 8 ? BitConverter.ToUInt64(bytes, 0) : BitConverter.ToUInt32(bytes, 0);
                string? name = _result!.Image.IsMappedVa(v) ? _result.NameFor(v) : null;
                string val = name ?? "0x" + v.ToString(bytes.Length == 8 ? "X" : "X8");
                return (bytes.Length == 8 ? "dq " : "dd ", val, name is not null ? SyntaxTheme.Symbol : SyntaxTheme.Number);
            }
            case 2: return ("dw ", $"0x{BitConverter.ToUInt16(bytes, 0):X4}", SyntaxTheme.Number);
            case 1: return ("db ", $"0x{bytes[0]:X2}", SyntaxTheme.Number);
        }

        var sb = new System.Text.StringBuilder();
        for (int i = 0; i < bytes.Length && i < 16; i++) { if (i > 0) sb.Append(", "); sb.Append("0x").Append(bytes[i].ToString("X2")); }
        if (bytes.Length > 16) sb.Append(", …");
        return ("db ", sb.ToString(), SyntaxTheme.Bytes);
    }

    private static bool TryFormatString(byte[] b, int minLen, out string text)
    {
        text = "";
        bool ascii = b.Length >= minLen;
        for (int i = 0; ascii && i < b.Length; i++)
            if (b[i] is not (>= 0x20 and < 0x7F or 0x09) && !(b[i] == 0 && i == b.Length - 1)) ascii = false;
        if (ascii) { text = Quote(b, wide: false); return true; }

        if (b.Length >= Math.Max(6, minLen * 2) && b.Length % 2 == 0)
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
            long visible = _topDisplay + r;
            if (visible >= VisibleCount) break;
            var (isLabel, instrLine) = ContentAt(ToDisplay(visible));
            if (isLabel || _result.Linear.IsDataAt(instrLine)) continue;
            int ri = RegionStartAt(instrLine);
            if (ri >= 0 && _collapsed.Contains(_regions[ri].Va)) continue;   // collapsed header — no arrow
            ulong va = _result.Linear.VaAt(instrLine);
            if (!_dis.TryDecode(va, out var instr)) continue;
            if (instr.DirectTarget is not ulong target) continue;
            if (instr.Flow == FlowKind.Call) continue; // arrows for jumps only

            long targetInstr = _result.Linear.IndexOf(target);
            if (_result.Linear.VaAt(targetInstr) != target) continue;
            long targetVis = ToVisible(DisplayIndexOfInstr(targetInstr));
            if (targetVis < 0) continue;   // target hidden inside a collapsed region
            long visTop = _topDisplay, visBot = _topDisplay + rows;
            if (targetVis < visTop || targetVis >= visBot) continue;

            double y0 = (visible - _topDisplay) * _rowHeight + _rowHeight / 2;
            double y1 = (targetVis - _topDisplay) * _rowHeight + _rowHeight / 2;
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
        var decompile = new MenuItem { Header = "Decompile function" };
        decompile.Click += (_, _) => { if (CaretVa != 0) OpenInDecompilerRequested?.Invoke(CaretVa); };
        var saveAsm = new MenuItem { Header = "Save function as ASM…" };
        saveAsm.Click += (_, _) => { if (CaretVa != 0) SaveAsmRequested?.Invoke(CaretVa); };
        var follow = new MenuItem { Header = "Follow target", InputGestureText = "Enter" };
        follow.Click += (_, _) => FollowCaret();
        // Reflect the caret's actual target each time the menu opens: show where Follow goes, and grey it
        // out when there's nothing to follow — so it's clear up front whether the action will do anything.
        var patch = new MenuItem { Header = "Patch instruction…" };
        patch.Click += (_, _) => { if (CaretVa != 0) PatchRequested?.Invoke(CaretVa); };
        var toggleBp = new MenuItem { Header = "Toggle breakpoint", InputGestureText = "F2" };
        toggleBp.Click += (_, _) => { if (CaretVa != 0) BreakpointToggleRequested?.Invoke(CaretVa); };
        var hwBp = new MenuItem { Header = "Hardware breakpoint…" };
        hwBp.Click += (_, _) => { if (CaretVa != 0) HardwareBreakpointRequested?.Invoke(CaretVa); };
        var editBp = new MenuItem { Header = "Edit breakpoint…" };
        editBp.Click += (_, _) => { if (CaretVa != 0) EditBreakpointRequested?.Invoke(CaretVa); };
        // Reflect the caret's actual target each time the menu opens: show where Follow goes, grey it out when
        // there's nothing to follow, and enable "Edit breakpoint…" only when a breakpoint exists at the caret.
        menu.Opened += (_, _) =>
        {
            ulong? t = CaretFollowTarget();
            follow.IsEnabled = t is not null;
            follow.Header = t is ulong tt ? $"Follow target → {NameOrAddr(tt)}" : "Follow target";
            editBp.IsEnabled = CaretVa != 0 && IsBreakpointAt?.Invoke(CaretVa) == true;
        };
        var runTo = new MenuItem { Header = "Run to cursor" };
        runTo.Click += (_, _) => { if (CaretVa != 0) RunToCursorRequested?.Invoke(CaretVa); };
        var runToRet = new MenuItem { Header = "Continue to return", InputGestureText = "Ctrl+F9" };
        runToRet.Click += (_, _) => RunToReturnRequested?.Invoke();
        var captureFn = new MenuItem { Header = "Capture this function" };
        captureFn.Click += (_, _) => { if (CaretVa != 0) CaptureFunctionRequested?.Invoke(CaretVa); };
        menu.Items.Add(copy);
        menu.Items.Add(selectAll);
        menu.Items.Add(new Separator());
        menu.Items.Add(follow);
        menu.Items.Add(xref);
        menu.Items.Add(graph);
        menu.Items.Add(decompile);
        menu.Items.Add(saveAsm);
        menu.Items.Add(new Separator());
        menu.Items.Add(toggleBp);
        menu.Items.Add(hwBp);
        menu.Items.Add(editBp);
        menu.Items.Add(runTo);
        menu.Items.Add(runToRet);
        menu.Items.Add(captureFn);
        menu.Items.Add(patch);
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
            // A click in the left gutter margin is the breakpoint strip: a single-click toggles a breakpoint on
            // that code line. Consume it so the margin never selects or follows (and a double-click can't slip a
            // follow through). Header/label/data rows aren't breakpoint rows, so they fall through to OnClick.
            if (_owner.InBreakpointGutter(p, out long bpLine))
            {
                if (e.ClickCount == 1) _owner.ToggleBreakpointAtLine(bpLine);
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
            Cursor = _owner.NearDivider(p.X) ? Cursors.SizeWE
                   : _owner.InBreakpointGutter(p, out _) ? Cursors.Hand   // breakpoint margin
                   : Cursors.Arrow;
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
            long visible = Math.Clamp(_owner._topDisplay + (long)(e.GetPosition(this).Y / _owner._rowHeight), 0, Math.Max(0, _owner.VisibleCount - 1));
            var (_, instr) = _owner.ContentAt(_owner.ToDisplay(visible));
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
                case Key.F2: if (_owner.CaretVa != 0) _owner.BreakpointToggleRequested?.Invoke(_owner.CaretVa); break;
                default: return;
            }
            e.Handled = true;
        }

        protected override void OnRender(DrawingContext dc) => _owner.Render(dc, ActualWidth, ActualHeight);
    }
}

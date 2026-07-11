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
    private IInstructionDecoder? _dis;   // for "follow call/branch"; the live decoder while debugging, else file-backed
    private DecompiledFunction? _dc;
    private IReadOnlyList<DecompLine> _lines = [];
    private ILLevel _level = ILLevel.PseudoC;

    private readonly Dictionary<ulong, DecompiledFunction> _cache = [];
    private ulong _shownFn;
    private int _buildSeq;

    private long _top;
    private long _caret = -1;

    private ulong _ipVa;            // the debuggee's current instruction (0 = not running) — drawn as an amber band
    private int _ipLine = -1;       // the line _ipVa resolves to, recomputed whenever the shown lines change
    private ulong? _pendingGoto;    // a sync target (from the linear view / navigation) awaiting the async build

    private readonly Typeface _typeface =
        new(new FontFamily("Cascadia Mono, Consolas"), FontStyles.Normal, FontWeights.Normal, FontStretches.Normal);
    private const double FontSize = 13.0;
    private const int IndentChars = 4;
    private double _rowHeight = 16;
    private double _charWidth = 8;
    private int _addrDigits = 8;

    public event Action<ulong>? NavigateRequested;
    public event Action<ulong>? SelectionChanged;
    public event Action<ulong>? SaveCRequested;
    /// <summary>Rename the symbol at the caret line's address (right-click → Rename).</summary>
    public event Action<ulong>? RenameRequested;
    /// <summary>Set/clear an inline comment at the caret line's address (right-click → Set comment).</summary>
    public event Action<ulong>? CommentRequested;
    /// <summary>Toggle a bookmark at the caret line's address (right-click → Toggle bookmark).</summary>
    public event Action<ulong>? BookmarkToggleRequested;
    /// <summary>Emulate the shown function to resolve constants / decrypt data (right-click → Emulate).</summary>
    public event Action<ulong>? EmulateFunctionRequested;

    // ---- debugging surface (shared with the linear + graph views; see MainWindow.WireControls) ----
    /// <summary>Toggle a software breakpoint at the line's address (gutter click, F9, right-click).</summary>
    public event Action<ulong>? BreakpointToggleRequested;
    /// <summary>Set a hardware breakpoint / watchpoint at the caret line's address.</summary>
    public event Action<ulong>? HardwareBreakpointRequested;
    /// <summary>Edit the condition / hit-count / enabled state of the breakpoint at the caret line.</summary>
    public event Action<ulong>? EditBreakpointRequested;
    /// <summary>Run the debuggee to the caret line's address.</summary>
    public event Action<ulong>? RunToCursorRequested;
    /// <summary>Continue until the shown function returns.</summary>
    public event Action? RunToReturnRequested;
    /// <summary>Capture the shown function (record its behaviour while debugging).</summary>
    public event Action<ulong>? CaptureFunctionRequested;

    /// <summary>Gutter marks addresses that have a breakpoint (host reads the shared breakpoint set).</summary>
    public Func<ulong, bool>? IsBreakpointAt { get; set; }
    /// <summary>True → the breakpoint at this address is a hardware one (dot painted in the HW colour).</summary>
    public Func<ulong, bool>? IsHardwareBreakpointAt { get; set; }
    /// <summary>True → the instruction executed; drives the coverage/trace tint.</summary>
    public Func<ulong, bool>? IsInstrHit { get; set; }

    /// <summary>Repaint (breakpoint dots / trace tint changed elsewhere). Cheap — no rebuild.</summary>
    public void Refresh() => _surface.InvalidateVisual();

    /// <summary>The live/debugger decoder to read process memory while a session is running (set by the host
    /// on the first stop, cleared on teardown). The default file-backed decoder can't read a live process, so
    /// without this the CFG/lift decode nothing and every function reads "no code recovered".</summary>
    public IInstructionDecoder? LiveDecoder { get; set; }

    /// <summary>The address of the current caret line (0 when nothing is selected / it's a synthetic line).</summary>
    private ulong CaretVa => _caret >= 0 && _caret < _lines.Count ? _lines[(int)_caret].Va : 0;

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

        var menu = new ContextMenu();
        var rename = new MenuItem { Header = "Rename…", InputGestureText = "N" };
        rename.Click += (_, _) => { if (CaretVa != 0) RenameRequested?.Invoke(CaretVa); };
        var comment = new MenuItem { Header = "Set comment…", InputGestureText = ";" };
        comment.Click += (_, _) => { if (CaretVa != 0) CommentRequested?.Invoke(CaretVa); };
        var bookmark = new MenuItem { Header = "Toggle bookmark" };
        bookmark.Click += (_, _) => { if (CaretVa != 0) BookmarkToggleRequested?.Invoke(CaretVa); };
        var emulate = new MenuItem { Header = "Emulate function (deobfuscate)…" };
        emulate.Click += (_, _) => { if (_shownFn != 0) EmulateFunctionRequested?.Invoke(_shownFn); };
        var saveC = new MenuItem { Header = "Save function as C…" };
        saveC.Click += (_, _) => { if (_shownFn != 0) SaveCRequested?.Invoke(_shownFn); };
        // Debug items — same actions as the linear view's, acting on the caret line's address / shown function.
        var toggleBp = new MenuItem { Header = "Toggle breakpoint", InputGestureText = "F9" };
        toggleBp.Click += (_, _) => { if (CaretVa != 0) BreakpointToggleRequested?.Invoke(CaretVa); };
        var hwBp = new MenuItem { Header = "Hardware breakpoint…" };
        hwBp.Click += (_, _) => { if (CaretVa != 0) HardwareBreakpointRequested?.Invoke(CaretVa); };
        var editBp = new MenuItem { Header = "Edit breakpoint…" };
        editBp.Click += (_, _) => { if (CaretVa != 0) EditBreakpointRequested?.Invoke(CaretVa); };
        var runTo = new MenuItem { Header = "Run to cursor" };
        runTo.Click += (_, _) => { if (CaretVa != 0) RunToCursorRequested?.Invoke(CaretVa); };
        var runToRet = new MenuItem { Header = "Continue to return", InputGestureText = "Ctrl+F9" };
        runToRet.Click += (_, _) => RunToReturnRequested?.Invoke();
        var captureFn = new MenuItem { Header = "Capture this function" };
        captureFn.Click += (_, _) => { if (_shownFn != 0) CaptureFunctionRequested?.Invoke(_shownFn); };
        menu.Items.Add(rename);
        menu.Items.Add(comment);
        menu.Items.Add(bookmark);
        menu.Items.Add(new Separator());
        menu.Items.Add(emulate);
        menu.Items.Add(saveC);
        menu.Items.Add(new Separator());
        menu.Items.Add(toggleBp);
        menu.Items.Add(hwBp);
        menu.Items.Add(editBp);
        menu.Items.Add(runTo);
        menu.Items.Add(runToRet);
        menu.Items.Add(captureFn);
        // Edit breakpoint only makes sense on a line that already has one (mirrors the linear view).
        menu.Opened += (_, _) => editBp.IsEnabled = CaretVa != 0 && IsBreakpointAt?.Invoke(CaretVa) == true;
        _surface.ContextMenu = menu;

        MeasureFont();
        UpdateLevelButtons();
    }

    /// <summary>Show <paramref name="function"/> in the decompiler, building (and caching) it if needed.</summary>
    public void SetFunction(AnalysisResult result, Function function)
    {
        // A new image (e.g. the static↔live debugger swap) invalidates the decoder and the per-function
        // cache — both were built over the old address space.
        if (_dis is not null && !ReferenceEquals(_result?.Image, result.Image)) { _dis = null; _cache.Clear(); }
        _result = result;
        // Follow-call needs a decoder that can read the shown bytes: the live decoder while debugging (process
        // memory), else the file-backed one. The image-swap reset above rebuilds it on the static↔live switch.
        _dis ??= LiveDecoder ?? new Disassembler(result.Image);
        _addrDigits = Math.Max(8, result.Image.MaxVa.ToString("X").Length);

        if (_cache.TryGetValue(function.Va, out var cached)) { _shownFn = function.Va; Show(cached); return; }

        // Build the CFG on the UI thread (shared mutable state), then lift/structure/emit in the background.
        // Pass the live decoder while debugging so the descent reads process memory, not the (absent) file image.
        if (!function.BlocksBuilt)
            CfgBuilder.Build(result.Image, function, result.JumpTables,
                LiveDecoder is null ? null : NeutralDisasm.For(result.Image, result.Names, LiveDecoder));

        _shownFn = function.Va;
        int seq = ++_buildSeq;
        ShowBuilding(function);

        var fn = function;
        var decoder = LiveDecoder;
        Task.Run(() => Decompiler.Decompile(fn, result, decoder)).ContinueWith(t =>
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
        _ipVa = 0;
        _ipLine = -1;
        _pendingGoto = null;
        ConfigureScroll();
        _surface.InvalidateVisual();
    }

    /// <summary>Drop the per-function decompilation cache (its emitted lines baked in the old names/comments)
    /// and re-render the current function, so a user rename/comment shows immediately.</summary>
    public void InvalidateCache()
    {
        _cache.Clear();
        if (_result is { } r && _shownFn != 0 && r.FunctionByVa.TryGetValue(_shownFn, out var fn))
            SetFunction(r, fn);
    }

    private void Show(DecompiledFunction dc)
    {
        _dc = dc;
        _lines = dc.Lines(_level);
        _top = 0;
        _caret = -1;
        _ipLine = _ipVa != 0 ? BestLineFor(_ipVa) : -1;
        ConfigureScroll();
        ApplyPendingGoto();   // a sync target that arrived while this function was still building on the bg thread
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
        if (_dc is not null)
        {
            ulong keep = CaretVa;   // the focused instruction — preserve it across the level switch
            _lines = _dc.Lines(_level);
            _top = 0;
            _caret = -1;
            _ipLine = _ipVa != 0 ? BestLineFor(_ipVa) : -1;
            ConfigureScroll();
            if (keep != 0) GoToVa(keep);   // land on the same instruction at the new level, not back at the top
        }
        _surface.InvalidateVisual();
    }

    // ---- cross-view sync (linear ⇄ decompiler, static and while running) ----

    /// <summary>Scroll to and select the line whose source instruction best matches <paramref name="va"/>,
    /// keeping the decompiler in step with the linear view / navigation. Purely visual — it does not raise
    /// <see cref="SelectionChanged"/>, so a sync never bounces back. If the function is still building on the
    /// background thread the target is remembered and applied when its lines arrive (see <see cref="Show"/>).</summary>
    public void GoToVa(ulong va)
    {
        _pendingGoto = va;
        ApplyPendingGoto();
    }

    private void ApplyPendingGoto()
    {
        if (_pendingGoto is not ulong va || _dc is null) return;   // lines not built yet → Show() retries
        int idx = BestLineFor(va);
        if (idx < 0) return;
        _pendingGoto = null;
        _caret = idx;
        long third = Math.Max(0, VisibleRows / 3);
        _top = Math.Clamp((long)idx - third, 0L, (long)Math.Max(0, _lines.Count - 1));
        _scroll.Value = _top;
        _surface.InvalidateVisual();
    }

    /// <summary>Mark the debuggee's current instruction with the amber IP band (like the linear view) and
    /// scroll to it; pass 0 to clear the band when the session ends.</summary>
    public void SetCurrentIp(ulong va)
    {
        _ipVa = va;
        _ipLine = va != 0 ? BestLineFor(va) : -1;
        if (va != 0) GoToVa(va);
        else _surface.InvalidateVisual();
    }

    /// <summary>Index of the addressed line (synthetic Va==0 lines skipped) whose VA is closest to
    /// <paramref name="va"/>; -1 if the function has no addressed lines. Lines are roughly address-ordered,
    /// so a nearest match is a good "you are here" even where structuring reorders a few.</summary>
    private int BestLineFor(ulong va)
    {
        int best = -1;
        ulong bestDiff = ulong.MaxValue;
        for (int i = 0; i < _lines.Count; i++)
        {
            ulong lva = _lines[i].Va;
            if (lva == 0) continue;
            ulong diff = lva > va ? lva - va : va - lva;
            if (diff < bestDiff) { bestDiff = diff; best = i; if (diff == 0) break; }
        }
        return best;
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
    private double BpGutterW => 1.7 * _charWidth;   // clickable breakpoint strip left of the address (VS-style)
    private double AddrX => BpGutterW + 3;
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

    private void ToggleBreakpointAtLine(long line)
    {
        if (line < 0 || line >= _lines.Count) return;
        ulong va = _lines[(int)line].Va;
        if (va == 0) return;               // synthetic line (brace / blank) — nothing to break on
        _caret = line;
        BreakpointToggleRequested?.Invoke(va);
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
            var band = new Rect(BpGutterW, y, width - BpGutterW, _rowHeight);

            // Coverage/trace tint first, so the current-IP amber and the caret band paint on top of it.
            if (line.Va != 0 && IsInstrHit?.Invoke(line.Va) == true)
                dc.DrawRectangle(SyntaxTheme.CoveredInstr, null, band);
            // The debuggee's current instruction (amber) wins over the plain caret band when running.
            if (_ipVa != 0 && idx == _ipLine)
                dc.DrawRectangle(SyntaxTheme.CurrentIp, null, band);
            else if (idx == _caret)
                dc.DrawRectangle(SyntaxTheme.CurrentLine, null, band);

            if (line.Va != 0 && IsBreakpointAt?.Invoke(line.Va) == true)
            {
                var dot = IsHardwareBreakpointAt?.Invoke(line.Va) == true ? SyntaxTheme.HwBreakpointDot : SyntaxTheme.BreakpointDot;
                dc.DrawEllipse(dot, null, new Point(BpGutterW / 2, y + _rowHeight / 2), 4, 4);
            }

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
            var p = e.GetPosition(this);
            long line = _owner._top + (long)(p.Y / _owner._rowHeight);
            // A click in the left gutter strip toggles a breakpoint (VS-style), like the linear view; a
            // double-click there is swallowed rather than navigating.
            if (p.X <= _owner.BpGutterW)
            {
                if (e.ClickCount == 1) _owner.ToggleBreakpointAtLine(line);
                e.Handled = true;
                return;
            }
            _owner.MoveCaret(line);
            if (e.ClickCount == 2) _owner.Activate(line);
            e.Handled = true;
        }

        // Hand cursor over the breakpoint gutter so it reads as clickable.
        protected override void OnMouseMove(MouseEventArgs e)
            => Cursor = e.GetPosition(this).X <= _owner.BpGutterW ? Cursors.Hand : Cursors.Arrow;

        // Move the caret to the right-clicked line so the context menu's Rename/Comment/Bookmark act on it.
        protected override void OnMouseRightButtonDown(MouseButtonEventArgs e)
        {
            Focus();
            long line = _owner._top + (long)(e.GetPosition(this).Y / _owner._rowHeight);
            _owner.MoveCaret(line);
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
                case Key.N when (Keyboard.Modifiers & ModifierKeys.Control) == 0:
                    if (_owner.CaretVa != 0) _owner.RenameRequested?.Invoke(_owner.CaretVa); break;
                case Key.OemSemicolon:
                    if (_owner.CaretVa != 0) _owner.CommentRequested?.Invoke(_owner.CaretVa); break;
                case Key.F2 or Key.F9:
                    if (_owner.CaretVa != 0) _owner.BreakpointToggleRequested?.Invoke(_owner.CaretVa); break;
                default: return;
            }
            e.Handled = true;
        }

        protected override void OnRender(DrawingContext dc) => _owner.Render(dc, ActualWidth, ActualHeight);
    }
}

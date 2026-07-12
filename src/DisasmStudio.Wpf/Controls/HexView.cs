using System.Globalization;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Input;
using System.Windows.Media;
using DisasmStudio.Core.Analysis;
using DisasmStudio.Core.Formats;
using DisasmStudio.Debug;
using DisasmStudio.Wpf.Services;

namespace DisasmStudio.Wpf.Controls;

/// <summary>
/// A lightweight, virtualized hex viewer (after CDA.Modern's HexView), backed by an
/// <see cref="IBinaryImage"/>. Only the visible rows are ever read, so it is usable over an
/// arbitrarily large address space. Pure WPF vector text, crisp at any 4K/5K scale. A byte range
/// can be selected (click / drag / shift-click) and copied as hex or text.
/// </summary>
public sealed class HexView : Grid
{
    private readonly Surface _surface;
    private readonly ScrollBar _scroll;

    private IBinaryImage? _image;
    private ulong _topAddress;
    private const int BytesPerRow = 16;

    private readonly Typeface _typeface =
        new(new FontFamily("Cascadia Mono, Consolas"), FontStyles.Normal, FontWeights.Normal, FontStretches.Normal);
    private const double FontSize = 13.0;
    private double _rowHeight = 16;
    private double _charWidth = 8;

    private ulong _selAnchor, _selCaret;
    private bool _hasSelection;
    private int _editNibble;   // 0 = next keystroke sets the high nibble, 1 = low nibble
    private const long MaxCopyBytes = 1 << 20;

    /// <summary>Raised (with the edited VA) after a byte is changed, so the host can track the edit.</summary>
    public event Action<ulong>? Edited;
    /// <summary>Rename the symbol at the clicked byte's address (right-click → Rename).</summary>
    public event Action<ulong>? RenameRequested;
    /// <summary>Set/clear an inline comment at the clicked byte's address (right-click → Set comment).</summary>
    public event Action<ulong>? CommentRequested;
    /// <summary>Toggle a bookmark at the clicked byte's address (right-click → Toggle bookmark).</summary>
    public event Action<ulong>? BookmarkToggleRequested;
    /// <summary>Raised (with the caret VA) when the user moves the selection caret — click, drag, or keyboard —
    /// so the host can sync the status bar / xrefs. Programmatic <see cref="GoTo"/> and search selections stay
    /// quiet, so a sync from another view never bounces back.</summary>
    public event Action<ulong>? SelectionChanged;
    /// <summary>Raised (with the byte VA) on a double-click, so the host can navigate every view there.</summary>
    public event Action<ulong>? NavigateRequested;
    /// <summary>Raised (right-click → Find, matching the Ctrl+F shortcut) so the host shows the search dialog.</summary>
    public event Action? FindRequested;
    /// <summary>Raised (right-click → Find next) to repeat the last search forward.</summary>
    public event Action? FindNextRequested;
    /// <summary>Raised (right-click → Find previous) to repeat the last search backward.</summary>
    public event Action? FindPreviousRequested;
    /// <summary>Raised (right-click → Memory breakpoint) to set a software data breakpoint on the selected byte
    /// range, breaking on read / write / either per the <see cref="MemAccess"/>.</summary>
    public event Action<(ulong Lo, ulong Hi, MemAccess Access)>? MemoryBreakpointRequested;

    // Nested Surface is a separate class and can't raise the owner's events directly (C# event-access rule),
    // so route double-click / drag-end notifications through these.
    private void NotifySelection() => SelectionChanged?.Invoke(_selCaret);
    private void NotifyNavigate(ulong addr) => NavigateRequested?.Invoke(addr);

    /// <summary>The address of the current selection caret (the clicked byte), or 0 when nothing is selected.</summary>
    private ulong SelectedVa => _hasSelection ? _selCaret : 0;

    /// <summary>When set (debugging), byte edits are written by VA through this hook (e.g. to process
    /// memory) instead of the file-offset patch path — which can't address a live 64-bit process.</summary>
    public Func<ulong, byte, bool>? WriteByteAt { get; set; }

    private static readonly Brush BgBrush = Palette.BaseBrush;
    private static readonly Brush AddrBrush = Palette.BlueBrush;
    private static readonly Brush HexBrush = Palette.TextBrush;
    private static readonly Brush AsciiBrush = Palette.GreenBrush;
    private static readonly Brush DimBrush = Palette.Surface2Brush;      // unreadable/zero bytes
    private static readonly Brush SelBrush = Palette.SelOverlayBrush;    // lavender @ 0x66 alpha
    private static readonly Brush PatchBrush = Palette.PeachBrush;       // edited byte

    public HexView()
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

        var copyHex = new MenuItem { Header = "Copy (hex)", InputGestureText = "Ctrl+C" };
        copyHex.Click += (_, _) => CopySelection(asText: false);
        var copyText = new MenuItem { Header = "Copy (text)" };
        copyText.Click += (_, _) => CopySelection(asText: true);
        var rename = new MenuItem { Header = "Rename…" };
        rename.Click += (_, _) => { if (SelectedVa != 0) RenameRequested?.Invoke(SelectedVa); };
        var comment = new MenuItem { Header = "Set comment…" };
        comment.Click += (_, _) => { if (SelectedVa != 0) CommentRequested?.Invoke(SelectedVa); };
        var bookmark = new MenuItem { Header = "Toggle bookmark" };
        bookmark.Click += (_, _) => { if (SelectedVa != 0) BookmarkToggleRequested?.Invoke(SelectedVa); };
        var find = new MenuItem { Header = "Find…", InputGestureText = "Ctrl+F" };
        find.Click += (_, _) => FindRequested?.Invoke();
        var findNext = new MenuItem { Header = "Find next", InputGestureText = "F3" };
        findNext.Click += (_, _) => FindNextRequested?.Invoke();
        var findPrev = new MenuItem { Header = "Find previous", InputGestureText = "Shift+F3" };
        findPrev.Click += (_, _) => FindPreviousRequested?.Invoke();
        // Software memory (data) breakpoint over the selection — break on read / write / either (while debugging).
        // Flat items: the dark MenuItem template has no sub-menu popup, so nested items would never render.
        var memRead = new MenuItem { Header = "Break on read (memory bp)" };
        memRead.Click += (_, _) => { if (Selection is { } s) MemoryBreakpointRequested?.Invoke((s.Lo, s.Hi, MemAccess.Read)); };
        var memWrite = new MenuItem { Header = "Break on write (memory bp)" };
        memWrite.Click += (_, _) => { if (Selection is { } s) MemoryBreakpointRequested?.Invoke((s.Lo, s.Hi, MemAccess.Write)); };
        var memRw = new MenuItem { Header = "Break on read/write (memory bp)" };
        memRw.Click += (_, _) => { if (Selection is { } s) MemoryBreakpointRequested?.Invoke((s.Lo, s.Hi, MemAccess.ReadWrite)); };
        var menu = new ContextMenu();
        menu.Opened += (_, _) =>
            rename.IsEnabled = comment.IsEnabled = bookmark.IsEnabled =
            memRead.IsEnabled = memWrite.IsEnabled = memRw.IsEnabled = SelectedVa != 0;
        menu.Items.Add(copyHex);
        menu.Items.Add(copyText);
        menu.Items.Add(new Separator());
        menu.Items.Add(find);
        menu.Items.Add(findNext);
        menu.Items.Add(findPrev);
        menu.Items.Add(new Separator());
        menu.Items.Add(memRead);
        menu.Items.Add(memWrite);
        menu.Items.Add(memRw);
        menu.Items.Add(new Separator());
        menu.Items.Add(rename);
        menu.Items.Add(comment);
        menu.Items.Add(bookmark);
        _surface.ContextMenu = menu;

        MeasureFont();
    }

    public void SetImage(IBinaryImage? image)
    {
        _image = image;
        _topAddress = image?.MinVa ?? 0;
        _hasSelection = false;
        ConfigureScroll();
        _surface.InvalidateVisual();
    }

    public void InvalidateView() => _surface.InvalidateVisual();

    public void GoTo(ulong address, bool select = false, int length = 1)
    {
        if (_image is null) return;
        if (address < _image.MinVa) address = _image.MinVa;
        if (address > _image.MaxVa) address = _image.MaxVa;

        // Highlight the target so navigation is visible even between two addresses in the same 16-byte row
        // (e.g. rsp+4 vs rsp+8, which otherwise render identically and look like nothing happened), and so a
        // target that lands in unmapped memory is still clearly shown. `length` highlights the whole instruction
        // (all its opcode bytes), not just the first — the caller passes the instruction's byte count.
        if (select)
        {
            ulong end = address + (ulong)(Math.Max(1, length) - 1);
            if (end >= _image.MaxVa) end = _image.MaxVa > _image.MinVa ? _image.MaxVa - 1 : address;
            _selAnchor = address;
            _selCaret = end;
            _hasSelection = true;
            _editNibble = 0;
        }

        ulong aligned = address - (address % BytesPerRow);
        ulong back = (ulong)(Math.Max(0, VisibleRows / 2) * BytesPerRow);
        _topAddress = aligned > _image.MinVa + back ? aligned - back : _image.MinVa;

        SyncScrollValue();
        _surface.InvalidateVisual();
    }

    // ---- byte / text search (see DisasmStudio.Core.Analysis.ByteSearch) ----
    private byte[]? _lastPattern;
    private bool[]? _lastMask;

    public enum FindResult { NoImage, NotFound, Found, FoundWrapped }

    /// <summary>Search for <paramref name="pattern"/> (with an optional wildcard <paramref name="mask"/>) from
    /// just past the current selection, wrapping around the image once. Records the pattern for
    /// <see cref="SearchAgain"/> (F3). On a hit, selects the whole match and scrolls it into view.</summary>
    public FindResult Search(byte[] pattern, bool[]? mask, bool forward)
    {
        _lastPattern = pattern;
        _lastMask = mask;
        return RunSearch(forward);
    }

    /// <summary>Repeat the last <see cref="Search"/> in the given direction (F3 / Shift+F3). No-op if none.</summary>
    public FindResult SearchAgain(bool forward) => _lastPattern is null ? FindResult.NotFound : RunSearch(forward);

    private FindResult RunSearch(bool forward)
    {
        if (_image is null) return FindResult.NoImage;
        if (_lastPattern is null) return FindResult.NotFound;

        // Resume from just outside the current selection so repeated searches step through matches: past its
        // end going forward, before its start going backward. With nothing selected, sweep from the near edge.
        ulong start;
        if (_hasSelection)
        {
            var (lo, hi) = SelRange();
            start = forward
                ? (hi + 1 < _image.MaxVa ? hi + 1 : _image.MinVa)
                : (lo > _image.MinVa ? lo - 1 : _image.MaxVa - 1);
        }
        else start = forward ? _image.MinVa : _image.MaxVa - 1;

        ulong? hit = ByteSearch.Find(_image, start, _lastPattern, _lastMask, forward);
        if (hit is null) return FindResult.NotFound;

        ulong matchLo = hit.Value;
        ulong matchHi = matchLo + (ulong)_lastPattern.Length - 1;
        bool wrapped = forward ? matchLo < start : matchLo > start;
        SelectRange(matchLo, matchHi);
        return wrapped ? FindResult.FoundWrapped : FindResult.Found;
    }

    /// <summary>Select the byte range [<paramref name="lo"/>, <paramref name="hi"/>] and scroll it into view.
    /// Quiet (programmatic, like <see cref="GoTo"/>) — raises no <see cref="SelectionChanged"/>.</summary>
    private void SelectRange(ulong lo, ulong hi)
    {
        if (_image is null) return;
        _selAnchor = lo;
        _selCaret = hi;
        _hasSelection = true;
        _editNibble = 0;

        // Centre the match's first byte, reusing GoTo's row alignment.
        ulong aligned = lo - (lo % BytesPerRow);
        ulong back = (ulong)(Math.Max(0, VisibleRows / 2) * BytesPerRow);
        _topAddress = aligned > _image.MinVa + back ? aligned - back : _image.MinVa;

        SyncScrollValue();
        _surface.InvalidateVisual();
    }

    private int VisibleRows => Math.Max(1, (int)(_surface.ActualHeight / _rowHeight));

    private void MeasureFont()
    {
        double dpi = VisualTreeHelper.GetDpi(this).PixelsPerDip;
        var ft = new FormattedText("0", CultureInfo.InvariantCulture, FlowDirection.LeftToRight,
            _typeface, FontSize, Brushes.White, dpi);
        _charWidth = ft.WidthIncludingTrailingWhitespace;
        _rowHeight = Math.Ceiling(ft.Height) + 2;
    }

    private void ConfigureScroll()
    {
        if (_image is null) { _scroll.Maximum = 0; return; }
        double totalRows = (_image.MaxVa - _image.MinVa) / (double)BytesPerRow;
        _scroll.Minimum = 0;
        _scroll.Maximum = Math.Max(0, totalRows - VisibleRows);
        _scroll.LargeChange = VisibleRows;
        _scroll.ViewportSize = VisibleRows;
        SyncScrollValue();
    }

    private void SyncScrollValue()
    {
        if (_image is null) return;
        _scroll.Value = (_topAddress - _image.MinVa) / (double)BytesPerRow;
    }

    private void OnScroll(object sender, ScrollEventArgs e)
    {
        if (_image is null) return;
        ulong row = (ulong)Math.Max(0, e.NewValue);
        _topAddress = _image.MinVa + row * BytesPerRow;
        _surface.InvalidateVisual();
    }

    private void ScrollByRows(int rows)
    {
        if (_image is null) return;
        long delta = (long)rows * BytesPerRow;
        long next = (long)_topAddress + delta;
        if (next < (long)_image.MinVa) next = (long)_image.MinVa;
        _topAddress = (ulong)next;
        SyncScrollValue();
        _surface.InvalidateVisual();
    }

    private int AddrDigits => _image is { Bitness: 64 } ? 12 : 8;
    private double HexX => 4 + (AddrDigits + 2) * _charWidth;
    private double AsciiX => HexX + 50 * _charWidth;
    private static int HexCharOffset(int c) => c * 3 + (c >= 8 ? 1 : 0);

    private bool HitTestByte(Point p, out ulong addr)
    {
        addr = 0;
        if (_image is null) return false;
        int r = Math.Max(0, (int)(p.Y / _rowHeight));
        ulong rowAddr = _topAddress + (ulong)(r * BytesPerRow);

        int col;
        if (p.X >= AsciiX) col = (int)((p.X - AsciiX) / _charWidth);
        else if (p.X >= HexX)
        {
            double cx = (p.X - HexX) / _charWidth;
            col = cx < 24 ? (int)(cx / 3) : 8 + (int)((cx - 25) / 3);
        }
        else col = 0;
        col = Math.Clamp(col, 0, BytesPerRow - 1);

        ulong a = rowAddr + (ulong)col;
        if (a < _image.MinVa) a = _image.MinVa;
        if (a >= _image.MaxVa) a = _image.MaxVa > _image.MinVa ? _image.MaxVa - 1 : _image.MinVa;
        addr = a;
        return true;
    }

    private void StartSelect(ulong addr, bool extend)
    {
        if (extend && _hasSelection) _selCaret = addr;
        else { _selAnchor = addr; _selCaret = addr; _hasSelection = true; }
        _editNibble = 0;
        _surface.InvalidateVisual();
        NotifySelection();
    }

    /// <summary>Move the edit caret by <paramref name="delta"/> bytes, scrolling it into view.</summary>
    private void MoveCaret(long delta, bool extend = false)
    {
        if (_image is null) return;
        if (!_hasSelection) { _selAnchor = _selCaret = _topAddress; _hasSelection = true; }
        long n = Math.Clamp((long)_selCaret + delta, (long)_image.MinVa, (long)_image.MaxVa - 1);
        _selCaret = (ulong)n;
        if (!extend) _selAnchor = _selCaret;
        _editNibble = 0;
        EnsureCaretVisible();
        _surface.InvalidateVisual();
        NotifySelection();
    }

    private void EnsureCaretVisible()
    {
        if (_image is null) return;
        if (_selCaret < _topAddress)
            _topAddress = _selCaret - _selCaret % BytesPerRow;
        else
        {
            ulong lastVisible = _topAddress + (ulong)(VisibleRows * BytesPerRow) - 1;
            if (_selCaret > lastVisible)
            {
                ulong caretRow = _selCaret - _selCaret % BytesPerRow;
                ulong span = (ulong)((VisibleRows - 1) * BytesPerRow);
                _topAddress = caretRow > _image.MinVa + span ? caretRow - span : _image.MinVa;
            }
        }
        SyncScrollValue();
    }

    /// <summary>Overwrite the high or low nibble of the caret byte and advance after a full byte.</summary>
    private void TypeHex(int nibble)
    {
        if (_image is null || !_hasSelection) return;
        ulong editVa = _selCaret;
        var cur = _image.ReadBytesAtVa(editVa, 1);
        byte b = cur.Length == 1 ? cur[0] : (byte)0;
        byte nb = _editNibble == 0 ? (byte)((nibble << 4) | (b & 0x0F)) : (byte)((b & 0xF0) | nibble);
        if (WriteByteAt is not null) { if (!WriteByteAt(editVa, nb)) return; }      // live: write by VA
        else { int off = _image.VaToOffset(editVa); if (off < 0) return; _image.Patch(off, [nb]); }
        if (_editNibble == 0) _editNibble = 1;
        else
        {
            _editNibble = 0;
            ulong next = editVa + 1;
            if (next < _image.MaxVa) { _selAnchor = _selCaret = next; }
        }
        Edited?.Invoke(editVa);
        _surface.InvalidateVisual();
    }

    private void ExtendSelect(ulong addr)
    {
        if (!_hasSelection) { _selAnchor = addr; _hasSelection = true; }
        _selCaret = addr;
        _surface.InvalidateVisual();
    }

    private (ulong Lo, ulong Hi) SelRange() =>
        _selAnchor <= _selCaret ? (_selAnchor, _selCaret) : (_selCaret, _selAnchor);

    /// <summary>The current inclusive byte selection [Lo, Hi], or null when nothing is selected.</summary>
    public (ulong Lo, ulong Hi)? Selection => _hasSelection ? SelRange() : null;

    /// <summary>True if <paramref name="addr"/> falls within the current selection (used so a right-click inside
    /// a multi-byte selection doesn't collapse it).</summary>
    private bool SelectionContains(ulong addr)
    {
        if (!_hasSelection) return false;
        var (lo, hi) = SelRange();
        return addr >= lo && addr <= hi;
    }

    private void CopySelection(bool asText)
    {
        if (_image is null || !_hasSelection) return;
        var (lo, hi) = SelRange();
        long count = Math.Min((long)(hi - lo) + 1, MaxCopyBytes);

        var sb = new StringBuilder();
        var buf = new byte[4096];
        ulong addr = lo;
        long remaining = count;
        bool first = true;
        while (remaining > 0)
        {
            int want = (int)Math.Min(remaining, buf.Length);
            int read = _image.ReadVa(addr, buf.AsSpan(0, want));
            if (read <= 0) break;
            for (int i = 0; i < read; i++)
            {
                byte b = buf[i];
                if (asText) sb.Append(b >= 0x20 && b < 0x7F ? (char)b : '.');
                else { if (!first) sb.Append(' '); sb.Append(b.ToString("X2")); first = false; }
            }
            addr += (ulong)read;
            remaining -= read;
            if (read < want) break;
        }
        try { Clipboard.SetText(sb.ToString()); } catch { /* clipboard busy */ }
    }

    private void Render(DrawingContext dc, double width, double height)
    {
        dc.DrawRectangle(BgBrush, null, new Rect(0, 0, width, height));
        if (_image is null) return;

        int addrDigits = AddrDigits;
        double hexX = HexX, asciiX = AsciiX;
        int rows = (int)(height / _rowHeight) + 1;
        double dpi = VisualTreeHelper.GetDpi(this).PixelsPerDip;
        (ulong selLo, ulong selHi) = _hasSelection ? SelRange() : (1UL, 0UL);

        var row = new byte[BytesPerRow];
        for (int r = 0; r < rows; r++)
        {
            ulong addr = _topAddress + (ulong)(r * BytesPerRow);
            if (addr >= _image.MaxVa) break;

            Array.Clear(row);
            int read = _image.ReadVa(addr, row);
            double y = r * _rowHeight;

            if (_hasSelection && selHi >= addr && selLo <= addr + BytesPerRow - 1)
            {
                int cStart = selLo > addr ? (int)(selLo - addr) : 0;
                int cEnd = selHi < addr + BytesPerRow - 1 ? (int)(selHi - addr) : BytesPerRow - 1;
                DrawSelection(dc, hexX, asciiX, y, cStart, cEnd);
            }

            Draw(dc, addr.ToString("X" + addrDigits) + "  ", 4, y, AddrBrush, dpi);

            var hex = new StringBuilder(BytesPerRow * 3);
            var ascii = new StringBuilder(BytesPerRow);
            for (int c = 0; c < BytesPerRow; c++)
            {
                if (c < read)
                {
                    byte b = row[c];
                    hex.Append(b.ToString("X2")).Append(' ');
                    ascii.Append(b >= 0x20 && b < 0x7F ? (char)b : '.');
                }
                else { hex.Append("?? "); ascii.Append(' '); }
                if (c == 7) hex.Append(' ');
            }

            Draw(dc, hex.ToString(), hexX, y, read > 0 ? HexBrush : DimBrush, dpi);
            Draw(dc, ascii.ToString(), asciiX, y, AsciiBrush, dpi);

            // Re-draw edited bytes in the patch colour so changes stand out.
            if (_image.IsDirty)
                for (int c = 0; c < read; c++)
                {
                    int off = _image.VaToOffset(addr + (ulong)c);
                    if (off >= 0 && _image.IsPatchedAt(off))
                        Draw(dc, row[c].ToString("X2"), hexX + HexCharOffset(c) * _charWidth, y, PatchBrush, dpi);
                }
        }
    }

    private void DrawSelection(DrawingContext dc, double hexX, double asciiX, double y, int cStart, int cEnd)
    {
        dc.DrawRectangle(SelBrush, null,
            new Rect(asciiX + cStart * _charWidth, y, (cEnd - cStart + 1) * _charWidth, _rowHeight));
        DrawHexRun(dc, hexX, y, Math.Max(cStart, 0), Math.Min(cEnd, 7));
        DrawHexRun(dc, hexX, y, Math.Max(cStart, 8), Math.Min(cEnd, 15));
    }

    private void DrawHexRun(DrawingContext dc, double hexX, double y, int cLo, int cHi)
    {
        if (cLo > cHi) return;
        double x0 = hexX + HexCharOffset(cLo) * _charWidth;
        double x1 = hexX + (HexCharOffset(cHi) + 2) * _charWidth;
        dc.DrawRectangle(SelBrush, null, new Rect(x0, y, x1 - x0, _rowHeight));
    }

    private void Draw(DrawingContext dc, string text, double x, double y, Brush brush, double dpi)
    {
        var ft = new FormattedText(text, CultureInfo.InvariantCulture, FlowDirection.LeftToRight,
            _typeface, FontSize, brush, dpi);
        dc.DrawText(ft, new Point(x, y));
    }


    private sealed class Surface : FrameworkElement
    {
        private readonly HexView _owner;
        private bool _dragging;

        public Surface(HexView owner) { _owner = owner; ClipToBounds = true; Focusable = true; }

        protected override void OnRenderSizeChanged(SizeChangedInfo info)
        {
            base.OnRenderSizeChanged(info);
            _owner.ConfigureScroll();
        }

        protected override void OnDpiChanged(DpiScale oldDpi, DpiScale newDpi)
        {
            _owner.MeasureFont();
            _owner.ConfigureScroll();
            InvalidateVisual();
        }

        protected override void OnMouseWheel(MouseWheelEventArgs e)
        {
            _owner.ScrollByRows(-Math.Sign(e.Delta) * 3);
            e.Handled = true;
        }

        protected override void OnMouseLeftButtonDown(MouseButtonEventArgs e)
        {
            Focus();
            if (_owner.HitTestByte(e.GetPosition(this), out ulong addr))
            {
                bool extend = (Keyboard.Modifiers & ModifierKeys.Shift) != 0;
                _owner.StartSelect(addr, extend);
                if (e.ClickCount == 2) _owner.NotifyNavigate(addr);   // double-click → navigate every view
                else { CaptureMouse(); _dragging = true; }
            }
            e.Handled = true;
        }

        protected override void OnMouseMove(MouseEventArgs e)
        {
            if (!_dragging) return;
            var p = e.GetPosition(this);
            if (p.Y < 0) _owner.ScrollByRows(-1);
            else if (p.Y >= ActualHeight) _owner.ScrollByRows(1);
            double clampedY = Math.Max(0, Math.Min(p.Y, ActualHeight - 1));
            if (_owner.HitTestByte(new Point(p.X, clampedY), out ulong addr))
                _owner.ExtendSelect(addr);
        }

        protected override void OnMouseLeftButtonUp(MouseButtonEventArgs e)
        {
            // Fire once at the end of a drag (not per-move in ExtendSelect) so the caret lands, then sync
            // the status bar / xrefs — without rebuilding xrefs on every pixel of the drag.
            if (_dragging) { _dragging = false; ReleaseMouseCapture(); _owner.NotifySelection(); }
        }

        // Right-click inside an existing multi-byte selection keeps it (so "memory breakpoint on the selection"
        // and copy act on the whole highlighted run); right-clicking elsewhere selects just that byte for the
        // context menu's Rename/Comment/Bookmark.
        protected override void OnMouseRightButtonDown(MouseButtonEventArgs e)
        {
            Focus();
            if (_owner.HitTestByte(e.GetPosition(this), out ulong addr) && !_owner.SelectionContains(addr))
                _owner.StartSelect(addr, extend: false);
        }

        protected override void OnKeyDown(KeyEventArgs e)
        {
            bool ctrl = (Keyboard.Modifiers & ModifierKeys.Control) != 0;
            bool shift = (Keyboard.Modifiers & ModifierKeys.Shift) != 0;
            if (e.Key == Key.C && ctrl) { _owner.CopySelection(asText: false); e.Handled = true; return; }

            int rows = Math.Max(1, (int)(ActualHeight / _owner._rowHeight) - 1);
            switch (e.Key)
            {
                case Key.Left: _owner.MoveCaret(-1, shift); break;
                case Key.Right: _owner.MoveCaret(1, shift); break;
                case Key.Up: _owner.MoveCaret(-BytesPerRow, shift); break;
                case Key.Down: _owner.MoveCaret(BytesPerRow, shift); break;
                case Key.Home: _owner.MoveCaret(-(long)(_owner._selCaret % BytesPerRow), shift); break;
                case Key.End: _owner.MoveCaret(BytesPerRow - 1 - (long)(_owner._selCaret % BytesPerRow), shift); break;
                case Key.PageUp: _owner.MoveCaret(-(long)rows * BytesPerRow, shift); break;
                case Key.PageDown: _owner.MoveCaret((long)rows * BytesPerRow, shift); break;
                default: return;
            }
            e.Handled = true;
        }

        // Typing a hex digit over the caret byte edits it (nibble at a time).
        protected override void OnTextInput(TextCompositionEventArgs e)
        {
            if ((Keyboard.Modifiers & ModifierKeys.Control) != 0) return;
            foreach (char ch in e.Text)
            {
                int v = ch is >= '0' and <= '9' ? ch - '0'
                    : ch is >= 'a' and <= 'f' ? ch - 'a' + 10
                    : ch is >= 'A' and <= 'F' ? ch - 'A' + 10 : -1;
                if (v < 0) continue;
                _owner.TypeHex(v);
                e.Handled = true;
            }
        }

        protected override void OnRender(DrawingContext dc) => _owner.Render(dc, ActualWidth, ActualHeight);
    }
}

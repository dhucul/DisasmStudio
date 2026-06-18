using System.Globalization;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Input;
using System.Windows.Media;
using DisasmStudio.Core.Formats;

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
    private const long MaxCopyBytes = 1 << 20;

    private static readonly Brush BgBrush = Frozen(0x10, 0x14, 0x1B);
    private static readonly Brush AddrBrush = Frozen(0x6B, 0x8F, 0xD6);
    private static readonly Brush HexBrush = Frozen(0xE6, 0xEA, 0xF0);
    private static readonly Brush AsciiBrush = Frozen(0x8F, 0xC1, 0x8A);
    private static readonly Brush DimBrush = Frozen(0x4A, 0x54, 0x62);
    private static readonly Brush SelBrush = FrozenA(0x66, 0x4D, 0x8D, 0xF7);

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
        _surface.ContextMenu = new ContextMenu();
        _surface.ContextMenu.Items.Add(copyHex);
        _surface.ContextMenu.Items.Add(copyText);

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

    public void GoTo(ulong address)
    {
        if (_image is null) return;
        if (address < _image.MinVa) address = _image.MinVa;
        if (address > _image.MaxVa) address = _image.MaxVa;

        ulong aligned = address - (address % BytesPerRow);
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

    private static Brush Frozen(byte r, byte g, byte b) { var x = new SolidColorBrush(Color.FromRgb(r, g, b)); x.Freeze(); return x; }
    private static Brush FrozenA(byte a, byte r, byte g, byte b) { var x = new SolidColorBrush(Color.FromArgb(a, r, g, b)); x.Freeze(); return x; }

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
                CaptureMouse();
                _dragging = true;
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
            if (_dragging) { _dragging = false; ReleaseMouseCapture(); }
        }

        protected override void OnKeyDown(KeyEventArgs e)
        {
            if (e.Key == Key.C && (Keyboard.Modifiers & ModifierKeys.Control) != 0)
            {
                _owner.CopySelection(asText: false);
                e.Handled = true;
            }
        }

        protected override void OnRender(DrawingContext dc) => _owner.Render(dc, ActualWidth, ActualHeight);
    }
}

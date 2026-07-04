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
using Microsoft.Win32;

namespace DisasmStudio.Wpf.Controls;

/// <summary>
/// The managed (.NET) decompiler pane: a type/member tree on the left, and the selected node rendered as C#
/// or IL on the right — the managed counterpart to <see cref="DecompilerView"/>. It reuses the same
/// DPI-correct <see cref="FormattedText"/> drawing and shared <see cref="SyntaxTheme"/> brushes, but is driven
/// by a <see cref="ManagedAssembly"/> and a selected node rather than a native function/VA. Decompilation runs
/// on a background thread (large types never freeze the UI) and is seq-guarded so a fast tree click wins.
/// </summary>
public sealed class ManagedDecompilerView : Grid
{
    private readonly Surface _surface;
    private readonly ScrollBar _scroll;
    private readonly TreeView _tree;
    private readonly Button _csBtn;
    private readonly Button _ilBtn;
    private readonly TextBlock _path;

    private ManagedAssembly? _asm;
    private ManagedTypeNode? _node;
    private bool _il;
    private IReadOnlyList<DecompLine> _lines = [];
    private int _buildSeq;
    private long _top;
    private long _caret = -1;

    private readonly Typeface _typeface =
        new(new FontFamily("Cascadia Mono, Consolas"), FontStyles.Normal, FontWeights.Normal, FontStretches.Normal);
    private const double FontSize = 13.0;
    private double _rowHeight = 16;
    private double _charWidth = 8;

    public ManagedDecompilerView()
    {
        RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });

        // C# / IL toggle bar + current-node path.
        var bar = new Border
        {
            Background = (Brush)Application.Current.Resources["Surface"],
            BorderBrush = (Brush)Application.Current.Resources["Outline"],
            BorderThickness = new Thickness(0, 0, 0, 1),
            Padding = new Thickness(6, 4, 6, 4),
        };
        var dock = new DockPanel { LastChildFill = true };
        // Save-to-C# on the right; export the current node, or the whole assembly.
        var saveBtn = new Button { Content = "Save C#…", Margin = new Thickness(6, 0, 0, 0) };
        saveBtn.Click += OnSaveCSharp;
        DockPanel.SetDock(saveBtn, Dock.Right);
        dock.Children.Add(saveBtn);

        var strip = new StackPanel { Orientation = Orientation.Horizontal };
        _csBtn = new Button { Content = "C#", Margin = new Thickness(0, 0, 6, 0) };
        _ilBtn = new Button { Content = "IL", Margin = new Thickness(0, 0, 12, 0) };
        _csBtn.Click += (_, _) => SetMode(il: false);
        _ilBtn.Click += (_, _) => SetMode(il: true);
        _path = new TextBlock { VerticalAlignment = VerticalAlignment.Center, TextTrimming = TextTrimming.CharacterEllipsis,
            Foreground = (Brush)Application.Current.Resources["TextSecondary"] };
        strip.Children.Add(_csBtn);
        strip.Children.Add(_ilBtn);
        strip.Children.Add(_path);
        dock.Children.Add(strip);   // fills remaining space (LastChildFill)
        bar.Child = dock;
        SetRow(bar, 0);
        Children.Add(bar);

        // Left: member tree. Right: rendered code + scrollbar.
        var split = new Grid();
        split.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(300), MinWidth = 140 });
        split.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        split.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });

        _tree = new TreeView { BorderThickness = new Thickness(0) };
        _tree.SelectedItemChanged += OnTreeSelected;
        SetColumn(_tree, 0);
        split.Children.Add(_tree);

        var gs = new GridSplitter { Width = 4, HorizontalAlignment = HorizontalAlignment.Stretch, Background = (Brush)Application.Current.Resources["Outline"] };
        SetColumn(gs, 1);
        split.Children.Add(gs);

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
        SetColumn(host, 2);
        split.Children.Add(host);

        SetRow(split, 1);
        Children.Add(split);

        MeasureFont();
        UpdateModeButtons();
    }

    /// <summary>Show the assembly: build the tree and select its first application type.</summary>
    public void SetAssembly(ManagedAssembly asm)
    {
        _asm = asm;
        _node = null;
        _il = false;
        UpdateModeButtons();
        BuildTree(asm.Root);
    }

    // Export decompiled C# to a .cs file — the whole assembly, or just the current type/member.
    private async void OnSaveCSharp(object sender, RoutedEventArgs e)
    {
        if (_asm is not { } asm) return;
        var owner = Window.GetWindow(this);

        var node = _node;
        bool haveNode = node is { Kind: not ManagedNodeKind.Assembly and not ManagedNodeKind.Namespace };
        bool whole = true;
        if (haveNode)
        {
            var choice = MessageBox.Show(owner,
                $"Save the whole assembly as C#?\n\nYes — the whole assembly\nNo — just '{node!.Display}'",
                "Save C#", MessageBoxButton.YesNoCancel, MessageBoxImage.Question);
            if (choice == MessageBoxResult.Cancel) return;
            whole = choice == MessageBoxResult.Yes;
        }

        string baseName = SafeName(whole ? asm.Metadata.Name : node!.Display);
        var dlg = new SaveFileDialog { Title = "Save C#", FileName = baseName + ".cs", Filter = "C# source|*.cs|All files|*.*" };
        if (dlg.ShowDialog(owner) != true) return;
        string path = dlg.FileName;

        _path.Text = "Saving C#…";
        string text = await Task.Run(() => whole ? asm.WholeModuleCSharp() : asm.CSharpText(node!));
        try { File.WriteAllText(path, text); _path.Text = "Saved " + path; }
        catch (Exception ex) { MessageBox.Show(owner, ex.Message, "Save failed", MessageBoxButton.OK, MessageBoxImage.Error); _path.Text = ""; }
    }

    private static string SafeName(string s)
    {
        foreach (char c in Path.GetInvalidFileNameChars()) s = s.Replace(c, '_');
        return string.IsNullOrWhiteSpace(s) ? "decompiled" : s;
    }

    public void Clear()
    {
        _asm = null;
        _node = null;
        _tree.Items.Clear();
        _lines = [];
        _top = 0;
        _caret = -1;
        _path.Text = "";
        ConfigureScroll();
        _surface.InvalidateVisual();
    }

    /// <summary>Show a placeholder before the assembly finishes loading (so switching here shows a note, not blank).</summary>
    public void ShowLoading(string message)
    {
        _asm = null;
        _node = null;
        _tree.Items.Clear();
        _lines = [new DecompLine(0, [new AsmToken(message, AsmTokenKind.Comment)], 0)];
        _path.Text = "";
        _top = 0;
        _caret = -1;
        ConfigureScroll();
        _surface.InvalidateVisual();
    }

    // ---- tree ----

    private void BuildTree(ManagedTypeNode root)
    {
        _tree.Items.Clear();
        var rootItem = MakeItem(root);
        _tree.Items.Add(rootItem);
        rootItem.IsExpanded = true;   // fires OnItemExpanded synchronously → real namespace items replace the placeholder

        // Auto-select the first type so the pane isn't empty. Expand each namespace before reading its items (its
        // children are the lazy placeholder until then). Every cast is guarded, so this is safe even if a WPF
        // Expanded event ever fires late — worst case nothing is auto-selected.
        foreach (var nsObj in rootItem.Items)
        {
            if (nsObj is not TreeViewItem ns) continue;
            ns.IsExpanded = true;     // populate this namespace's type items synchronously
            foreach (var typeObj in ns.Items)
                if (typeObj is TreeViewItem t && t.Tag is ManagedTypeNode { Kind: ManagedNodeKind.Type or ManagedNodeKind.NestedType })
                {
                    t.IsSelected = true;
                    return;
                }
            ns.IsExpanded = false;    // no type here — collapse and try the next namespace
        }
        rootItem.IsSelected = true;   // fallback: nothing selectable
    }

    private TreeViewItem MakeItem(ManagedTypeNode node)
    {
        var item = new TreeViewItem { Header = Label(node), Tag = node };
        // Populate children lazily: attach a placeholder and fill on first expand so a large assembly's member
        // lists don't all materialise up front.
        if (node.Children.Count > 0)
        {
            item.Items.Add(Placeholder);
            item.Expanded += OnItemExpanded;
        }
        return item;
    }

    private static readonly object Placeholder = new();

    private void OnItemExpanded(object sender, RoutedEventArgs e)
    {
        if (sender is not TreeViewItem item || item.Tag is not ManagedTypeNode node) return;
        if (item.Items.Count == 1 && ReferenceEquals(item.Items[0], Placeholder))
        {
            item.Items.Clear();
            foreach (var child in node.Children) item.Items.Add(MakeItem(child));
        }
        e.Handled = true;
    }

    private static string Label(ManagedTypeNode n)
    {
        string sigil = n.Kind switch
        {
            ManagedNodeKind.Assembly => "▣ ",
            ManagedNodeKind.Namespace => "{ } ",
            ManagedNodeKind.Type or ManagedNodeKind.NestedType => "❏ ",
            ManagedNodeKind.Method => "ƒ ",
            ManagedNodeKind.Property => "◆ ",
            ManagedNodeKind.Event => "⚡ ",
            ManagedNodeKind.Field => "▪ ",
            _ => "",
        };
        return sigil + n.Display;
    }

    private void OnTreeSelected(object sender, RoutedPropertyChangedEventArgs<object> e)
    {
        if (e.NewValue is TreeViewItem { Tag: ManagedTypeNode node }) { _node = node; Rebuild(); }
    }

    // ---- decompilation ----

    private void SetMode(bool il)
    {
        if (_il == il) return;
        _il = il;
        UpdateModeButtons();
        Rebuild();
    }

    private void Rebuild()
    {
        if (_asm is not { } asm || _node is not { } node) return;
        _path.Text = (_il ? "IL — " : "C# — ") + node.Display;
        int seq = ++_buildSeq;
        _lines = [new DecompLine(0, [new AsmToken(_il ? "// disassembling…" : "// decompiling…", AsmTokenKind.Comment)], 0)];
        _top = 0; _caret = -1;
        ConfigureScroll();
        _surface.InvalidateVisual();

        bool il = _il;
        Task.Run(() => il ? asm.DecompileIl(node) : asm.DecompileCSharp(node)).ContinueWith(t =>
        {
            var lines = t.IsCompletedSuccessfully ? t.Result : [new DecompLine(0, [new AsmToken("// failed", AsmTokenKind.Comment)], 0)];
            Dispatcher.Invoke(() =>
            {
                if (seq != _buildSeq) return;   // a newer selection won
                _lines = lines;
                _top = 0; _caret = -1;
                ConfigureScroll();
                _surface.InvalidateVisual();
            });
        });
    }

    private void UpdateModeButtons()
    {
        _csBtn.FontWeight = _il ? FontWeights.Normal : FontWeights.SemiBold;
        _ilBtn.FontWeight = _il ? FontWeights.SemiBold : FontWeights.Normal;
        _csBtn.Foreground = _il ? (Brush)Application.Current.Resources["TextSecondary"] : (Brush)Application.Current.Resources["Accent"];
        _ilBtn.Foreground = _il ? (Brush)Application.Current.Resources["Accent"] : (Brush)Application.Current.Resources["TextSecondary"];
    }

    // ---- geometry / rendering (mirrors DecompilerView, minus the address gutter) ----

    private int VisibleRows => Math.Max(1, (int)(_surface.ActualHeight / _rowHeight));
    private const double ContentX = 8;
    private const int IndentChars = 4;

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
        _surface.InvalidateVisual();
    }

    private void Render(DrawingContext dc, double width, double height)
    {
        dc.DrawRectangle(SyntaxTheme.Background, null, new Rect(0, 0, width, height));
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
                dc.DrawRectangle(SyntaxTheme.CurrentLine, null, new Rect(0, y, width, _rowHeight));

            double x = ContentX + line.Indent * IndentChars * _charWidth;
            foreach (var tok in line.Tokens)
                x = Draw(dc, tok.Text, x, y, SyntaxTheme.BrushFor(tok.Kind), dpi);
        }
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
        private readonly ManagedDecompilerView _owner;
        public Surface(ManagedDecompilerView owner) { _owner = owner; ClipToBounds = true; Focusable = true; }

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
            switch (e.Key)
            {
                case Key.Down: _owner.MoveCaret(_owner._caret + 1); break;
                case Key.Up: _owner.MoveCaret(_owner._caret - 1); break;
                case Key.PageDown: _owner.MoveCaret(_owner._caret + _owner.VisibleRows); break;
                case Key.PageUp: _owner.MoveCaret(_owner._caret - _owner.VisibleRows); break;
                default: return;
            }
            e.Handled = true;
        }

        protected override void OnRender(DrawingContext dc) => _owner.Render(dc, ActualWidth, ActualHeight);
    }
}

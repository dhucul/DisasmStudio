using System.Collections.ObjectModel;
using System.Globalization;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Media;
using DisasmStudio.Debug;

namespace DisasmStudio.Wpf;

/// <summary>x64dbg/IDA-style exceptions editor: a grid of code (or range) → break-first / break-second /
/// pass-to-program. Edits the supplied <see cref="ExceptionFilter"/> in place when the user clicks OK.</summary>
internal static class ExceptionDialog
{
    private static readonly Brush Bg = new SolidColorBrush(Color.FromRgb(0x16, 0x1B, 0x22));
    private static readonly Brush Fg = new SolidColorBrush(Color.FromRgb(0xE6, 0xEA, 0xF0));
    private static readonly Brush Sub = new SolidColorBrush(Color.FromRgb(0xAE, 0xB7, 0xC4));
    private static readonly Brush RowBg = new SolidColorBrush(Color.FromRgb(0x1B, 0x21, 0x2A));
    private static readonly Brush HdrBg = new SolidColorBrush(Color.FromRgb(0x22, 0x2A, 0x35));

    private sealed class Row
    {
        public string Code { get; set; } = "";
        public string Name { get; set; } = "";
        public bool BreakFirst { get; set; } = true;
        public bool BreakSecond { get; set; } = true;
        public bool Pass { get; set; } = true;
        public bool IsDefault { get; set; }
    }

    /// <summary>Show the editor seeded from <paramref name="filter"/>. Returns a fresh filter on OK (so the
    /// caller can swap the engine's reference atomically — the debug thread may be reading the old one), or
    /// null if cancelled.</summary>
    public static ExceptionFilter? Show(Window owner, ExceptionFilter filter)
    {
        var rows = new ObservableCollection<Row>
        {
            new() { Code = "(any other exception)", Name = filter.Default.Name, BreakFirst = filter.Default.BreakFirstChance,
                    BreakSecond = filter.Default.BreakSecondChance, Pass = filter.Default.PassToProgram, IsDefault = true },
        };
        foreach (var r in filter.Rules.OrderBy(r => r.CodeLow))
            rows.Add(new Row
            {
                Code = r.CodeLow == r.CodeHigh ? $"{r.CodeLow:X8}" : $"{r.CodeLow:X8}-{r.CodeHigh:X8}",
                Name = r.Name, BreakFirst = r.BreakFirstChance, BreakSecond = r.BreakSecondChance, Pass = r.PassToProgram,
            });

        var grid = new DataGrid
        {
            ItemsSource = rows,
            AutoGenerateColumns = false,
            CanUserAddRows = false,
            CanUserDeleteRows = false,
            HeadersVisibility = DataGridHeadersVisibility.Column,
            GridLinesVisibility = DataGridGridLinesVisibility.Horizontal,
            Background = Bg, Foreground = Fg, RowBackground = RowBg, Margin = new Thickness(16, 16, 16, 8),
            BorderThickness = new Thickness(0), MinHeight = 280,
        };
        grid.ColumnHeaderStyle = HeaderStyle();
        var mono = new FontFamily("Cascadia Mono, Consolas");
        grid.Columns.Add(new DataGridTextColumn { Header = "Code (hex)", Binding = new System.Windows.Data.Binding("Code"), Width = 150, FontFamily = mono });
        grid.Columns.Add(new DataGridTextColumn { Header = "Name", Binding = new System.Windows.Data.Binding("Name"), Width = new DataGridLength(1, DataGridLengthUnitType.Star) });
        grid.Columns.Add(new DataGridCheckBoxColumn { Header = "Break 1st", Binding = new System.Windows.Data.Binding("BreakFirst") });
        grid.Columns.Add(new DataGridCheckBoxColumn { Header = "Break 2nd", Binding = new System.Windows.Data.Binding("BreakSecond") });
        grid.Columns.Add(new DataGridCheckBoxColumn { Header = "Pass to program", Binding = new System.Windows.Data.Binding("Pass") });

        var hint = new TextBlock
        {
            Text = "First-chance vs second-chance (unhandled). \"Pass to program\" lets the target's own handler run. " +
                   "Code is a single value (E06D7363) or a range (40010006-4001000A).",
            Foreground = Sub, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(16, 0, 16, 8),
        };

        var add = new Button { Content = "Add", MinWidth = 64, Margin = new Thickness(0, 0, 8, 0) };
        var remove = new Button { Content = "Remove", MinWidth = 64 };
        add.Click += (_, _) => rows.Add(new Row { Code = "0", Name = "" });
        remove.Click += (_, _) => { if (grid.SelectedItem is Row { IsDefault: false } r) rows.Remove(r); };
        var leftButtons = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(16, 0, 0, 16) };
        leftButtons.Children.Add(add);
        leftButtons.Children.Add(remove);

        ExceptionFilter? built = null;
        var ok = new Button { Content = "OK", IsDefault = true, MinWidth = 70, Margin = new Thickness(0, 0, 8, 0) };
        var cancel = new Button { Content = "Cancel", IsCancel = true, MinWidth = 70, Margin = new Thickness(0, 0, 16, 0) };
        var rightButtons = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right, Margin = new Thickness(0, 0, 0, 16) };
        rightButtons.Children.Add(ok);
        rightButtons.Children.Add(cancel);

        var win = new Window
        {
            Title = "Debugger exceptions", Owner = owner, Width = 640, Height = 460,
            WindowStartupLocation = WindowStartupLocation.CenterOwner, Background = Bg, Foreground = Fg,
        };
        ok.Click += (_, _) =>
        {
            grid.CommitEdit(DataGridEditingUnit.Cell, true);
            grid.CommitEdit(DataGridEditingUnit.Row, true);
            built = Build(rows);
            win.DialogResult = true;
        };

        var buttonBar = new Grid();
        buttonBar.Children.Add(leftButtons);
        buttonBar.Children.Add(rightButtons);

        var root = new DockPanel();
        DockPanel.SetDock(buttonBar, Dock.Bottom);
        DockPanel.SetDock(hint, Dock.Bottom);
        root.Children.Add(buttonBar);
        root.Children.Add(hint);
        root.Children.Add(grid);
        win.Content = root;
        win.ShowDialog();
        return built;
    }

    private static ExceptionFilter Build(IEnumerable<Row> rows)
    {
        var filter = new ExceptionFilter();
        foreach (var row in rows)
        {
            if (row.IsDefault)
            {
                filter.Default.Name = row.Name;
                filter.Default.BreakFirstChance = row.BreakFirst;
                filter.Default.BreakSecondChance = row.BreakSecond;
                filter.Default.PassToProgram = row.Pass;
                continue;
            }
            if (!TryParseRange(row.Code, out uint lo, out uint hi)) continue;   // drop unparseable rows
            filter.Rules.Add(new ExceptionRule
            {
                CodeLow = lo, CodeHigh = hi, Name = row.Name,
                BreakFirstChance = row.BreakFirst, BreakSecondChance = row.BreakSecond, PassToProgram = row.Pass,
            });
        }
        return filter;
    }

    private static bool TryParseRange(string s, out uint lo, out uint hi)
    {
        lo = hi = 0;
        if (string.IsNullOrWhiteSpace(s)) return false;
        s = s.Trim();
        int dash = s.IndexOf('-');
        if (dash > 0)
            return TryHex(s[..dash], out lo) && TryHex(s[(dash + 1)..], out hi) && hi >= lo;
        if (!TryHex(s, out lo)) return false;
        hi = lo;
        return true;
    }

    private static bool TryHex(string s, out uint v)
    {
        s = s.Trim();
        if (s.StartsWith("0x", StringComparison.OrdinalIgnoreCase)) s = s[2..];
        return uint.TryParse(s, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out v);
    }

    private static Style HeaderStyle()
    {
        var st = new Style(typeof(DataGridColumnHeader));
        st.Setters.Add(new Setter(Control.BackgroundProperty, HdrBg));
        st.Setters.Add(new Setter(Control.ForegroundProperty, Fg));
        st.Setters.Add(new Setter(Control.PaddingProperty, new Thickness(8, 4, 8, 4)));
        st.Setters.Add(new Setter(Control.BorderThicknessProperty, new Thickness(0)));
        return st;
    }
}

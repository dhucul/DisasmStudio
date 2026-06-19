using System.Globalization;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using DisasmStudio.Debug;
using DisasmStudio.Wpf.Services;

namespace DisasmStudio.Wpf.Controls;

/// <summary>
/// The debugger pane (shown at the bottom while a session is live): editable Registers with
/// dereference annotations, the Stack and a hex Memory dump (both dereferenced), the Call Stack, and
/// Breakpoints / Threads / Modules lists. Double-clicking an address navigates the disassembly.
/// </summary>
public sealed class DebugPanel : Grid
{
    private static readonly FontFamily Mono = new("Cascadia Mono, Consolas");

    private DebugSession? _session;
    private uint _viewTid;
    private ulong _dumpAddr;

    private readonly DataGrid _regs;
    private readonly ListBox _stack, _calls, _bps, _threads, _modules;
    private readonly TextBox _dump, _dumpAddrBox;
    private readonly List<ulong> _stackVas = [];
    private readonly List<ulong> _callVas = [];
    private readonly List<ulong> _bpVas = [];
    private readonly List<ulong> _moduleVas = [];

    public event Action<ulong>? NavigateRequested;

    private sealed class RegRow { public string Name { get; set; } = ""; public string Value { get; set; } = ""; public string Deref { get; set; } = ""; }

    public DebugPanel()
    {
        Background = (Brush)Application.Current.Resources["Surface"];
        ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(330) });
        ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(5) });
        ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(320) });
        ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(5) });
        ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });

        _regs = new DataGrid
        {
            AutoGenerateColumns = false, CanUserAddRows = false, CanUserReorderColumns = false,
            HeadersVisibility = DataGridHeadersVisibility.Column, FontFamily = Mono, FontSize = 12,
        };
        _regs.Columns.Add(new DataGridTextColumn { Header = "Reg", Binding = new System.Windows.Data.Binding("Name"), IsReadOnly = true, Width = 56 });
        _regs.Columns.Add(new DataGridTextColumn { Header = "Value", Binding = new System.Windows.Data.Binding("Value"), Width = 130 });
        _regs.Columns.Add(new DataGridTextColumn { Header = "→", Binding = new System.Windows.Data.Binding("Deref"), IsReadOnly = true, Width = new DataGridLength(1, DataGridLengthUnitType.Star) });
        _regs.CellEditEnding += OnRegEdit;
        Add(0, "Registers", _regs);

        _stack = MonoList(); _stack.MouseDoubleClick += (_, _) => NavTo(_stackVas, _stack.SelectedIndex);
        Add(2, "Stack", _stack);

        var tabs = new TabControl { Background = (Brush)Application.Current.Resources["Surface"] };
        _calls = MonoList(); _calls.MouseDoubleClick += (_, _) => NavTo(_callVas, _calls.SelectedIndex);
        _bps = MonoList(); _bps.MouseDoubleClick += (_, _) => NavTo(_bpVas, _bps.SelectedIndex);
        _threads = MonoList(); _threads.MouseDoubleClick += OnThreadActivate;
        _modules = MonoList(); _modules.MouseDoubleClick += (_, _) => NavTo(_moduleVas, _modules.SelectedIndex);

        var memPanel = new DockPanel();
        _dumpAddrBox = new TextBox { FontFamily = Mono, Margin = new Thickness(4), ToolTip = "Address or register to follow (Enter)" };
        _dumpAddrBox.KeyDown += (_, e) => { if (e.Key == Key.Enter) { _dumpAddr = ParseAddr(_dumpAddrBox.Text); RefreshDump(); } };
        DockPanel.SetDock(_dumpAddrBox, Dock.Top);
        _dump = new TextBox { FontFamily = Mono, FontSize = 12, IsReadOnly = true, VerticalScrollBarVisibility = ScrollBarVisibility.Auto, BorderThickness = new Thickness(0) };
        memPanel.Children.Add(_dumpAddrBox);
        memPanel.Children.Add(_dump);

        tabs.Items.Add(new TabItem { Header = "Memory", Content = memPanel });
        tabs.Items.Add(new TabItem { Header = "Call Stack", Content = _calls });
        tabs.Items.Add(new TabItem { Header = "Breakpoints", Content = _bps });
        tabs.Items.Add(new TabItem { Header = "Threads", Content = _threads });
        tabs.Items.Add(new TabItem { Header = "Modules", Content = _modules });
        SetColumn(tabs, 4);
        Children.Add(tabs);

        var sp1 = new GridSplitter { Width = 5, HorizontalAlignment = HorizontalAlignment.Stretch, Background = (Brush)Application.Current.Resources["Outline"] };
        var sp2 = new GridSplitter { Width = 5, HorizontalAlignment = HorizontalAlignment.Stretch, Background = (Brush)Application.Current.Resources["Outline"] };
        SetColumn(sp1, 1); SetColumn(sp2, 3);
        Children.Add(sp1); Children.Add(sp2);
    }

    private void Add(int col, string title, FrameworkElement body)
    {
        var dock = new DockPanel();
        var hdr = new TextBlock { Text = title.ToUpperInvariant(), Margin = new Thickness(8, 6, 8, 4), FontWeight = FontWeights.SemiBold, FontSize = 11, Foreground = (Brush)Application.Current.Resources["TextMuted"] };
        DockPanel.SetDock(hdr, Dock.Top);
        dock.Children.Add(hdr);
        dock.Children.Add(body);
        SetColumn(dock, col);
        Children.Add(dock);
    }

    private static ListBox MonoList() => new() { FontFamily = Mono, FontSize = 12, Background = (Brush)Application.Current.Resources["Surface"] };

    public void SetSession(DebugSession? session) { _session = session; _viewTid = 0; _dumpAddr = 0; }

    public void Refresh()
    {
        if (_session is null || !_session.IsStopped) return;
        var regs = _viewTid != 0 ? _session.Engine.GetRegisters(_viewTid) : _session.Registers;
        if (regs is null) return;
        var deref = _session.Deref;

        int w = regs.Is32 ? 8 : 16;
        var rows = new List<RegRow>();
        foreach (var (name, value) in regs.Items)
            rows.Add(new RegRow { Name = name, Value = value.ToString("X" + (name is "cs" or "ds" or "es" or "fs" or "gs" or "ss" ? "4" : w.ToString())), Deref = deref?.Describe(value) ?? "" });
        _regs.ItemsSource = rows;

        // stack
        _stack.Items.Clear(); _stackVas.Clear();
        int ptr = regs.Is32 ? 4 : 8;
        var sb = _session.Engine.ReadMemory(regs.Sp, ptr * 24);
        for (int i = 0; i + ptr <= sb.Length; i += ptr)
        {
            ulong slot = regs.Sp + (ulong)i;
            ulong val = ptr == 8 ? BitConverter.ToUInt64(sb, i) : BitConverter.ToUInt32(sb, i);
            string d = deref?.Describe(val) ?? "";
            _stackVas.Add(val);
            _stack.Items.Add($"{slot:X}  {val.ToString("X" + w)}  {d}");
        }

        // call stack
        _calls.Items.Clear(); _callVas.Clear();
        foreach (var f in CallStack.Walk(_session.Engine, regs))
        {
            _callVas.Add(f);
            _calls.Items.Add($"{f.ToString("X" + w)}  {_session.LiveResult?.NameFor(f) ?? deref?.Describe(f) ?? ""}");
        }

        // breakpoints
        _bps.Items.Clear(); _bpVas.Clear();
        foreach (var bp in _session.Engine.BreakpointList)
        {
            _bpVas.Add(bp.Address);
            _bps.Items.Add($"{bp.Address.ToString("X" + w)}  {(bp.Hardware ? $"hw {bp.Kind}" : "software")}  {_session.LiveResult?.NameFor(bp.Address) ?? ""}");
        }

        // threads
        _threads.Items.Clear();
        foreach (var t in _session.Engine.Threads)
            _threads.Items.Add($"{t.Id}{(t.Id == _session.Engine.CurrentThreadId ? "  (current)" : "")}");

        // modules
        _modules.Items.Clear(); _moduleVas.Clear();
        foreach (var m in _session.Engine.Modules)
        {
            _moduleVas.Add(m.Base);
            _modules.Items.Add($"{m.Base.ToString("X" + w)}  {m.Name}");
        }

        if (_dumpAddr == 0) _dumpAddr = regs.Sp;
        RefreshDump();
    }

    private void RefreshDump()
    {
        if (_session is null || !_session.IsStopped) return;
        var bytes = _session.Engine.ReadMemory(_dumpAddr, 16 * 16);
        var sb = new System.Text.StringBuilder();
        for (int row = 0; row * 16 < bytes.Length; row++)
        {
            int n = Math.Min(16, bytes.Length - row * 16);
            sb.Append((_dumpAddr + (ulong)(row * 16)).ToString("X16")).Append("  ");
            for (int i = 0; i < 16; i++) sb.Append(i < n ? bytes[row * 16 + i].ToString("X2") + " " : "   ");
            sb.Append(' ');
            for (int i = 0; i < n; i++) { byte b = bytes[row * 16 + i]; sb.Append(b is >= 0x20 and < 0x7F ? (char)b : '.'); }
            sb.Append('\n');
        }
        _dump.Text = sb.ToString();
    }

    private void OnRegEdit(object? sender, DataGridCellEditEndingEventArgs e)
    {
        if (_session is null || e.EditAction != DataGridEditAction.Commit || e.Column.DisplayIndex != 1) return;
        if (e.Row.Item is not RegRow row || e.EditingElement is not TextBox tb) return;
        if (ulong.TryParse(tb.Text.Replace("0x", "").Trim(), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var val))
            _session.Engine.SetRegister(row.Name, val, _viewTid);
        Dispatcher.BeginInvoke(Refresh);
    }

    private void OnThreadActivate(object? sender, MouseButtonEventArgs e)
    {
        if (_session is null || _threads.SelectedItem is not string s) return;
        var idx = s.IndexOf(' ');
        if (uint.TryParse(idx > 0 ? s[..idx] : s, out var tid)) { _viewTid = tid; _dumpAddr = 0; Refresh(); }
    }

    private void NavTo(List<ulong> vas, int idx) { if (idx >= 0 && idx < vas.Count && vas[idx] != 0) NavigateRequested?.Invoke(vas[idx]); }

    private ulong ParseAddr(string s)
    {
        s = s.Trim();
        if (_session?.Registers is { } r) foreach (var (name, value) in r.Items) if (string.Equals(name, s, StringComparison.OrdinalIgnoreCase)) return value;
        if (s.StartsWith("0x", StringComparison.OrdinalIgnoreCase)) s = s[2..];
        return ulong.TryParse(s, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var v) ? v : _dumpAddr;
    }
}

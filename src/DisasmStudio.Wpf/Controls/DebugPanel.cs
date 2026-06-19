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
    private readonly DataGrid _stack;
    private readonly ListBox _calls, _bps, _threads, _modules, _capture;
    private readonly TreeView _callGraph;
    private readonly TabControl _tabs;
    private readonly HexView _dump;
    private readonly TextBox _dumpAddrBox;
    private bool _dumpInit;
    private readonly List<ulong> _callVas = [];
    private readonly List<ulong> _bpVas = [];
    private readonly List<ulong> _moduleVas = [];

    public event Action<ulong>? NavigateRequested;

    private sealed class RegRow { public string Name { get; set; } = ""; public string Value { get; set; } = ""; public string Deref { get; set; } = ""; }
    private sealed class StackRow { public string Addr { get; set; } = ""; public string Value { get; set; } = ""; public string Deref { get; set; } = ""; public ulong Slot; public ulong ValueRaw; }
    private sealed class CaptureItem { public ulong Va; public string Text = ""; public override string ToString() => Text; }

    // EFLAGS bits shown as individual, editable (0/1) rows after the registers.
    private static readonly (string Name, int Bit)[] Flags =
        [("CF", 0), ("PF", 2), ("AF", 4), ("ZF", 6), ("SF", 7), ("TF", 8), ("IF", 9), ("DF", 10), ("OF", 11)];

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
            IsReadOnly = false,   // the global DataGrid style is read-only; registers/flags are editable
        };
        _regs.Columns.Add(new DataGridTextColumn { Header = "Reg", Binding = new System.Windows.Data.Binding("Name"), IsReadOnly = true, Width = 56 });
        _regs.Columns.Add(new DataGridTextColumn { Header = "Value", Binding = new System.Windows.Data.Binding("Value"), Width = 130 });
        _regs.Columns.Add(new DataGridTextColumn { Header = "→", Binding = new System.Windows.Data.Binding("Deref"), IsReadOnly = true, Width = new DataGridLength(1, DataGridLengthUnitType.Star) });
        _regs.CellEditEnding += OnRegEdit;
        Add(0, "Registers", _regs);

        _stack = new DataGrid
        {
            AutoGenerateColumns = false, CanUserAddRows = false, CanUserReorderColumns = false,
            HeadersVisibility = DataGridHeadersVisibility.Column, FontFamily = Mono, FontSize = 12, IsReadOnly = false,
        };
        _stack.Columns.Add(new DataGridTextColumn { Header = "Addr", Binding = new System.Windows.Data.Binding("Addr"), IsReadOnly = true, Width = 116 });
        _stack.Columns.Add(new DataGridTextColumn { Header = "Value", Binding = new System.Windows.Data.Binding("Value"), Width = 130 });
        _stack.Columns.Add(new DataGridTextColumn { Header = "→", Binding = new System.Windows.Data.Binding("Deref"), IsReadOnly = true, Width = new DataGridLength(1, DataGridLengthUnitType.Star) });
        _stack.CellEditEnding += OnStackEdit;
        _stack.MouseDoubleClick += OnStackActivate;
        Add(2, "Stack", _stack);

        var tabs = new TabControl { Background = (Brush)Application.Current.Resources["Surface"] };
        _tabs = tabs;
        _calls = MonoList(); _calls.MouseDoubleClick += (_, _) => NavTo(_callVas, _calls.SelectedIndex);
        _bps = MonoList(); _bps.MouseDoubleClick += (_, _) => NavTo(_bpVas, _bps.SelectedIndex);
        _threads = MonoList(); _threads.MouseDoubleClick += OnThreadActivate;
        _modules = MonoList(); _modules.MouseDoubleClick += (_, _) => NavTo(_moduleVas, _modules.SelectedIndex);
        _capture = MonoList(); _capture.MouseDoubleClick += (_, _) => { if (_capture.SelectedItem is CaptureItem ci && ci.Va != 0) NavigateRequested?.Invoke(ci.Va); };
        _callGraph = new TreeView { FontFamily = Mono, FontSize = 12, Background = (Brush)Application.Current.Resources["Surface"], BorderThickness = new Thickness(0) };
        _callGraph.MouseDoubleClick += (_, _) => { if (_callGraph.SelectedItem is TreeViewItem ti && ti.Tag is ulong va && va != 0) NavigateRequested?.Invoke(va); };

        var memPanel = new DockPanel();
        _dump = new HexView();   // editable hex view over the whole live address space
        _dumpAddrBox = new TextBox { FontFamily = Mono, Margin = new Thickness(4), ToolTip = "Address or register to follow (Enter); type hex over a byte to edit memory" };
        _dumpAddrBox.KeyDown += (_, e) => { if (e.Key == Key.Enter) { _dumpAddr = ParseAddr(_dumpAddrBox.Text); _dump.GoTo(_dumpAddr); } };
        DockPanel.SetDock(_dumpAddrBox, Dock.Top);
        memPanel.Children.Add(_dumpAddrBox);
        memPanel.Children.Add(_dump);

        tabs.Items.Add(new TabItem { Header = "Memory", Content = memPanel });
        tabs.Items.Add(new TabItem { Header = "Call Stack", Content = _calls });
        tabs.Items.Add(new TabItem { Header = "Breakpoints", Content = _bps });
        tabs.Items.Add(new TabItem { Header = "Threads", Content = _threads });
        tabs.Items.Add(new TabItem { Header = "Modules", Content = _modules });
        tabs.Items.Add(new TabItem { Header = "Capture", Content = _capture });
        tabs.Items.Add(new TabItem { Header = "Call Graph", Content = _callGraph });
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

    public void SetSession(DebugSession? session) { _session = session; _viewTid = 0; _dumpAddr = 0; _dumpInit = false; _dump.SetImage(null); ClearCapture(); }

    // ---- FunCap-style capture display ----

    public void ClearCapture() { _capture.Items.Clear(); _callGraph.Items.Clear(); }

    public void SelectCaptureTab() { foreach (TabItem t in _tabs.Items) if ((string)t.Header == "Capture") { _tabs.SelectedItem = t; break; } }

    /// <summary>Append capture records [<paramref name="from"/>..] as log lines; returns the new total shown.</summary>
    public void AppendCapture(IReadOnlyList<CaptureRecord> recs, int from, bool is32)
    {
        bool atEnd = _capture.Items.Count == 0 || _capture.SelectedIndex < 0;
        for (int i = from; i < recs.Count; i++)
            _capture.Items.Add(new CaptureItem { Va = recs[i].CalleeVa, Text = FunctionCapture.Format(recs[i], is32) });
        if (atEnd && _capture.Items.Count > 0) _capture.ScrollIntoView(_capture.Items[^1]);
    }

    public void RebuildCallGraph(Dictionary<ulong, HashSet<ulong>> edges, Func<ulong, string> nameOf)
    {
        _callGraph.Items.Clear();
        if (edges.Count == 0) return;
        var callees = new HashSet<ulong>(edges.Values.SelectMany(s => s));
        var roots = edges.Keys.Where(k => !callees.Contains(k)).ToList();
        if (roots.Count == 0) roots = edges.Keys.ToList();
        foreach (var r in roots.OrderBy(x => x)) _callGraph.Items.Add(BuildNode(r, edges, nameOf, [], 0));
    }

    private static TreeViewItem BuildNode(ulong va, Dictionary<ulong, HashSet<ulong>> edges, Func<ulong, string> nameOf, HashSet<ulong> path, int depth)
    {
        var item = new TreeViewItem { Header = nameOf(va), Tag = va };
        if (depth < 12 && path.Add(va) && edges.TryGetValue(va, out var callees))
        {
            foreach (var c in callees.OrderBy(x => x)) item.Items.Add(BuildNode(c, edges, nameOf, path, depth + 1));
            path.Remove(va);
        }
        return item;
    }

    public void Refresh()
    {
        if (_session is null || !_session.IsStopped) return;
        // Read fresh (the debuggee is frozen) so register/flag edits are reflected, not the last-stop snapshot.
        var regs = _session.Engine.GetRegisters(_viewTid);
        if (regs is null && _viewTid != 0) { _viewTid = 0; regs = _session.Engine.GetRegisters(0); }  // viewed thread gone
        if (regs is null) return;
        var deref = _session.Deref;

        int w = regs.Is32 ? 8 : 16;
        var rows = new List<RegRow>();
        foreach (var (name, value) in regs.Items)
            rows.Add(new RegRow { Name = name, Value = value.ToString("X" + (name is "cs" or "ds" or "es" or "fs" or "gs" or "ss" ? "4" : w.ToString())), Deref = deref?.Describe(value) ?? "" });
        // individual CPU flags (decoded from rflags/eflags), each editable as 0/1
        ulong fl = regs[regs.Is32 ? "eflags" : "rflags"];
        foreach (var (fname, bit) in Flags)
            rows.Add(new RegRow { Name = fname, Value = ((fl >> bit) & 1).ToString(), Deref = (((fl >> bit) & 1) != 0) ? "set" : "" });
        _regs.ItemsSource = rows;

        // stack (editable: Value commits write to process memory)
        int ptr = regs.Is32 ? 4 : 8;
        var sb = _session.Engine.ReadMemory(regs.Sp, ptr * 24);
        var stackRows = new List<StackRow>();
        for (int i = 0; i + ptr <= sb.Length; i += ptr)
        {
            ulong slot = regs.Sp + (ulong)i;
            ulong val = ptr == 8 ? BitConverter.ToUInt64(sb, i) : BitConverter.ToUInt32(sb, i);
            stackRows.Add(new StackRow { Addr = slot.ToString("X" + w), Value = val.ToString("X" + w), Deref = deref?.Describe(val) ?? "", Slot = slot, ValueRaw = val });
        }
        _stack.ItemsSource = stackRows;

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

        // memory dump: an editable HexView over the whole live address space
        if (!_dumpInit)
        {
            _dump.SetImage(new FullMemoryImage(_session.Engine));
            _dump.WriteByteAt = (va, b) => _session?.Engine.WriteMemory(va, [b]) ?? false;
            _dumpInit = true;
            if (_dumpAddr == 0) _dumpAddr = regs.Sp;
            _dump.GoTo(_dumpAddr);
        }
        else _dump.InvalidateView();   // re-read after stepping
    }

    private void OnRegEdit(object? sender, DataGridCellEditEndingEventArgs e)
    {
        if (_session is null || e.EditAction != DataGridEditAction.Commit || e.Column.DisplayIndex != 1) return;
        if (e.Row.Item is not RegRow row || e.EditingElement is not TextBox tb) return;
        var regs = _session.Engine.GetRegisters(_viewTid);

        int idx = Array.FindIndex(Flags, f => f.Name.Equals(row.Name, StringComparison.OrdinalIgnoreCase));
        if (idx >= 0 && regs is not null)
        {
            // editing a flag: set/clear that bit in rflags/eflags
            string fn = regs.Is32 ? "eflags" : "rflags";
            ulong fl = regs[fn];
            bool on = tb.Text.Trim() is not ("0" or "" or "false" or "False");
            int bit = Flags[idx].Bit;
            _session.Engine.SetRegister(fn, on ? fl | (1UL << bit) : fl & ~(1UL << bit), _viewTid);
        }
        else if (ulong.TryParse(tb.Text.Replace("0x", "").Trim(), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var val))
            _session.Engine.SetRegister(row.Name, val, _viewTid);

        Dispatcher.BeginInvoke(Refresh);
    }

    private void OnStackEdit(object? sender, DataGridCellEditEndingEventArgs e)
    {
        if (_session is null || e.EditAction != DataGridEditAction.Commit || e.Column.DisplayIndex != 1) return;
        if (e.Row.Item is not StackRow row || e.EditingElement is not TextBox tb) return;
        if (ulong.TryParse(tb.Text.Replace("0x", "").Trim(), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var val))
        {
            var bytes = _session.Engine.Is32 ? BitConverter.GetBytes((uint)val) : BitConverter.GetBytes(val);
            _session.Engine.WriteMemory(row.Slot, bytes);
        }
        Dispatcher.BeginInvoke(Refresh);
    }

    private void OnStackActivate(object? sender, MouseButtonEventArgs e)
    {
        if (_stack.CurrentColumn?.DisplayIndex == 1) return;   // double-clicking the Value column edits, not navigates
        if (_stack.SelectedItem is StackRow row && row.ValueRaw != 0) NavigateRequested?.Invoke(row.ValueRaw);
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
        if (_session?.Engine.GetRegisters(_viewTid) is { } r) foreach (var (name, value) in r.Items) if (string.Equals(name, s, StringComparison.OrdinalIgnoreCase)) return value;
        if (s.StartsWith("0x", StringComparison.OrdinalIgnoreCase)) s = s[2..];
        return ulong.TryParse(s, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var v) ? v : _dumpAddr;
    }
}

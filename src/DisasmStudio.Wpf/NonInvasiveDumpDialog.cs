using System.Diagnostics;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using DisasmStudio.Debug.Unpacking;

namespace DisasmStudio.Wpf;

/// <summary>
/// The non-invasive dumper dialog: snapshot a process's main image to a clean PE without attaching a debugger,
/// so an anti-debug protector passes its own checks and decrypts itself. Two modes — <b>Attach</b> to a process
/// you launched separately and pick by PID, or <b>Launch and watch</b>, where the tool starts the target itself
/// (still no debugger) and watches from the first instruction. Either way the <b>Auto</b> watch dumps the moment
/// the image settles (its code stops changing and looks decrypted / the app goes idle). Built in code to match
/// the project's other dialogs.
/// </summary>
internal sealed class NonInvasiveDumpDialog : Window
{
    private static readonly Brush Bg = new SolidColorBrush(Color.FromRgb(0x16, 0x1B, 0x22));
    private static readonly Brush Fg = new SolidColorBrush(Color.FromRgb(0xE6, 0xEA, 0xF0));
    private static readonly Brush Sub = new SolidColorBrush(Color.FromRgb(0xAE, 0xB7, 0xC4));
    private static readonly FontFamily Mono = new("Cascadia Mono, Consolas");

    private readonly ulong _preferredImageBase;
    private readonly string _defaultDir;

    private readonly RadioButton _modeAttach;
    private readonly RadioButton _modeLaunch;
    private readonly StackPanel _attachPanel;
    private readonly StackPanel _launchPanel;
    private readonly ComboBox _process;
    private readonly TextBox _targetPath;
    private readonly TextBox _args;
    private readonly CheckBox _sandbox;
    private readonly CheckBox _suspend;
    private readonly CheckBox _snapshot;
    private readonly CheckBox _auto;
    private readonly TextBox _maxWait;
    private readonly TextBox _output;
    private readonly TextBox _log;
    private readonly Button _dump;
    private readonly Button _open;
    private readonly Button _openSnap;
    private bool _running;
    private string? _snapPath;
    private CancellationTokenSource? _cts;

    /// <summary>Set to the dumped file's path when the user chooses to reopen it; null otherwise.</summary>
    public string? OpenPath { get; private set; }

    private sealed record ProcItem(int Pid, string Name)
    {
        public override string ToString() => $"{Name}  (pid {Pid})";
    }

    public NonInvasiveDumpDialog(Window owner, ulong preferredImageBase, string? defaultDir)
    {
        _preferredImageBase = preferredImageBase;
        _defaultDir = string.IsNullOrWhiteSpace(defaultDir) || !Directory.Exists(defaultDir)
            ? Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments)
            : defaultDir!;

        Owner = owner;
        Title = "Dump process (non-invasive)";
        Width = 660;
        Height = 600;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        Background = Bg;
        Foreground = Fg;

        var root = new Grid { Margin = new Thickness(16) };
        root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });   // blurb
        root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });   // options
        root.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) }); // log
        root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });   // buttons

        var blurb = new TextBlock
        {
            Text = "Snapshots a process's main image without debugging it — so a protector's anti-debug checks " +
                   "pass and the program decrypts itself. Attach to a separately-launched target, or have the tool " +
                   "launch and watch it from the first instruction. Virtualized code stays virtualized — feed such " +
                   "a dump to the Devirtualizer.",
            Foreground = Sub, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 0, 0, 12),
        };
        Grid.SetRow(blurb, 0);
        root.Children.Add(blurb);

        var opt = new StackPanel();
        Grid.SetRow(opt, 1);

        // --- mode ---
        var modeRow = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 0, 0, 8) };
        _modeAttach = new RadioButton { Content = "Attach to running process", Foreground = Fg, IsChecked = true, Margin = new Thickness(0, 0, 18, 0) };
        _modeLaunch = new RadioButton { Content = "Launch and watch", Foreground = Fg };
        modeRow.Children.Add(_modeAttach);
        modeRow.Children.Add(_modeLaunch);
        opt.Children.Add(modeRow);

        // --- attach panel ---
        _attachPanel = new StackPanel();
        _attachPanel.Children.Add(Label("Target process"));
        var procRow = new DockPanel { Margin = new Thickness(0, 0, 0, 4) };
        var refresh = new Button { Content = "Refresh", MinWidth = 76, Margin = new Thickness(8, 0, 0, 0) };
        refresh.Click += (_, _) => PopulateProcesses();
        DockPanel.SetDock(refresh, Dock.Right);
        _process = new ComboBox { FontFamily = Mono };
        _process.SelectionChanged += (_, _) => SuggestOutputPath();
        procRow.Children.Add(refresh);
        procRow.Children.Add(_process);
        _attachPanel.Children.Add(procRow);
        opt.Children.Add(_attachPanel);

        // --- launch panel ---
        _launchPanel = new StackPanel { Visibility = Visibility.Collapsed };
        _launchPanel.Children.Add(Label("Target executable"));
        var tgtRow = new DockPanel { Margin = new Thickness(0, 0, 0, 6) };
        var browseTgt = new Button { Content = "Browse…", MinWidth = 76, Margin = new Thickness(8, 0, 0, 0) };
        browseTgt.Click += OnBrowseTarget;
        DockPanel.SetDock(browseTgt, Dock.Right);
        _targetPath = new TextBox { FontFamily = Mono };
        _targetPath.TextChanged += (_, _) => SuggestOutputPath();
        tgtRow.Children.Add(browseTgt);
        tgtRow.Children.Add(_targetPath);
        _launchPanel.Children.Add(tgtRow);
        _launchPanel.Children.Add(Label("Arguments (optional)"));
        _args = new TextBox { FontFamily = Mono, Margin = new Thickness(0, 0, 0, 6) };
        _launchPanel.Children.Add(_args);
        _sandbox = new CheckBox
        {
            Content = "Sandbox: job object (blocks child processes, kill-on-close)",
            Foreground = Fg, IsChecked = true, Margin = new Thickness(0, 0, 0, 2),
        };
        _launchPanel.Children.Add(_sandbox);
        _launchPanel.Children.Add(new TextBlock
        {
            Text = "Process-level containment only — it does NOT block network or filesystem access. " +
                   "Run truly untrusted samples in a disposable VM.",
            Foreground = new SolidColorBrush(Color.FromRgb(0xF0, 0xB6, 0x4D)),
            FontSize = 11, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(20, 0, 0, 4),
        });
        opt.Children.Add(_launchPanel);

        // --- shared options ---
        _suspend = new CheckBox
        {
            Content = "Suspend the target while dumping (consistent snapshot; thawed afterward)",
            Foreground = Fg, IsChecked = true, Margin = new Thickness(0, 8, 0, 4),
        };
        opt.Children.Add(_suspend);

        _snapshot = new CheckBox
        {
            Content = "Full process snapshot (.dssnap): also capture private VM/heap regions (for VM protectors)",
            Foreground = Fg, IsChecked = false, Margin = new Thickness(0, 0, 0, 4),
        };
        opt.Children.Add(_snapshot);

        _auto = new CheckBox
        {
            Content = "Auto: watch the target and dump when its image settles (decrypted / idle)",
            Foreground = Fg, IsChecked = true, Margin = new Thickness(0, 0, 0, 4),
        };
        _auto.Checked += (_, _) => UpdateMaxWaitEnabled();
        _auto.Unchecked += (_, _) => UpdateMaxWaitEnabled();
        opt.Children.Add(_auto);

        var waitRow = new DockPanel { Margin = new Thickness(20, 0, 0, 8) };
        var waitLabel = new TextBlock { Text = "max wait (s)", Foreground = Sub, VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(0, 0, 8, 0) };
        DockPanel.SetDock(waitLabel, Dock.Left);
        _maxWait = new TextBox { FontFamily = Mono, Text = "30", Width = 56, HorizontalAlignment = HorizontalAlignment.Left };
        waitRow.Children.Add(waitLabel);
        waitRow.Children.Add(_maxWait);
        opt.Children.Add(waitRow);

        opt.Children.Add(Label("Output file"));
        var outRow = new DockPanel { Margin = new Thickness(0, 0, 0, 6) };
        var browse = new Button { Content = "Browse…", MinWidth = 76, Margin = new Thickness(8, 0, 0, 0) };
        browse.Click += OnBrowseOutput;
        DockPanel.SetDock(browse, Dock.Right);
        _output = new TextBox { FontFamily = Mono };
        outRow.Children.Add(browse);
        outRow.Children.Add(_output);
        opt.Children.Add(outRow);
        root.Children.Add(opt);

        _modeAttach.Checked += (_, _) => ApplyMode();
        _modeLaunch.Checked += (_, _) => ApplyMode();

        // --- log ---
        _log = new TextBox
        {
            IsReadOnly = true, FontFamily = Mono, FontSize = 11,
            Background = new SolidColorBrush(Color.FromRgb(0x0E, 0x11, 0x16)), Foreground = Sub,
            VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
            TextWrapping = TextWrapping.NoWrap, HorizontalScrollBarVisibility = ScrollBarVisibility.Auto,
            Margin = new Thickness(0, 4, 0, 8), AcceptsReturn = true,
        };
        Grid.SetRow(_log, 2);
        root.Children.Add(_log);

        // --- buttons ---
        var buttons = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right };
        Grid.SetRow(buttons, 3);
        _dump = new Button { Content = "Dump", IsDefault = true, MinWidth = 120, Margin = new Thickness(0, 0, 8, 0) };
        _dump.Click += OnDump;
        _open = new Button { Content = "Open dump", MinWidth = 100, Margin = new Thickness(0, 0, 8, 0), IsEnabled = false };
        _open.Click += (_, _) => { OpenPath = _output.Text.Trim(); DialogResult = true; };
        _openSnap = new Button { Content = "Open snapshot", MinWidth = 110, Margin = new Thickness(0, 0, 8, 0), IsEnabled = false };
        _openSnap.Click += (_, _) => { if (_snapPath is { Length: > 0 }) { OpenPath = _snapPath; DialogResult = true; } };
        var close = new Button { Content = "Close", IsCancel = true, MinWidth = 80 };
        buttons.Children.Add(_dump);
        buttons.Children.Add(_open);
        buttons.Children.Add(_openSnap);
        buttons.Children.Add(close);
        root.Children.Add(buttons);

        Content = root;
        PopulateProcesses();
        ApplyMode();
    }

    private bool LaunchMode => _modeLaunch.IsChecked == true;

    private void ApplyMode()
    {
        bool launch = LaunchMode;
        _attachPanel.Visibility = launch ? Visibility.Collapsed : Visibility.Visible;
        _launchPanel.Visibility = launch ? Visibility.Visible : Visibility.Collapsed;
        // Launch-and-watch inherently watches from t=0, so Auto is implied and locked on.
        if (launch) { _auto.IsChecked = true; _auto.IsEnabled = false; }
        else _auto.IsEnabled = !_running;
        _dump.Content = launch ? "Launch & Dump" : "Dump";
        UpdateMaxWaitEnabled();
        SuggestOutputPath();
    }

    private void UpdateMaxWaitEnabled() => _maxWait.IsEnabled = !_running && (LaunchMode || _auto.IsChecked == true);

    private void PopulateProcesses()
    {
        int previously = (_process.SelectedItem as ProcItem)?.Pid ?? -1;
        var items = new List<ProcItem>();
        foreach (var p in Process.GetProcesses())
        {
            try { items.Add(new ProcItem(p.Id, p.ProcessName)); }
            catch { /* process exited between enumeration and read */ }
            finally { p.Dispose(); }
        }
        items.Sort((a, b) =>
        {
            int c = string.Compare(a.Name, b.Name, StringComparison.OrdinalIgnoreCase);
            return c != 0 ? c : a.Pid.CompareTo(b.Pid);
        });
        _process.ItemsSource = items;
        var keep = items.FirstOrDefault(i => i.Pid == previously);
        _process.SelectedItem = keep ?? items.FirstOrDefault();
        if (keep is null) SuggestOutputPath();
    }

    private void SuggestOutputPath()
    {
        string? stem = null;
        string dir = _defaultDir;
        if (LaunchMode)
        {
            string t = _targetPath?.Text.Trim() ?? "";
            if (t.Length > 0)
            {
                stem = Path.GetFileNameWithoutExtension(t);
                string d = SafeDir(t);
                if (Directory.Exists(d)) dir = d;
            }
        }
        else if (_process.SelectedItem is ProcItem p)
        {
            stem = $"{p.Name}_{p.Pid}";
        }
        if (string.IsNullOrEmpty(stem)) return;
        // Only overwrite the box if it's empty or still a prior suggestion, so a hand-edited path is preserved.
        if (string.IsNullOrWhiteSpace(_output.Text) || _output.Text.EndsWith("_dump.exe", StringComparison.OrdinalIgnoreCase))
            _output.Text = Path.Combine(dir, $"{stem}_dump.exe");
    }

    private void OnBrowseTarget(object sender, RoutedEventArgs e)
    {
        var dlg = new Microsoft.Win32.OpenFileDialog
        {
            Title = "Choose target executable",
            Filter = "Executable (*.exe)|*.exe|All files (*.*)|*.*",
            InitialDirectory = SafeDir(_targetPath.Text),
        };
        if (dlg.ShowDialog(this) == true) _targetPath.Text = dlg.FileName;
    }

    private void OnBrowseOutput(object sender, RoutedEventArgs e)
    {
        var dlg = new Microsoft.Win32.SaveFileDialog
        {
            Title = "Save dumped image",
            Filter = "Executable (*.exe)|*.exe|All files (*.*)|*.*",
            FileName = Path.GetFileName(_output.Text),
            InitialDirectory = SafeDir(_output.Text),
        };
        if (dlg.ShowDialog(this) == true) _output.Text = dlg.FileName;
    }

    private async void OnDump(object sender, RoutedEventArgs e)
    {
        if (_running) { _cts?.Cancel(); _dump.IsEnabled = false; return; }   // "Stop" pressed during a watch

        bool launch = LaunchMode;
        bool auto = launch || _auto.IsChecked == true;   // launch mode always watches from t=0

        string outPath = _output.Text.Trim();
        if (outPath.Length == 0) { Append("Choose an output path first."); return; }

        int maxWaitSec = 30;
        if (auto && (!int.TryParse(_maxWait.Text.Trim(), out maxWaitSec) || maxWaitSec < 1 || maxWaitSec > 600))
        {
            Append("Enter a max wait between 1 and 600 seconds.");
            return;
        }

        // mode-specific inputs
        string target = "", args = "";
        bool sandbox = false;
        int pid = 0;
        string label;
        if (launch)
        {
            target = _targetPath.Text.Trim();
            if (target.Length == 0 || !File.Exists(target)) { Append("Choose a target executable that exists."); return; }
            args = _args.Text.Trim();
            sandbox = _sandbox.IsChecked == true;
            label = Path.GetFileName(target);
        }
        else
        {
            if (_process.SelectedItem is not ProcItem proc) { Append("Select a target process first."); return; }
            pid = proc.Pid;
            label = $"{proc.Name} (pid {proc.Pid})";
        }

        _running = true;
        SetInputsEnabled(false);
        _open.IsEnabled = false;
        _openSnap.IsEnabled = false;
        _log.Clear();
        Append($"{(launch ? "Launching + watching" : auto ? "Watching" : "Dumping")} {label}…");

        bool suspend = _suspend.IsChecked == true;
        ulong preferred = _preferredImageBase;
        var progress = new Progress<string>(Append);
        var report = ((IProgress<string>)progress).Report;

        // Any watch (launch or auto) can be cancelled via the Dump→Stop button.
        _cts = (launch || auto) ? new CancellationTokenSource() : null;
        if (_cts is not null) { _dump.Content = "Stop"; _dump.IsEnabled = true; } else _dump.IsEnabled = false;

        var optAuto = new AutoTimingOptions(MaxWaitMs: maxWaitSec * 1000);
        Func<bool>? cancelled = _cts is { } cts ? () => cts.IsCancellationRequested : null;
        string? snapReq = _snapshot.IsChecked == true ? Path.ChangeExtension(outPath, ".dssnap") : null;

        NonInvasiveDumpResult result;
        try
        {
            result = await Task.Run(() => launch
                ? NonInvasiveDumper.LaunchAndDump(new LaunchWatchOptions(target, args, null, sandbox), outPath, suspend, preferred, optAuto, report, cancelled, snapReq)
                : auto
                    ? NonInvasiveDumper.DumpWhenSettled(pid, outPath, suspend, preferred, optAuto, report, cancelled, snapReq)
                    : NonInvasiveDumper.Dump(pid, outPath, suspend, preferred, report, snapReq));
        }
        catch (Exception ex)
        {
            Append("ERROR: " + ex.Message);
            FinishRun();
            return;
        }

        Append("");
        if (result.Ok)
        {
            Append($"SUCCESS — dumped {result.Bitness}-bit image, {result.SizeOfImage:X} bytes from base {result.ImageBase:X}.");
            Append($"Imports: {result.ImportsResolved} resolved, {result.ImportsUnresolved} unresolved.");
            if (result.HottestExecEntropy >= 7.0)
                Append("Note: the largest code section is still high-entropy — the target may not have finished " +
                       "decrypting (or it is virtualized). Increase the max wait and retry, or feed this dump to Devirt.");
            Append($"Wrote: {result.OutputPath}");
            if (result.RawOutputPath is { } rp)
                Append($"The in-memory PE header was reconstructed (protector anti-dump). A faithful raw copy was also " +
                       $"written: {rp} — if the rebuilt PE looks off, open that as a raw/flat image at base {result.ImageBase:X}.");
            _open.IsEnabled = true;
            if (result.SnapshotOutputPath is { } snap)
            {
                _snapPath = snap;
                Append($"Full process snapshot: {snap} — open it to follow indirect jumps into the protector's private VM regions.");
                _openSnap.IsEnabled = true;
            }
        }
        else
        {
            Append("FAILED: " + (result.Error ?? "unknown error"));
            if (result.RawOutputPath is { } rp)
                Append($"A raw decrypted memory image was still captured: {rp} — open it as a raw/flat image at the image base to inspect the decrypted bytes.");
        }
        FinishRun();
    }

    private void FinishRun()
    {
        _running = false;
        _cts?.Dispose();
        _cts = null;
        SetInputsEnabled(true);
        _dump.Content = LaunchMode ? "Launch & Dump" : "Dump";
        _dump.IsEnabled = true;
    }

    private void SetInputsEnabled(bool on)
    {
        _modeAttach.IsEnabled = on;
        _modeLaunch.IsEnabled = on;
        _process.IsEnabled = on;
        _targetPath.IsEnabled = on;
        _args.IsEnabled = on;
        _sandbox.IsEnabled = on;
        _suspend.IsEnabled = on;
        _snapshot.IsEnabled = on;
        _auto.IsEnabled = on && !LaunchMode;
        _maxWait.IsEnabled = on && (LaunchMode || _auto.IsChecked == true);
        _output.IsEnabled = on;
        // _dump is managed by OnDump/FinishRun (it doubles as Stop during a watch).
    }

    private void Append(string line)
    {
        _log.AppendText(line + "\n");
        _log.ScrollToEnd();
    }

    private static TextBlock Label(string text) => new()
    {
        Text = text, Foreground = Sub, Margin = new Thickness(0, 0, 0, 4),
    };

    private static string SafeDir(string path)
    {
        try { return Path.GetDirectoryName(Path.GetFullPath(path)) ?? ""; } catch { return ""; }
    }
}

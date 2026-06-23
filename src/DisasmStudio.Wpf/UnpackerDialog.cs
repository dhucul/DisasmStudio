using System.Globalization;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using DisasmStudio.Core.Devirt;
using DisasmStudio.Core.Formats;
using DisasmStudio.Core.Unpacking;
using DisasmStudio.Debug.Unpacking;

namespace DisasmStudio.Wpf;

/// <summary>
/// The generic-unpacker dialog: choose an OEP strategy, sandbox toggle and output path, then run an
/// <see cref="UnpackSession"/> that drives the debugger to OEP, dumps, rebuilds imports and writes a clean
/// PE. Progress streams live into a log; on success the user can reopen the rebuilt file. Built in code to
/// match the project's other dialogs; inherits the app's themed control styles.
/// </summary>
internal sealed class UnpackerDialog : Window
{
    private static readonly Brush Bg = new SolidColorBrush(Color.FromRgb(0x16, 0x1B, 0x22));
    private static readonly Brush Fg = new SolidColorBrush(Color.FromRgb(0xE6, 0xEA, 0xF0));
    private static readonly Brush Sub = new SolidColorBrush(Color.FromRgb(0xAE, 0xB7, 0xC4));
    private static readonly Brush Warn = new SolidColorBrush(Color.FromRgb(0xF0, 0xB6, 0x4D));
    private static readonly FontFamily Mono = new("Cascadia Mono, Consolas");

    private readonly string _target;
    private readonly int _bitness;
    private readonly ulong _imageBase;
    private readonly PackerVerdict _verdict;
    private readonly ComboBox _strategy;
    private readonly TextBox _manualOep;
    private readonly CheckBox _sandbox;
    private readonly CheckBox _apiHooks;
    private readonly CheckBox _rdtsc;
    private readonly TextBox _output;
    private readonly TextBox _log;
    private readonly Button _start;
    private readonly Button _open;
    private readonly Button _devirt;
    private readonly Button _devirtProbe;
    private UnpackResult? _lastResult;
    private bool _running;

    /// <summary>Set to the rebuilt file's path when the user chooses to reopen it; null otherwise.</summary>
    public string? OpenPath { get; private set; }

    public UnpackerDialog(Window owner, string targetPath, int bitness, ulong imageBase, PackerVerdict verdict)
    {
        _target = targetPath;
        _bitness = bitness;
        _imageBase = imageBase;
        _verdict = verdict;

        Owner = owner;
        Title = "Unpack";
        Width = 640;
        Height = 560;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        Background = Bg;
        Foreground = Fg;

        var root = new Grid { Margin = new Thickness(16) };
        root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });   // verdict
        root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });   // options
        root.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) }); // log
        root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });   // buttons

        // --- verdict banner ---
        bool virt = verdict.Kind == PackerKind.Virtualizer;
        var verdictText = new TextBlock
        {
            Text = $"{Path.GetFileName(targetPath)}  ·  {(bitness == 64 ? "x64" : "x86")}\n{verdict.Notes}",
            Foreground = virt ? Warn : Sub,
            TextWrapping = TextWrapping.Wrap,
            Margin = new Thickness(0, 0, 0, 12),
        };
        Grid.SetRow(verdictText, 0);
        root.Children.Add(verdictText);

        // --- options ---
        var opt = new StackPanel();
        Grid.SetRow(opt, 1);

        opt.Children.Add(Label("OEP detection strategy"));
        _strategy = new ComboBox { Margin = new Thickness(0, 0, 0, 8) };
        _strategy.Items.Add("Auto (ESP-trick → section guard)");
        _strategy.Items.Add("ESP-trick (x86 compressors)");
        _strategy.Items.Add("Section guard");
        _strategy.Items.Add("Manual OEP");
        _strategy.Items.Add("Run free — no trace (VM protectors); dump on settle/fault");
        _strategy.Items.Add("Trace VM loop/handlers (single-step diagnostic)");
        _strategy.SelectedIndex = 0;
        opt.Children.Add(_strategy);

        opt.Children.Add(Label("Manual OEP address (hex) — used only with the Manual strategy"));
        _manualOep = new TextBox { FontFamily = Mono, IsEnabled = false, Margin = new Thickness(0, 0, 0, 8) };
        opt.Children.Add(_manualOep);
        _strategy.SelectionChanged += (_, _) => _manualOep.IsEnabled = _strategy.SelectedIndex == 3;

        _sandbox = new CheckBox
        {
            Content = "Sandbox: job object (blocks child processes, kill-on-close)",
            Foreground = Fg,
            IsChecked = true,
            Margin = new Thickness(0, 0, 0, 2),
        };
        opt.Children.Add(_sandbox);
        _apiHooks = new CheckBox
        {
            Content = "Anti-debug API hooks (ntdll/user32 — uncheck to test ntdll-prologue hook detection)",
            Foreground = Fg,
            IsChecked = true,
            Margin = new Thickness(0, 0, 0, 2),
        };
        opt.Children.Add(_apiHooks);
        _rdtsc = new CheckBox
        {
            Content = "Patch rdtsc in target (uncheck to leave the target unmodified — test self-CRC detection)",
            Foreground = Fg,
            IsChecked = true,
            Margin = new Thickness(0, 0, 0, 2),
        };
        opt.Children.Add(_rdtsc);
        opt.Children.Add(new TextBlock
        {
            Text = "Note: this is process-level containment only — it does NOT block network or filesystem access. " +
                   "Run truly untrusted samples in a disposable VM.",
            Foreground = Warn, FontSize = 11, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(20, 0, 0, 10),
        });

        opt.Children.Add(Label("Output file"));
        var outRow = new DockPanel { Margin = new Thickness(0, 0, 0, 6) };
        var browse = new Button { Content = "Browse…", MinWidth = 76, Margin = new Thickness(8, 0, 0, 0) };
        browse.Click += OnBrowse;
        DockPanel.SetDock(browse, Dock.Right);
        _output = new TextBox { FontFamily = Mono, Text = DefaultOutputPath(targetPath) };
        outRow.Children.Add(browse);
        outRow.Children.Add(_output);
        opt.Children.Add(outRow);
        root.Children.Add(opt);

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
        _start = new Button { Content = "Unpack", IsDefault = true, MinWidth = 90, Margin = new Thickness(0, 0, 8, 0) };
        _start.Click += OnStart;
        _open = new Button { Content = "Open unpacked", MinWidth = 110, Margin = new Thickness(0, 0, 8, 0), IsEnabled = false };
        _open.Click += (_, _) => { OpenPath = _output.Text.Trim(); DialogResult = true; };
        _devirt = new Button { Content = "Devirt snapshot", MinWidth = 112, Margin = new Thickness(0, 0, 8, 0), IsEnabled = false };
        _devirt.Click += OnDevirtSnapshot;
        _devirtProbe = new Button { Content = "Devirt best probe", MinWidth = 120, Margin = new Thickness(0, 0, 8, 0), IsEnabled = false };
        _devirtProbe.Click += OnDevirtBestProbe;
        var close = new Button { Content = "Close", IsCancel = true, MinWidth = 80 };
        buttons.Children.Add(_start);
        buttons.Children.Add(_open);
        buttons.Children.Add(_devirt);
        buttons.Children.Add(_devirtProbe);
        buttons.Children.Add(close);
        root.Children.Add(buttons);

        Content = root;

        if (virt)
            Append("WARNING: a code-virtualizing protector was detected. Generic unpacking cannot recover the " +
                   "original code; any dump will be unreliable. Proceeding will likely fail or produce a partial image.");
    }

    private void OnBrowse(object sender, RoutedEventArgs e)
    {
        var dlg = new Microsoft.Win32.SaveFileDialog
        {
            Title = "Save unpacked file",
            Filter = "Executable (*.exe)|*.exe|All files (*.*)|*.*",
            FileName = Path.GetFileName(_output.Text),
            InitialDirectory = SafeDir(_output.Text),
        };
        if (dlg.ShowDialog(this) == true) _output.Text = dlg.FileName;
    }

    private async void OnStart(object sender, RoutedEventArgs e)
    {
        if (_running) return;
        string outPath = _output.Text.Trim();
        if (outPath.Length == 0) { Append("Choose an output path first."); return; }

        ulong? manualOep = null;
        var method = _strategy.SelectedIndex switch
        {
            1 => OepMethod.EspTrick,
            2 => OepMethod.SectionGuard,
            3 => OepMethod.Manual,
            4 => OepMethod.RunFree,
            5 => OepMethod.TraceVm,
            _ => OepMethod.Auto,
        };
        if (method == OepMethod.Manual)
        {
            manualOep = ParseHex(_manualOep.Text);
            if (manualOep is null) { Append("Enter a valid hex OEP address for the Manual strategy."); return; }
        }

        _running = true;
        SetInputsEnabled(false);
        _log.Clear();
        _lastResult = null;
        _devirt.IsEnabled = false;
        _devirtProbe.IsEnabled = false;

        var options = new UnpackOptions(method, manualOep, _sandbox.IsChecked == true, outPath, _imageBase,
            UseApiHooks: _apiHooks.IsChecked == true, InterceptRdtsc: _rdtsc.IsChecked == true);
        var session = new UnpackSession(_target, options);
        session.Progress += line => Dispatcher.BeginInvoke(() => Append(line));

        UnpackResult result;
        try { result = await session.RunAsync(); }
        catch (Exception ex) { Append("ERROR: " + ex.Message); _running = false; SetInputsEnabled(true); return; }

        if (result.Ok)
        {
            Append("");
            if (result.Method == OepMethod.TraceVm)
            {
                Append("TRACE COMPLETE - VM loop/handler trace finished.");
                if (!string.IsNullOrWhiteSpace(result.TraceReportPath))
                    Append($"Report: {result.TraceReportPath}");
            }
            else
            {
            Append($"SUCCESS — OEP {result.Oep:X} via {result.Method}" +
                   $"{(result.OepConfirmed ? " (prologue confirmed)" : " (prologue unconfirmed)")}.");
            Append($"Imports: {result.ImportsResolved} resolved, {result.ImportsUnresolved} unresolved.");
            Append($"Wrote: {result.OutputPath}");
            _open.IsEnabled = true;
            }
            _lastResult = result;
            EnableProbeButton(result);
        }
        else
        {
            Append("");
            Append("FAILED: " + (result.Error ?? "unknown error"));
            if (_verdict.Kind == PackerKind.Virtualizer)
            {
                Append("");
                Append("This file was identified as a code-virtualizing protector (VMProtect/Themida-class). The OEP " +
                       "strategies here are built for compressors that decompress the original code and jump to it — a " +
                       "moment that does not exist when the code is virtualized to bytecode.");
                Append("If the goal is only to strip an outer compression layer (e.g. VMProtect's \"Pack the output " +
                       "file\"), try the Manual strategy with the post-stub OEP, or extract any embedded PE from the " +
                       "Resources tab. Even then, the recovered code stays virtualized.");
            }
            _lastResult = result;
            if (!string.IsNullOrWhiteSpace(result.FaultDumpPath) && File.Exists(result.FaultDumpPath))
            {
                Append($"Devirtualizer: snapshot available at {result.FaultDumpPath}. Use 'Devirt snapshot' to analyze it.");
                _devirt.IsEnabled = true;
            }
            EnableProbeButton(result);
            SetInputsEnabled(true);   // let the user adjust strategy and retry
        }
        _running = false;
        _start.IsEnabled = !result.Ok;
    }

    private void EnableProbeButton(UnpackResult result)
    {
        var probes = ExistingProbes(result).ToList();
        if (probes.Count == 0)
        {
            _devirtProbe.IsEnabled = false;
            if (result.Method == OepMethod.RunFree)
            {
                string dirs = string.Join(", ", ProbeSearchDirs(result));
                Append("Run-free probes: none found. 'Devirt best probe' needs files matching " +
                       $"'{ProbeFilePattern()}' in {dirs}. Run Unpack with the Run-free strategy again to generate them.");
            }
            return;
        }

        var best = BestProbe(probes);
        Append($"Run-free probes: {probes.Count} captured. Best candidate: {best.Label} " +
               $"{best.HottestExecSection ?? "exec"} entropy {best.HottestExecEntropy:F2}, " +
               $"nonzero {best.HottestExecNonZeroPercent:F1}% -> {best.Path}");
        if (best.HottestExecEntropy >= 7.0)
            Append("Run-free probes: all candidates are still high-entropy; Devirt best probe is available for inspection, but recovery is unlikely.");
        _devirtProbe.IsEnabled = true;
    }

    private IEnumerable<RunFreeProbeSnapshot> ExistingProbes(UnpackResult result)
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        if (result.ProbeSnapshots is not null)
        {
            foreach (var probe in result.ProbeSnapshots)
            {
                string path = SafeFullPath(probe.Path);
                if (File.Exists(path) && seen.Add(path))
                    yield return probe with { Path = path };
            }
        }

        ulong imageBase = ProbeImageBase(result);
        foreach (var path in DiscoverProbeFiles(result))
        {
            if (!seen.Add(path)) continue;
            var probe = ScoreProbe(path, imageBase);
            if (probe is not null) yield return probe;
        }
    }

    private IEnumerable<string> DiscoverProbeFiles(UnpackResult result)
    {
        string stemPattern = ProbeFilePattern();
        foreach (string dir in ProbeSearchDirs(result))
        {
            foreach (string pattern in new[] { stemPattern, "*_runfree_*.bin" }.Distinct(StringComparer.OrdinalIgnoreCase))
            {
                IEnumerable<string> files;
                try { files = Directory.EnumerateFiles(dir, pattern).OrderBy(p => p).ToArray(); }
                catch { continue; }
                foreach (string file in files)
                    yield return SafeFullPath(file);
            }
        }
    }

    private IEnumerable<string> ProbeSearchDirs(UnpackResult result)
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (string? path in new[] { _output.Text.Trim(), result.OutputPath, result.FaultDumpPath, _target })
        {
            if (string.IsNullOrWhiteSpace(path)) continue;
            string dir;
            try { dir = Path.GetDirectoryName(Path.GetFullPath(path)) ?? ""; }
            catch { continue; }
            if (dir.Length > 0 && Directory.Exists(dir) && seen.Add(dir))
                yield return dir;
        }
    }

    private string ProbeFilePattern()
    {
        string stem = Path.GetFileNameWithoutExtension(_target);
        return string.IsNullOrWhiteSpace(stem) ? "*_runfree_*.bin" : $"{stem}_runfree_*.bin";
    }

    private static RunFreeProbeSnapshot? ScoreProbe(string path, ulong imageBase)
    {
        try
        {
            var image = PeMemoryImage.Load(path, imageBase);
            var hot = image.Sections
                .Where(s => s.IsExecutable && s.FileSize > 0)
                .Select(s =>
                {
                    int len = Math.Min(s.FileSize, 1 << 20);
                    var bytes = image.ReadBytesAtVa(s.StartVa, len);
                    double entropy = bytes.Length > 0 ? Entropy.Shannon(bytes) : 0;
                    double nonZero = bytes.Length > 0 ? 100.0 * bytes.Count(b => b != 0) / bytes.Length : 0;
                    return (s.Name, Entropy: entropy, NonZero: nonZero);
                })
                .OrderByDescending(s => s.Entropy)
                .FirstOrDefault();
            if (hot.Name is null) return null;
            return new RunFreeProbeSnapshot(ProbeLabelFromPath(path), path, hot.Name, hot.Entropy, hot.NonZero);
        }
        catch
        {
            return null;
        }
    }

    private static RunFreeProbeSnapshot BestProbe(IEnumerable<RunFreeProbeSnapshot> probes) =>
        probes.OrderBy(p => p.HottestExecEntropy).ThenByDescending(p => p.HottestExecNonZeroPercent).First();

    private async void OnDevirtBestProbe(object sender, RoutedEventArgs e)
    {
        if (_lastResult is null) return;
        var probes = ExistingProbes(_lastResult).ToList();
        if (probes.Count == 0) { _devirtProbe.IsEnabled = false; return; }
        var probe = BestProbe(probes);
        await DevirtImagePath(probe.Path, ProbeImageBase(_lastResult),
            $"Devirtualizer: loading best run-free probe {probe.Label}...");
    }

    private async void OnDevirtSnapshot(object sender, RoutedEventArgs e)
    {
        if (_lastResult?.FaultDumpPath is not { Length: > 0 } path || !File.Exists(path)) return;
        await DevirtImagePath(path, _lastResult.FaultDumpBase, "Devirtualizer: loading fault snapshot...");
    }

    private async Task DevirtImagePath(string path, ulong imageBase, string startMessage)
    {
        _devirt.IsEnabled = false;
        _devirtProbe.IsEnabled = false;
        Append("");
        Append(startMessage);
        try
        {
            var image = PeMemoryImage.Load(path, imageBase);
            var result = await Task.Run(() => DevirtEngine.Run(image));
            Append($"Devirtualizer: {result.Status} - {result.Message}");
            new DevirtReportDialog(this, image, result).ShowDialog();
        }
        catch (Exception ex)
        {
            Append("Devirtualizer failed: " + ex.Message);
        }
        finally
        {
            if (_lastResult?.FaultDumpPath is { Length: > 0 } p && File.Exists(p))
                _devirt.IsEnabled = true;
            if (_lastResult is not null && ExistingProbes(_lastResult).Any())
                _devirtProbe.IsEnabled = true;
        }
    }

    private void SetInputsEnabled(bool on)
    {
        _strategy.IsEnabled = on;
        _manualOep.IsEnabled = on && _strategy.SelectedIndex == 3;
        _sandbox.IsEnabled = on;
        _output.IsEnabled = on;
        _start.IsEnabled = on;
    }

    private void Append(string line)
    {
        _log.AppendText(line + "\n");
        _log.ScrollToEnd();
    }

    private static string DefaultOutputPath(string target)
    {
        string dir = Path.GetDirectoryName(target) ?? ".";
        string name = Path.GetFileNameWithoutExtension(target);
        string ext = Path.GetExtension(target);
        return Path.Combine(dir, $"{name}_unpacked{ext}");
    }

    private static string SafeDir(string path)
    {
        try { return Path.GetDirectoryName(Path.GetFullPath(path)) ?? ""; } catch { return ""; }
    }

    private static TextBlock Label(string text) => new()
    {
        Text = text, Foreground = Sub, Margin = new Thickness(0, 0, 0, 4),
    };

    private static ulong? ParseHex(string? s)
    {
        if (string.IsNullOrWhiteSpace(s)) return null;
        s = s.Trim();
        if (s.StartsWith("0x", StringComparison.OrdinalIgnoreCase)) s = s[2..];
        return ulong.TryParse(s, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var v) ? v : null;
    }

    private ulong ProbeImageBase(UnpackResult result) => result.FaultDumpBase != 0 ? result.FaultDumpBase : _imageBase;

    private static string ProbeLabelFromPath(string path)
    {
        string stem = Path.GetFileNameWithoutExtension(path);
        int idx = stem.IndexOf("_runfree_", StringComparison.OrdinalIgnoreCase);
        return idx >= 0 ? stem[(idx + "_runfree_".Length)..] : stem;
    }

    private static string SafeFullPath(string path)
    {
        try { return Path.GetFullPath(path); }
        catch { return path; }
    }
}

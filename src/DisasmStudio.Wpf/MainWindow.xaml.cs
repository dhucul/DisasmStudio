using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Input;
using DisasmStudio.Core.Analysis;
using DisasmStudio.Core.Formats;
using DisasmStudio.Wpf.Services;
using DisasmStudio.Wpf.ViewModels;
using Microsoft.Win32;

namespace DisasmStudio.Wpf;

public partial class MainWindow : Window
{
    private const int MaxStringRows = 20_000;

    private readonly NavigationService _nav = new();
    private IBinaryImage? _image;
    private AnalysisResult? _result;
    private CancellationTokenSource? _cts;
    private ulong[] _funcStarts = [];
    private string? _projectPath;

    private ObservableCollection<FunctionItem> _functions = [];
    private ObservableCollection<StringItem> _strings = [];
    private ObservableCollection<ExportItem> _exports = [];
    private ICollectionView? _functionsView;
    private ICollectionView? _stringsView;
    private ICollectionView? _exportsView;

    public MainWindow()
    {
        InitializeComponent();
        WireControls();
        _nav.Navigated += OnNavigated;

        // Allow "DisasmStudio <file>" (CLI / Open-with) to load a target on startup.
        Loaded += async (_, _) =>
        {
            var args = Environment.GetCommandLineArgs();
            if (args.Length > 1 && File.Exists(args[1])) await LoadFile(args[1]);
        };
    }

    private void WireControls()
    {
        Linear.NavigateRequested += va => _nav.Navigate(va);
        Linear.GoToRequested += GoToDialog;
        Linear.SelectionChanged += OnAddressFocused;
        Linear.ShowXrefsRequested += va => { SideTabs.SelectedIndex = 0; ShowXrefs(va); };
        Linear.OpenInGraphRequested += va => { OpenGraph(va); CenterTabs.SelectedIndex = 1; };
        Graph.BlockSelected += va => _nav.Navigate(va);
    }

    // ---- open + analyze ----
    private async void OnOpen(object sender, RoutedEventArgs e)
    {
        var dlg = new OpenFileDialog
        {
            Title = "Open binary",
            Filter = "Binaries|*.exe;*.dll;*.sys;*.so;*.elf;*.o;*.bin;*.dat|All files|*.*",
        };
        if (dlg.ShowDialog(this) != true) return;
        await LoadFile(dlg.FileName);
    }

    private async void OnOpenProject(object sender, RoutedEventArgs e)
    {
        var dlg = new OpenFileDialog { Title = "Open project", Filter = "DisasmStudio project|*.dsproj|All files|*.*" };
        if (dlg.ShowDialog(this) != true) return;

        ProjectFile proj;
        try { proj = ProjectFile.Load(dlg.FileName); }
        catch (Exception ex) { MessageBox.Show(this, ex.Message, "Open project failed", MessageBoxButton.OK, MessageBoxImage.Warning); return; }

        IBinaryImage image;
        try
        {
            image = proj.Format == "Raw"
                ? RawImage.Load(proj.BinaryPath, proj.RawBaseVa, proj.RawBitness)
                : BinaryLoader.Load(proj.BinaryPath);
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, $"Couldn't load the binary referenced by this project:\n{proj.BinaryPath}\n\n{ex.Message}",
                "Open project failed", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        _projectPath = dlg.FileName;
        await StartAnalysis(image, proj.CurrentVa != 0 ? proj.CurrentVa : null, proj.CenterTab);
        Title = $"DisasmStudio — {Path.GetFileNameWithoutExtension(_projectPath)} ({Path.GetFileName(image.FilePath)})";
    }

    private void OnSaveProject(object sender, RoutedEventArgs e)
    {
        if (_image is null)
        {
            MessageBox.Show(this, "Open a binary first.", "Save project", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        string? path = _projectPath;
        if (path is null)
        {
            var dlg = new SaveFileDialog
            {
                Title = "Save project",
                Filter = "DisasmStudio project|*.dsproj",
                FileName = Path.GetFileNameWithoutExtension(_image.FilePath) + ".dsproj",
            };
            if (dlg.ShowDialog(this) != true) return;
            path = dlg.FileName;
        }

        var proj = new ProjectFile
        {
            BinaryPath = _image.FilePath,
            Format = _image.FormatName,
            RawBaseVa = _image.Format == BinaryFormat.Raw ? _image.ImageBase : 0,
            RawBitness = _image.Format == BinaryFormat.Raw ? _image.Bitness : 0,
            CurrentVa = _nav.Current ?? _image.EntryVa,
            CenterTab = CenterTabs.SelectedIndex,
        };
        try { proj.Save(path); }
        catch (Exception ex) { MessageBox.Show(this, ex.Message, "Save project failed", MessageBoxButton.OK, MessageBoxImage.Warning); return; }

        _projectPath = path;
        Title = $"DisasmStudio — {Path.GetFileNameWithoutExtension(_projectPath)} ({Path.GetFileName(_image.FilePath)})";
        StatusText.Text = $"Saved project to {path}";
    }

    private async Task LoadFile(string path)
    {
        _projectPath = null; // opening a binary directly starts an unsaved session
        IBinaryImage image;
        try
        {
            var fmt = BinaryLoader.Detect(path);
            if (fmt == BinaryFormat.Unknown)
            {
                var opt = Dialogs.AskRawOptions(this);
                if (opt is null) return;
                image = RawImage.Load(path, opt.Value.BaseVa, opt.Value.Bitness);
            }
            else image = BinaryLoader.Load(path);
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, ex.Message, "Open failed", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }
        await StartAnalysis(image);
    }

    private async Task StartAnalysis(IBinaryImage image, ulong? initialVa = null, int initialTab = 0)
    {
        _cts?.Cancel();
        _cts = new CancellationTokenSource();
        var token = _cts.Token;

        _image = image;
        _result = null;
        _nav.Reset();
        ClearLists();
        Title = $"DisasmStudio — {Path.GetFileName(image.FilePath)}";
        FileInfo.Text = $"{Path.GetFileName(image.FilePath)}  ·  {image.FormatName}  ·  {image.ArchName}  ·  base {image.ImageBase:X}";

        Progress.Visibility = Visibility.Visible;
        Progress.IsIndeterminate = true;
        StatusText.Text = "Analyzing…";
        var progress = new Progress<string>(s => StatusText.Text = s);

        try
        {
            var result = await Task.Run(() => AnalysisEngine.Analyze(image, progress, token), token);
            if (token.IsCancellationRequested) return;

            _result = result;
            PopulateLists(result);
            Linear.SetResult(result);
            Hex.SetImage(image);
            _funcStarts = result.Functions.Select(f => f.Va).ToArray();

            ulong target = initialVa ?? (image.EntryVa != 0 ? image.EntryVa
                : result.Functions.Count > 0 ? result.Functions[0].Va : image.MinVa);
            if (initialTab is >= 0 and <= 2) CenterTabs.SelectedIndex = initialTab;
            _nav.Navigate(target);
        }
        catch (OperationCanceledException) { }
        catch (Exception ex)
        {
            MessageBox.Show(this, ex.Message, "Analysis failed", MessageBoxButton.OK, MessageBoxImage.Error);
        }
        finally
        {
            Progress.Visibility = Visibility.Collapsed;
            Progress.IsIndeterminate = false;
        }
    }

    private void PopulateLists(AnalysisResult result)
    {
        var funcRows = result.Functions.Select(f => new FunctionItem(f, result.Image.SectionAt(f.Va)?.Name ?? ""));
        var importRows = result.Image.Imports.Select(i =>
            new FunctionItem(i.IatVa, Demangler.Demangle(i.Name), result.Image.SectionAt(i.IatVa)?.Name ?? ""));
        _functions = new ObservableCollection<FunctionItem>(funcRows.Concat(importRows).OrderBy(x => x.Va));
        _functionsView = CollectionViewSource.GetDefaultView(_functions);
        _functionsView.Filter = FuncFilterPredicate;
        FuncList.ItemsSource = _functionsView;

        _strings = new ObservableCollection<StringItem>(result.Strings.Take(MaxStringRows).Select(s => new StringItem(s)));
        _stringsView = CollectionViewSource.GetDefaultView(_strings);
        _stringsView.Filter = StringFilterPredicate;
        StringList.ItemsSource = _stringsView;

        _exports = new ObservableCollection<ExportItem>(result.Image.Symbols
            .Where(s => s.Kind == NamedSymbolKind.Export)
            .OrderBy(s => s.Name, StringComparer.OrdinalIgnoreCase)
            .Select(s => new ExportItem(s)));
        _exportsView = CollectionViewSource.GetDefaultView(_exports);
        _exportsView.Filter = ExportFilterPredicate;
        ExportList.ItemsSource = _exportsView;

        ImportList.ItemsSource = result.Image.Imports.Select(i => new ImportItem(i)).ToList();
        SectionList.ItemsSource = result.Image.Sections.Select(s => new SectionItem(s)).ToList();
    }

    private void ClearLists()
    {
        FuncList.ItemsSource = null;
        StringList.ItemsSource = null;
        ExportList.ItemsSource = null;
        ImportList.ItemsSource = null;
        SectionList.ItemsSource = null;
        XrefList.ItemsSource = null;
        Graph.Clear();
    }

    // ---- navigation ----
    private void OnNavigated(ulong va)
    {
        AddrBox.Text = va.ToString("X");
        BackBtn.IsEnabled = _nav.CanGoBack;
        FwdBtn.IsEnabled = _nav.CanGoForward;
        if (_result is null || _image is null) return;

        Linear.GoToVa(va);          // raises SelectionChanged → xrefs/status update
        Hex.GoTo(va);
        if (CenterTabs.SelectedIndex == 1) OpenGraph(va);

        // Data targets read better in the hex view.
        if (!_image.IsExecutableVa(va) && CenterTabs.SelectedIndex == 0)
            CenterTabs.SelectedIndex = 2;
    }

    private void OnAddressFocused(ulong va)
    {
        if (_result is null) return;
        string? name = _result.NameFor(va);
        StatusText.Text = name is null ? $"{va:X}" : $"{va:X}   {name}";
        ShowXrefs(va);
    }

    private void ShowXrefs(ulong va)
    {
        if (_result is null) return;
        var list = _result.Xrefs.To(va).Select(x => new XrefItem(x)).ToList();
        XrefList.ItemsSource = list;
        string? name = _result.NameFor(va);
        XrefHeader.Text = $"{va:X}{(name is null ? "" : $"  {name}")} — {list.Count} xref(s)";
    }

    private void OpenGraph(ulong va)
    {
        var fn = FindFunction(va);
        if (fn is not null && _result is not null) Graph.SetFunction(_result, fn);
    }

    private Function? FindFunction(ulong va)
    {
        if (_result is null || _funcStarts.Length == 0) return null;
        int lo = 0, hi = _funcStarts.Length - 1, best = -1;
        while (lo <= hi)
        {
            int mid = (lo + hi) >> 1;
            if (_funcStarts[mid] <= va) { best = mid; lo = mid + 1; }
            else hi = mid - 1;
        }
        return best < 0 ? null : _result.FunctionByVa[_funcStarts[best]];
    }

    // ---- toolbar ----
    private void OnBack(object sender, RoutedEventArgs e) => _nav.Back();
    private void OnForward(object sender, RoutedEventArgs e) => _nav.Forward();
    private void OnGo(object sender, RoutedEventArgs e) => GoFromAddrBox();
    private void OnAddrKeyDown(object sender, KeyEventArgs e) { if (e.Key == Key.Enter) GoFromAddrBox(); }

    private void GoFromAddrBox()
    {
        string s = AddrBox.Text.Trim();
        if (s.StartsWith("0x", StringComparison.OrdinalIgnoreCase)) s = s[2..];
        if (ulong.TryParse(s, System.Globalization.NumberStyles.HexNumber, null, out var va)) _nav.Navigate(va);
    }

    private void GoToDialog()
    {
        if (Dialogs.AskAddress(this) is ulong va) _nav.Navigate(va);
    }

    // ---- list interactions ----
    private void OnFuncSelected(object sender, SelectionChangedEventArgs e)
    {
        if (FuncList.SelectedItem is FunctionItem fi) _nav.Navigate(fi.Va);
    }
    private void OnFuncActivate(object sender, MouseButtonEventArgs e)
    {
        if (FuncList.SelectedItem is not FunctionItem fi) return;
        if (fi.Function is null) { _nav.Navigate(fi.Va); return; }   // import row — no CFG, just go to it
        OpenGraph(fi.Va);
        CenterTabs.SelectedIndex = 1;
    }
    private void OnFuncFilter(object sender, TextChangedEventArgs e) => _functionsView?.Refresh();

    private bool FuncFilterPredicate(object o)
    {
        string f = FuncFilter.Text.Trim();
        if (f.Length == 0 || o is not FunctionItem fi) return true;
        return fi.Name.Contains(f, StringComparison.OrdinalIgnoreCase)
            || fi.Address.Contains(f, StringComparison.OrdinalIgnoreCase)
            || fi.Section.Contains(f, StringComparison.OrdinalIgnoreCase);
    }

    private void OnStringFilter(object sender, TextChangedEventArgs e) => _stringsView?.Refresh();
    private bool StringFilterPredicate(object o)
    {
        string f = StringFilter.Text.Trim();
        if (f.Length == 0 || o is not StringItem si) return true;
        return si.Text.Contains(f, StringComparison.OrdinalIgnoreCase);
    }
    private void OnStringActivate(object sender, MouseButtonEventArgs e)
    {
        if (StringList.SelectedItem is not StringItem si || _result is null) return;

        // Prefer jumping to the code that references the string (shown in the linear view), not the
        // raw bytes. Match references anywhere inside the string's bytes — some code points at a
        // suffix/middle of a merged literal rather than its first byte. List them all in the panel.
        ulong end = si.Va + (ulong)Math.Max(1, si.ByteLength);
        // 1) direct code reference anywhere inside the string's bytes.
        var refs = _result.Xrefs.ToRange(si.Va, end);
        // 2) else the string may be reached through a pointer-table slot (precomputed during
        //    analysis) — resolve the slot, then the code that loads it. O(1), no UI-thread scan.
        if (refs.Count == 0 && _result.StringPointerSlots.TryGetValue(si.Va, out var slot))
            refs = _result.Xrefs.To(slot).ToList();

        if (refs.Count > 0)
        {
            CenterTabs.SelectedIndex = 0;          // Linear
            _nav.Navigate(refs[0].From);
            // Populate the panel AFTER navigating — the nav chain repopulates Xrefs for the target,
            // so set the string's referencers last so they stay shown.
            SideTabs.SelectedIndex = 0;
            XrefList.ItemsSource = refs.Select(x => new XrefItem(x)).ToList();
            string preview = si.Text.Length > 40 ? si.Text[..40] + "…" : si.Text;
            XrefHeader.Text = $"{si.Va:X}  \"{preview}\" — {refs.Count} ref(s)";
        }
        else
        {
            CenterTabs.SelectedIndex = 2;          // genuinely unreferenced data — show in hex
            _nav.Navigate(si.Va);
        }
    }

    private void OnImportActivate(object sender, MouseButtonEventArgs e)
    {
        if (ImportList.SelectedItem is not ImportItem im || _result is null) return;

        // Jump to the code that calls this import, not the (useless) IAT slot in hex. List every
        // caller in the Xrefs panel. Fall back to hex only if nothing references it.
        var refs = _result.Xrefs.To(im.Va);
        if (refs.Count > 0)
        {
            CenterTabs.SelectedIndex = 0;          // Linear
            _nav.Navigate(refs[0].From);
            SideTabs.SelectedIndex = 0;            // Xrefs — set after navigating so it isn't overwritten
            XrefList.ItemsSource = refs.Select(x => new XrefItem(x)).ToList();
            XrefHeader.Text = $"{im.Va:X}  {im.Name} — {refs.Count} caller(s)";
        }
        else
        {
            CenterTabs.SelectedIndex = 2;
            _nav.Navigate(im.Va);
        }
    }
    private void OnSectionActivate(object sender, MouseButtonEventArgs e)
    {
        if (SectionList.SelectedItem is SectionItem se) _nav.Navigate(se.Va);
    }

    private void OnExportActivate(object sender, MouseButtonEventArgs e)
    {
        if (ExportList.SelectedItem is ExportItem ex) _nav.Navigate(ex.Va);
    }
    private void OnExportFilter(object sender, TextChangedEventArgs e) => _exportsView?.Refresh();
    private bool ExportFilterPredicate(object o)
    {
        string f = ExportFilter.Text.Trim();
        if (f.Length == 0 || o is not ExportItem ex) return true;
        return ex.Name.Contains(f, StringComparison.OrdinalIgnoreCase)
            || ex.Address.Contains(f, StringComparison.OrdinalIgnoreCase);
    }
    private void OnXrefActivate(object sender, MouseButtonEventArgs e)
    {
        if (XrefList.SelectedItem is XrefItem xi) _nav.Navigate(xi.Va);
    }
}

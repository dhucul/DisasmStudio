using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Globalization;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Input;
using System.Windows.Threading;
using DisasmStudio.Core.Analysis;
using DisasmStudio.Core.Disasm;
using DisasmStudio.Core.Export;
using DisasmStudio.Core.Formats;
using DisasmStudio.Debug;
using Iced.Intel;
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
    private readonly Stack<(ulong Start, ulong End, bool IsPatch)> _changeStack = new();   // mirrors the image undo stack

    private DebugSession? _dbg;
    private AnalysisResult? _savedResult;   // static result, restored when the debug session ends
    private bool _dbgViewLive;
    private bool _restartPending;           // relaunch the target once the current debuggee has exited
    private Function? _graphFn;              // function currently shown in the graph (avoids rebuild per step)

    private DispatcherTimer? _captureTimer;  // polls the capture stream for the log/comments/graph
    private int _captureShown;               // records already pushed to the panel
    private int _captureEdges = -1;          // last call-graph edge total (rebuild only on change)
    private string? _captureLogPath;         // last chosen capture-log path (Save-As default)
    private readonly HashSet<ulong> _captureCommented = [];   // entries already annotated inline

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
        Linear.OpenInDecompilerRequested += va => { OpenDecompiler(va); CenterTabs.SelectedIndex = 3; };
        Linear.PatchRequested += OnPatchInstruction;
        Hex.Edited += OnHexEdited;
        Graph.BlockSelected += va => _nav.Navigate(va);
        Decompiler.NavigateRequested += va => _nav.Navigate(va);
        Decompiler.SelectionChanged += OnAddressFocused;
        Linear.SaveAsmRequested += SaveFunctionAsm;
        Decompiler.SaveCRequested += SaveFunctionC;
        Linear.BreakpointToggleRequested += va => { _dbg?.ToggleBreakpoint(va); Linear.Refresh(); Debug.Refresh(); };
        Linear.RunToCursorRequested += va => _dbg?.RunToCursor(va);
        Debug.NavigateRequested += va => _nav.Navigate(va);
        PreviewKeyDown += OnWindowPreviewKeyDown;
    }

    private void OnWindowPreviewKeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Z && (Keyboard.Modifiers & ModifierKeys.Control) != 0
            && Keyboard.FocusedElement is not TextBox)   // let text fields keep their own undo
        {
            UndoLastPatch();
            e.Handled = true;
            return;
        }
        bool shift = (Keyboard.Modifiers & ModifierKeys.Shift) != 0;
        switch (e.Key)
        {
            case Key.F5: OnDebugRun(sender, e); e.Handled = true; break;
            case Key.F7: OnStepInto(sender, e); e.Handled = true; break;
            case Key.F8: OnStepOver(sender, e); e.Handled = true; break;
            case Key.F11 when shift: OnStepOut(sender, e); e.Handled = true; break;
        }
    }

    // ---- debugger ----
    private void OnDebugRun(object sender, RoutedEventArgs e)
    {
        if (_dbg is not null) { if (_dbg.IsStopped) _dbg.Go(); return; }   // continue only from a stop (else it skips the next stop)
        if (_result is null || _image is null) { MessageBox.Show(this, "Open a binary first.", "Debug", MessageBoxButton.OK, MessageBoxImage.Information); return; }
        if (_image.Format != BinaryFormat.Pe) { MessageBox.Show(this, "Only Windows PE targets can be debugged.", "Debug", MessageBoxButton.OK, MessageBoxImage.Information); return; }
        BeginDebug(d => d.Launch(_image.FilePath));
    }

    private void OnAttach(object sender, RoutedEventArgs e)
    {
        if (_dbg is not null) { MessageBox.Show(this, "A debug session is already active.", "Attach", MessageBoxButton.OK, MessageBoxImage.Information); return; }
        if (_result is null) { MessageBox.Show(this, "Open the target's binary first so the disassembly matches.", "Attach", MessageBoxButton.OK, MessageBoxImage.Information); return; }
        if (Dialogs.AskPid(this) is uint pid) BeginDebug(d => d.Attach(pid));
    }

    private void BeginDebug(Action<DebugSession> start)
    {
        _savedResult = _result;
        _dbgViewLive = false;
        _dbg = new DebugSession(Dispatcher, _result!);
        _dbg.Stopped += OnDbgStopped;
        _dbg.Running += () => { StatusText.Text = "Running…"; DbgRunBtn.IsEnabled = false; SetStepButtons(false); };   // no continue/step while running
        _dbg.Exited += OnDbgExited;
        _dbg.Output += m => StatusText.Text = m;
        Debug.SetSession(_dbg);
        DebugDock.Visibility = Visibility.Visible;
        Linear.IsBreakpointAt = va => _dbg?.HasBreakpoint(va) ?? false;
        StatusText.Text = "Starting debugger…";
        start(_dbg);
    }

    // Stepping is only valid from a stop; ignore it (button or key) while the debuggee is running, where it
    // would queue a resume that the loop consumes at the next stop — silently skipping that stop.
    private void OnStepInto(object sender, RoutedEventArgs e) { if (_dbg is { IsStopped: true }) _dbg.StepInto(); }
    private void OnStepOver(object sender, RoutedEventArgs e) { if (_dbg is { IsStopped: true }) _dbg.StepOver(); }
    private void OnStepOut(object sender, RoutedEventArgs e) { if (_dbg is { IsStopped: true }) _dbg.StepOut(); }
    private void SetStepButtons(bool on) { StepIntoBtn.IsEnabled = StepOverBtn.IsEnabled = StepOutBtn.IsEnabled = on; }
    private void OnDebugPause(object sender, RoutedEventArgs e) => _dbg?.Pause();
    private void OnDebugStop(object sender, RoutedEventArgs e) => _dbg?.Stop();

    private void OnDebugRestart(object sender, RoutedEventArgs e)
    {
        if (_dbg is null) return;
        _restartPending = true;   // OnDbgExited relaunches the target once this debuggee is gone
        StatusText.Text = "Restarting…";
        _dbg.Stop();
    }

    // ---- FunCap-style function capture ----

    private void OnCaptureAll(object sender, RoutedEventArgs e)
    {
        if (_dbg is null) return;
        // A capture is in progress: stop it (toggle). If it is already draining, ignore the extra click so we
        // don't issue a second Pause or start a new capture over the one being torn down.
        if (_dbg.Capture is { } c) { if (!c.Draining) StopCapture(); return; }
        StartCapture(0);   // all functions
    }

    private void OnCaptureFunc(object sender, RoutedEventArgs e)
    {
        if (_dbg is null || _nav.Current is not ulong va) return;
        // Stopping a capture is asynchronous (it drains while frozen), so don't start a second one over it.
        if (_dbg.Capture is not null) { StatusText.Text = "Stop the current capture first."; return; }
        var fn = FindFunction(va);
        if (fn is null) { StatusText.Text = "No function at the current address to capture."; return; }
        StartCapture(fn.Va);   // the function at the current address
    }

    private void StartCapture(ulong funcVa)
    {
        // Arming breakpoints writes the debuggee's code pages; that's only safe while it is frozen at a stop
        // (writing into a running process can corrupt it). Require a stop before starting a capture.
        if (_dbg is not { IsStopped: true }) { StatusText.Text = "Pause the debuggee before starting a capture."; return; }

        // Choose where the capture log is written (defaults to the last path, then ~/funcap.txt).
        string defaultPath = _captureLogPath ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "funcap.txt");
        var dlg = new SaveFileDialog
        {
            Title = "Save capture log",
            Filter = "Text log|*.txt|All files|*.*",
            FileName = Path.GetFileName(defaultPath),
            InitialDirectory = Path.GetDirectoryName(defaultPath),
            OverwritePrompt = false,   // the log is meant to be overwritten; the user already picked the file
        };
        if (dlg.ShowDialog(this) != true) return;   // cancelled — don't start a capture
        string log = _captureLogPath = dlg.FileName;

        // Read the capture-option checkboxes (settings — they hold state, they don't trigger anything).
        bool once = OnceCheck.IsChecked == true;
        bool argsOnly = RetCheck.IsChecked != true;
        bool annotate = DerefCheck.IsChecked == true;

        var cap = _dbg!.StartCapture(funcVa, log, once, argsOnly, annotate);
        if (cap is null) { StatusText.Text = "Capture needs the program stopped at least once first."; return; }

        _captureShown = 0; _captureEdges = -1; _captureCommented.Clear();
        Debug.ClearCapture(); Debug.SelectCaptureTab();
        CaptureBtn.Content = "⦿ Capturing…";
        _captureTimer ??= new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(300) };
        _captureTimer.Tick -= OnCaptureTick; _captureTimer.Tick += OnCaptureTick;
        _captureTimer.Start();
        string scope = funcVa == 0 ? "all functions" : cap.NameOf(funcVa);
        string freq = once ? "first call" : "every call";
        string args = argsOnly ? ", args only" : "";
        StatusText.Text = $"Capturing {scope} ({freq}{args}) → {log}";
        _dbg.Go();   // run so captures start flowing
    }

    private void StopCapture()
    {
        _captureTimer?.Stop();
        OnCaptureTick(null, EventArgs.Empty);   // final flush of any pending records
        _dbg?.StopCapture();
        CaptureBtn.Content = "⦿ Capture";
        StatusText.Text = "Capture stopped.";
    }

    private void OnCaptureTick(object? sender, EventArgs e)
    {
        var cap = _dbg?.Capture;
        if (cap is null) return;
        bool is32 = _dbg!.Engine.Is32;

        cap.FlushLog();   // periodically persist the buffered log so an abnormal exit loses little
        var newRecs = cap.SnapshotFrom(_captureShown);   // only the records added since last tick
        if (newRecs.Count > 0)
        {
            Debug.AppendCapture(newRecs, 0, is32);
            if (_result?.Comments is IDictionary<ulong, string> comments)
                foreach (var r in newRecs)
                    if (!r.IsReturn && _captureCommented.Add(r.CalleeVa))
                        comments[r.CalleeVa] = FunctionCapture.ArgComment(r, is32);
            _captureShown += newRecs.Count;
            Linear.Refresh();   // surface the new inline comments
        }

        var edges = cap.EdgesSnapshot();
        int total = edges.Values.Sum(s => s.Count);
        if (total != _captureEdges) { _captureEdges = total; Debug.RebuildCallGraph(edges, cap.NameOf); }
    }

    private void OnDbgStopped()
    {
        if (_dbg is null) return;
        if (!_dbgViewLive && _dbg.LiveResult is not null)
        {
            // switch the whole UI to the live (rebased) analysis + live decoder on the first stop
            _dbgViewLive = true;
            _result = _dbg.LiveResult;
            _funcStarts = _result.Functions.Select(f => f.Va).ToArray();
            PopulateLists(_result);
            Linear.SetResult(_result, _dbg.LiveDecoder);
            Hex.SetImage(_result.Image);
            Hex.WriteByteAt = (va, b) => _dbg?.Engine.WriteMemory(va, [b]) ?? false;   // editable live memory
            CaptureBtn.IsEnabled = true; CaptureFnBtn.IsEnabled = true; OnceCheck.IsEnabled = true; RetCheck.IsEnabled = true; DerefCheck.IsEnabled = true;
            RestartBtn.IsEnabled = true;
        }
        DbgRunBtn.Content = "▶ Continue"; DbgRunBtn.IsEnabled = true; SetStepButtons(true);   // Run doubles as Continue (F5) during a session
        Linear.SetCurrentIp(_dbg.CurrentIp);
        Linear.Refresh();
        Debug.Refresh();
        if (CenterTabs.SelectedIndex == 1) OpenGraph(_dbg.CurrentIp);   // graph follows RIP too
        string? name = _result?.NameFor(_dbg.CurrentIp);
        StatusText.Text = $"{_dbg.LastReason} @ {_dbg.CurrentIp:X}{(name is null ? "" : "   " + name)}";
    }

    private void OnDbgExited(int code)
    {
        _captureTimer?.Stop();
        OnCaptureTick(null, EventArgs.Empty);   // flush the last records to the panel
        _dbg?.AbortCapture();   // process is gone: drop capture state and close the log (no live removal needed)
        CaptureBtn.Content = "⦿ Capture"; CaptureBtn.IsEnabled = false; CaptureFnBtn.IsEnabled = false; OnceCheck.IsEnabled = false; RetCheck.IsEnabled = false; DerefCheck.IsEnabled = false;
        RestartBtn.IsEnabled = false; DbgRunBtn.Content = "▶ Run"; DbgRunBtn.IsEnabled = true; SetStepButtons(false);   // re-enable for a fresh Run
        Linear.SetCurrentIp(0);
        Linear.IsBreakpointAt = null;
        Hex.WriteByteAt = null;
        _dbg = null; _dbgViewLive = false;
        Graph.Clear(); _graphFn = null;
        Debug.SetSession(null);
        DebugDock.Visibility = Visibility.Collapsed;
        if (_savedResult is not null && _image is not null)
        {
            _result = _savedResult; _savedResult = null;
            _funcStarts = _result.Functions.Select(f => f.Va).ToArray();
            PopulateLists(_result);
            Linear.SetResult(_result);
            Hex.SetImage(_image);
        }
        StatusText.Text = $"Debuggee exited (code {code}).";

        if (_restartPending)
        {
            _restartPending = false;
            var img = _image;
            if (img is { Format: BinaryFormat.Pe }) Dispatcher.BeginInvoke(() => BeginDebug(d => d.Launch(img.FilePath)));
        }
    }

    // ---- patching ----
    private void OnPatchInstruction(ulong va)
    {
        if (_image is null) return;
        var dis = new Disassembler(_image);
        if (!dis.TryDecodeAt(va, out var ins) || ins.Length == 0) return;

        var orig = _image.ReadBytesAtVa(va, ins.Length);
        string curHex = string.Join(" ", orig.Select(b => b.ToString("x2")));
        // Pre-fill a direct branch/call as assemblable text so flipping jmp→jz is a one-word edit.
        string prefill = ins.Op0Kind is OpKind.NearBranch16 or OpKind.NearBranch32 or OpKind.NearBranch64
            ? $"{ins.Mnemonic.ToString().ToLowerInvariant()} 0x{ins.NearBranchTarget:X}"
            : "";
        var req = Dialogs.AskPatch(this, va, ins.ToString(), curHex, prefill);
        if (req is null) return;

        byte[] patch;
        if (req.Value.Nop) patch = Patcher.Nop(ins.Length);
        else
        {
            var asm = Patcher.Assemble(_image.Bitness, va, req.Value.Asm);
            patch = asm.Bytes ?? TryParseHexBytes(req.Value.Asm)!;
            if (patch is null)
            {
                MessageBox.Show(this, asm.Error, "Assemble failed", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }
        }

        // Cover enough whole instructions to hold the new bytes; pad the remainder with NOPs so the
        // following instruction stays aligned.
        int cover = 0;
        ulong p = va;
        while (cover < patch.Length && dis.TryDecodeAt(p, out var n) && n.Length > 0) { cover += n.Length; p += (ulong)n.Length; }
        var final = Patcher.PadNop(patch, cover);
        if (!_image.PatchVa(va, final))
        {
            MessageBox.Show(this, "That address is not file-backed.", "Patch", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }
        ulong end = va + (ulong)final.Length;
        _changeStack.Push((va, end, true));
        RepairIndex(va, end);          // local re-decode of just this region — no full re-sweep
        UpdatePatchButtons();
    }

    private void OnHexEdited(ulong va)
    {
        // Hex byte edits stay view-local (no linear re-index — typing must stay snappy on huge files);
        // tracked so undo stays in lock-step with the image's undo stack.
        _changeStack.Push((va, va + 1, false));
        UpdatePatchButtons();
    }

    /// <summary>Re-decode just the changed region and splice it into the linear index — the rest of the
    /// index (built once by the full analysis) is reused as-is, so a patch costs a region decode, not a sweep.</summary>
    private void RepairIndex(ulong changeStart, ulong changeEnd)
    {
        if (_result is null || _image is null) return;
        var idx = _result.Linear;
        long line = idx.IndexOf(changeStart);
        if (idx.VaAt(line) > changeStart && line > 0) line--;
        if (idx.IsDataAt(line)) { Linear.Refresh(); Hex.InvalidateView(); return; }   // data byte: no boundary change

        ulong from = idx.VaAt(line);
        var d = new Disassembler(_image);
        var starts = new List<ulong>();
        ulong cur = from;
        for (int guard = 0; guard < 200_000 && cur < _image.MaxVa; guard++)
        {
            if (cur >= changeEnd)                              // resynced with an existing code boundary?
            {
                long l2 = idx.IndexOf(cur);
                if (idx.VaAt(l2) == cur && !idx.IsDataAt(l2)) break;
            }
            if (!d.TryDecodeAt(cur, out var ins) || ins.Length == 0) break;
            starts.Add(cur);
            cur += (ulong)ins.Length;
        }
        _result.Linear = idx.CloneWithRegion(from, cur, starts);
        Linear.RefreshAfterPatch();
        Linear.GoToVa(changeStart);
        Hex.InvalidateView();
    }

    private void UpdatePatchButtons()
    {
        SavePatchedBtn.IsEnabled = _image?.IsDirty == true;
        UndoBtn.IsEnabled = _image?.CanUndo == true;
    }

    private void OnUndoPatch(object sender, RoutedEventArgs e) => UndoLastPatch();

    private void UndoLastPatch()
    {
        if (_image is null || !_image.CanUndo) return;
        _image.Undo();
        if (_changeStack.Count > 0)
        {
            var (start, end, isPatch) = _changeStack.Pop();
            if (isPatch) RepairIndex(start, end); else Hex.InvalidateView();
        }
        UpdatePatchButtons();
    }

    private void OnSavePatched(object sender, RoutedEventArgs e)
    {
        if (_image is null || !_image.IsDirty) return;
        string baseName = Path.GetFileNameWithoutExtension(_image.FilePath);
        string ext = Path.GetExtension(_image.FilePath);
        var dlg = new SaveFileDialog { FileName = $"{baseName}.patched{ext}", Filter = "All files|*.*" };
        if (dlg.ShowDialog(this) != true) return;

        // Offer to keep a pristine copy of the original before writing the patched file.
        var ask = MessageBox.Show(this,
            $"Back up the original file first?\n\n{_image.FilePath}",
            "Save patched binary", MessageBoxButton.YesNoCancel, MessageBoxImage.Question);
        if (ask == MessageBoxResult.Cancel) return;
        if (ask == MessageBoxResult.Yes && !MakeBackup()) return;

        try
        {
            _image.SavePatchedAs(dlg.FileName);
            StatusText.Text = $"Saved patched binary ({_image.PatchCount} byte(s)) to {dlg.FileName}";
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, ex.Message, "Save failed", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    /// <summary>Copy the original (unpatched) file to a .bak; returns false if it failed and the user
    /// chose not to continue.</summary>
    private bool MakeBackup()
    {
        try
        {
            string bak = _image!.FilePath + ".bak";
            if (File.Exists(bak)) bak = $"{_image.FilePath}.{DateTime.Now:yyyyMMdd-HHmmss}.bak";
            File.Copy(_image.FilePath, bak);
            StatusText.Text = $"Backed up original to {bak}";
            return true;
        }
        catch (Exception ex)
        {
            return MessageBox.Show(this, $"Backup failed:\n{ex.Message}\n\nSave the patched file anyway?",
                "Backup failed", MessageBoxButton.YesNo, MessageBoxImage.Warning) == MessageBoxResult.Yes;
        }
    }

    /// <summary>Parse free-form hex bytes ("90 90", "9090", "0x90,0x90"); null if not all hex.</summary>
    private static byte[]? TryParseHexBytes(string s)
    {
        var bytes = new List<byte>();
        foreach (var tok in s.Split([' ', '\t', '\n', '\r', ','], StringSplitOptions.RemoveEmptyEntries))
        {
            string h = tok.StartsWith("0x", StringComparison.OrdinalIgnoreCase) ? tok[2..] : tok;
            if (h.Length == 0 || h.Length % 2 != 0) return null;
            for (int i = 0; i < h.Length; i += 2)
            {
                if (!byte.TryParse(h.AsSpan(i, 2), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var b)) return null;
                bytes.Add(b);
            }
        }
        return bytes.Count > 0 ? bytes.ToArray() : null;
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

    // ---- export to .asm / .c ----
    private async void OnSaveAsm(object sender, RoutedEventArgs e)
    {
        if (_result is null || _image is null) { MessageBox.Show(this, "Open a binary first.", "Save ASM", MessageBoxButton.OK, MessageBoxImage.Information); return; }
        var dlg = new SaveFileDialog { Title = "Save disassembly", Filter = "Assembly listing|*.asm|Text|*.txt|All files|*.*",
            FileName = Path.GetFileNameWithoutExtension(_image.FilePath) + ".asm" };
        if (dlg.ShowDialog(this) != true) return;
        var r = _result;
        await RunExport(dlg.FileName, "disassembly", (w, p, ct) => SourceExporter.WriteAsm(w, r, p, ct));
    }

    private async void OnSaveC(object sender, RoutedEventArgs e)
    {
        if (_result is null || _image is null) { MessageBox.Show(this, "Open a binary first.", "Save C", MessageBoxButton.OK, MessageBoxImage.Information); return; }
        var dlg = new SaveFileDialog
        {
            Title = "Save C",
            Filter = "Pseudo-C, readable|*.c|Compilable C|*.c|Text|*.txt|All files|*.*",
            FileName = Path.GetFileNameWithoutExtension(_image.FilePath) + ".c",
        };
        if (dlg.ShowDialog(this) != true) return;
        var r = _result;
        bool comp = dlg.FilterIndex == 2;
        await RunExport(dlg.FileName, comp ? "compilable C" : "Pseudo-C",
            comp ? (w, p, ct) => SourceExporter.WriteCompilableC(w, r, p, ct)
                 : (w, p, ct) => SourceExporter.WriteC(w, r, p, ct));
    }

    /// <summary>Run a whole-program export on a background thread, streaming to disk with progress.</summary>
    private async Task RunExport(string path, string what, Action<TextWriter, IProgress<int>, CancellationToken> body)
    {
        Progress.Visibility = Visibility.Visible;
        Progress.IsIndeterminate = false;
        Progress.Value = 0;
        StatusText.Text = $"Exporting {what}…";
        var prog = new Progress<int>(v => Progress.Value = v);
        try
        {
            await Task.Run(() =>
            {
                using var sw = new StreamWriter(path);
                body(sw, prog, CancellationToken.None);
            });
            StatusText.Text = $"Saved {what} to {path}";
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, ex.Message, "Export failed", MessageBoxButton.OK, MessageBoxImage.Error);
            StatusText.Text = "Export failed.";
        }
        finally { Progress.Visibility = Visibility.Collapsed; Progress.Value = 0; }
    }

    private void SaveFunctionAsm(ulong va)
    {
        var fn = FindFunction(va);
        if (fn is null || _result is null) return;
        var dlg = new SaveFileDialog { Title = "Save function disassembly", Filter = "Assembly listing|*.asm|Text|*.txt|All files|*.*",
            FileName = SafeFileName(fn.Name) + ".asm" };
        if (dlg.ShowDialog(this) != true) return;
        try
        {
            using var sw = new StreamWriter(dlg.FileName);
            SourceExporter.WriteAsmFunction(sw, _result, fn);
            StatusText.Text = $"Saved {fn.Name} to {dlg.FileName}";
        }
        catch (Exception ex) { MessageBox.Show(this, ex.Message, "Export failed", MessageBoxButton.OK, MessageBoxImage.Error); }
    }

    private void SaveFunctionC(ulong va)
    {
        var fn = FindFunction(va);
        if (fn is null || _result is null) return;
        var dlg = new SaveFileDialog
        {
            Title = "Save function C",
            Filter = "Pseudo-C, readable|*.c|Compilable C|*.c|Text|*.txt|All files|*.*",
            FileName = SafeFileName(fn.Name) + ".c",
        };
        if (dlg.ShowDialog(this) != true) return;
        try
        {
            using var sw = new StreamWriter(dlg.FileName);
            if (dlg.FilterIndex == 2) SourceExporter.WriteCompilableCFunction(sw, _result, fn);
            else SourceExporter.WriteCFunction(sw, _result, fn);
            StatusText.Text = $"Saved {fn.Name} to {dlg.FileName}";
        }
        catch (Exception ex) { MessageBox.Show(this, ex.Message, "Export failed", MessageBoxButton.OK, MessageBoxImage.Error); }
    }

    private static string SafeFileName(string s)
    {
        foreach (var c in Path.GetInvalidFileNameChars()) s = s.Replace(c, '_');
        return s.Length > 80 ? s[..80] : s;
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

    private async Task StartAnalysis(IBinaryImage image, ulong? initialVa = null, int initialTab = 0, bool fresh = true)
    {
        _cts?.Cancel();
        _cts = new CancellationTokenSource();
        var token = _cts.Token;

        _image = image;
        if (fresh)
        {
            // A new file: wipe the old session. A re-analyse after a patch/undo keeps the current
            // lists and navigation visible until the new results replace them (no empty flash).
            _result = null;
            _nav.Reset();
            _changeStack.Clear();
            ClearLists();
            Title = $"DisasmStudio — {Path.GetFileName(image.FilePath)}";
            FileInfo.Text = $"{Path.GetFileName(image.FilePath)}  ·  {image.FormatName}  ·  {image.ArchName}  ·  base {image.ImageBase:X}";
        }

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
            SavePatchedBtn.IsEnabled = image.IsDirty;
            UndoBtn.IsEnabled = image.CanUndo;
            _funcStarts = result.Functions.Select(f => f.Va).ToArray();

            ulong target = initialVa ?? (image.EntryVa != 0 ? image.EntryVa
                : result.Functions.Count > 0 ? result.Functions[0].Va : image.MinVa);
            if (initialTab is >= 0 and <= 3) CenterTabs.SelectedIndex = initialTab;
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
        _graphFn = null;
        Decompiler.Clear();
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
        if (CenterTabs.SelectedIndex == 3) OpenDecompiler(va);

        // Data targets read better in the hex view (skip while debugging — keep focus on the live code).
        if (_dbg is null && !_result.Image.IsExecutableVa(va) && CenterTabs.SelectedIndex == 0)
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
        if (fn is null || _result is null) return;
        // Rebuild only when the function changes (object identity differs across the static↔live swap too).
        bool changed = !ReferenceEquals(fn, _graphFn);
        // Disassembler mode fits the whole function; debugger mode keeps a readable zoom on the current
        // instruction (resetting the zoom only when we move to a different function, not on every step).
        if (changed) { Graph.SetFunction(_result, fn, _dbg?.LiveDecoder, autoFit: _dbg is null); _graphFn = fn; }
        if (_dbg is not null) Graph.SetCurrentIp(_dbg.CurrentIp, resetZoom: changed);
    }

    private void OpenDecompiler(ulong va)
    {
        var fn = FindFunction(va);
        if (fn is not null && _result is not null) Decompiler.SetFunction(_result, fn);
    }

    // Populate the graph / decompiler when the user switches to that tab (they build lazily).
    private void OnCenterTabChanged(object sender, SelectionChangedEventArgs e)
    {
        if (e.Source is not TabControl || _result is null || _nav.Current is not ulong va) return;
        if (CenterTabs.SelectedIndex == 1) OpenGraph(va);
        else if (CenterTabs.SelectedIndex == 3) OpenDecompiler(va);
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
        if (FuncList.SelectedItem is not FunctionItem fi) return;
        if (fi.Function is null) NavigateToImport(fi.Va, fi.Name);    // import row — go to its callers, not the IAT
        else _nav.Navigate(fi.Va);
    }
    private void OnFuncActivate(object sender, MouseButtonEventArgs e)
    {
        if (FuncList.SelectedItem is not FunctionItem fi) return;
        if (fi.Function is null) { NavigateToImport(fi.Va, fi.Name); return; }   // import row — no CFG
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
        if (ImportList.SelectedItem is ImportItem im) NavigateToImport(im.Va, im.Name);
    }

    /// <summary>Jump to the code that calls an import, not the (useless) IAT slot in hex. List every
    /// caller in the Xrefs panel; fall back to hex only if nothing references it.</summary>
    private void NavigateToImport(ulong iatVa, string name)
    {
        if (_result is null) return;
        var refs = _result.Xrefs.To(iatVa);
        if (refs.Count > 0)
        {
            CenterTabs.SelectedIndex = 0;          // Linear
            _nav.Navigate(refs[0].From);
            SideTabs.SelectedIndex = 0;            // Xrefs — set after navigating so it isn't overwritten
            XrefList.ItemsSource = refs.Select(x => new XrefItem(x)).ToList();
            XrefHeader.Text = $"{iatVa:X}  {name} — {refs.Count} caller(s)";
        }
        else
        {
            CenterTabs.SelectedIndex = 2;
            _nav.Navigate(iatVa);
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

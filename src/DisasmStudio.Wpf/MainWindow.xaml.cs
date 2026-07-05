using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Globalization;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Input;
using System.Windows.Interop;
using System.Windows.Media;
using System.Windows.Threading;
using DisasmStudio.Core.Analysis;
using DisasmStudio.Core.Devirt;
using DisasmStudio.Core.Disasm;
using DisasmStudio.Core.Export;
using DisasmStudio.Core.Formats;
using DisasmStudio.Core.Unpacking;
using DisasmStudio.Debug;
using DisasmStudio.Managed;
using DisasmStudio.ManagedDebug;
using Architecture = DisasmStudio.Core.Formats.Architecture;   // disambiguate from System.Runtime.InteropServices.Architecture
using Iced.Intel;
using DisasmStudio.Wpf.Controls;
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
    private Task _analysisDone = Task.CompletedTask;   // completes when the in-flight analysis ends (success/cancel/fault)
    private ulong[] _funcStarts = [];
    private string? _projectPath;
    private AnalysisOptions _loadOptions = AnalysisOptions.None;   // optional non-code sections / PE header folded into the listing
    private ResourceNodeVm? _selectedResource;                    // current leaf in the Resources tree (for Save)
    private ManagedAssembly? _managed;                            // the .NET model when the open image is a managed assembly
    private int _managedSeq;                                      // guards the async managed-load against a newer file open
    private readonly Stack<(ulong Start, ulong End, bool IsPatch)> _changeStack = new();   // mirrors the image undo stack

    private DebugSession? _dbg;
    // Managed (.NET source-level) debugging: a separate out-of-process ICorDebug session. Breakpoints are kept
    // by (method token + IL offset) rather than address, and persist across the session; they are sent to the
    // host on launch (as pending) and live while stopped.
    private ManagedDebugSession? _mdbg;
    private readonly Dictionary<int, BpLoc> _managedBps = [];   // id -> source breakpoint (module + method token + IL offset)
    private int _nextManagedBpId = 1;
    // Breakpoints toggled on the static listing before (or between) debug runs, kept as static VAs. They are
    // armed at the first stop of each session (rebased by the live ASLR slide) and mirror live toggles, so the
    // set persists across Run / Restart. The gutter reads it whenever the view isn't showing live addresses.
    private readonly Dictionary<ulong, BpDef> _pendingBreakpoints = [];
    private ExceptionFilter _exceptionFilter = ExceptionStore.Load();   // persisted x64dbg-style exception policy (swapped wholesale on edit)
    private AnalysisResult? _savedResult;   // static result, restored when the debug session ends
    private bool _dbgViewLive;
    // Instruction trace (◴ Trace). Single-steps the loaded module from the current stop and records each executed
    // instruction in *static* space (like _pendingBreakpoints) so the tint maps cleanly during a run and persists
    // for post-run inspection. Calls into system DLLs run at full speed (see DebuggerEngine.StartTrace). Nothing is
    // planted up front, so it begins recording exactly where you are — no whole-image arming.
    private bool _coverageEnabled;            // the ◴ Trace toggle (trace active)
    private readonly HashSet<ulong> _coveredInstrs = [];
    private DispatcherTimer? _coverageTimer;  // polls the engine while running so highlights grow live
    private bool _restartPending;           // relaunch the target once the current debuggee has exited
    private DllDebugParams? _dllDebug;      // set for a hosted-DLL session (null for an EXE); reused on Restart
    private Function? _graphFn;              // function currently shown in the graph (avoids rebuild per step)

    // How the current DLL session is hosted, so Restart can relaunch it identically.
    private readonly record struct DllDebugParams(string HostExe, string CommandLine, string? WorkingDir, string DllPath, uint BreakRva, bool BreakIsEntry);

    private DispatcherTimer? _captureTimer;  // polls the capture stream for the log/comments/graph
    private System.Threading.Timer? _captureFlushTimer;   // flushes the capture log off the UI thread (disk I/O)
    private int _captureEdges = -1;          // last call-graph edge total (rebuild only on change)
    private long _captureGraphBuiltAt;       // Environment.TickCount64 of the last call-graph rebuild (throttle)
    private const int CaptureGraphIntervalMs = 1500;   // min gap between (expensive) call-graph TreeView rebuilds
    private string? _captureLogPath;         // last chosen capture-log path (Save-As default)
    private readonly HashSet<ulong> _captureCommented = [];   // entries already annotated inline

    private ObservableCollection<FunctionItem> _functions = [];
    private ObservableCollection<StringItem> _strings = [];
    private ObservableCollection<ExportItem> _exports = [];
    private List<SearchResultItem> _searchIndex = [];   // all searchable items (functions/imports/exports/strings), built on load
    private const int MaxSearchRows = 500;              // cap the rendered result list; the header notes when a query matched more
    private ICollectionView? _functionsView;
    private ICollectionView? _stringsView;
    private ICollectionView? _exportsView;
    private string? _lastDroppedPath;
    private long _lastDropTick;
    private int _liveStringsGen;             // bumped per live-strings scan; a stale background result is dropped
    private volatile bool _liveStringsScanning;   // a live-strings scan is in flight (don't pile up another)
    private bool _liveStringsPending;        // a stop arrived mid-scan; rescan once the in-flight scan finishes (UI thread only)

    public MainWindow()
    {
        InitializeComponent();
        WireControls();
        EnableFileDrop();
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
        Linear.BreakpointToggleRequested += OnBreakpointToggle;
        Linear.HardwareBreakpointRequested += OnHardwareBreakpointRequest;
        Linear.EditBreakpointRequested += OnEditBreakpointRequest;
        // Gutter dots come from the user breakpoint set (not the raw engine list, which during a capture also
        // holds internal capture breakpoints). `va - LiveSlide` maps the shown address back to its static VA —
        // LiveSlide is 0 unless the listing is showing live addresses — so this is correct before and during a run.
        Linear.IsBreakpointAt = va => _pendingBreakpoints.ContainsKey(va - LiveSlide);
        Linear.IsHardwareBreakpointAt = va => _pendingBreakpoints.TryGetValue(va - LiveSlide, out var def) && def.Hardware;
        // Coverage tint: _coveredInstrs holds executed instruction VAs in static space (like the breakpoint set),
        // so `va - LiveSlide` maps the shown (live) address back to it during a run and matches directly after.
        Linear.IsInstrHit = va => _coveredInstrs.Count > 0 && _coveredInstrs.Contains(va - LiveSlide);
        Graph.IsInstrHit = Linear.IsInstrHit;   // the graph shares the same trace overlay (same VA space)
        // The graph shares the linear view's breakpoint handler and predicates (same VA space), so a breakpoint
        // set from either view shows in both.
        Graph.BreakpointToggleRequested += OnBreakpointToggle;
        Graph.IsBreakpointAt = Linear.IsBreakpointAt;
        Graph.IsHardwareBreakpointAt = Linear.IsHardwareBreakpointAt;
        // Managed (.NET) source-level breakpoints: toggle from the C# view, navigate the call stack.
        Managed.BreakpointToggleRequested += OnManagedBreakpointToggle;
        ManagedDebug.FrameActivated += OnManagedFrameActivated;
        Linear.RunToCursorRequested += va => _dbg?.RunToCursor(va);
        Linear.RunToReturnRequested += () => OnRunToReturn(this, new RoutedEventArgs());
        Linear.CaptureFunctionRequested += CaptureFunctionAt;
        Linear.StatusRequested += msg => StatusText.Text = msg;
        Debug.NavigateRequested += va => _nav.Navigate(va);
        PreviewKeyDown += OnWindowPreviewKeyDown;
    }

    private void EnableFileDrop()
    {
        AllowDrop = true;
        AddHandler(DragDrop.PreviewDragEnterEvent, new DragEventHandler(OnFileDragOver), handledEventsToo: true);
        AddHandler(DragDrop.PreviewDragOverEvent, new DragEventHandler(OnFileDragOver), handledEventsToo: true);
        AddHandler(DragDrop.PreviewDropEvent, new DragEventHandler(OnFileDrop), handledEventsToo: true);
        AddHandler(DragDrop.DragEnterEvent, new DragEventHandler(OnFileDragOver), handledEventsToo: true);
        AddHandler(DragDrop.DragOverEvent, new DragEventHandler(OnFileDragOver), handledEventsToo: true);
        AddHandler(DragDrop.DropEvent, new DragEventHandler(OnFileDrop), handledEventsToo: true);
        SourceInitialized += (_, _) => EnableNativeFileDrop();
        Loaded += (_, _) => EnableFileDropOnVisualTree(this);
    }

    private void EnableNativeFileDrop()
    {
        if (PresentationSource.FromVisual(this) is not HwndSource source) return;
        NativeFileDrop.Enable(source.Handle);
        source.AddHook(OnNativeMessage);
    }

    private IntPtr OnNativeMessage(IntPtr hwnd, int msg, IntPtr wParam, IntPtr lParam, ref bool handled)
    {
        if (msg != NativeFileDrop.WmDropFiles) return IntPtr.Zero;

        handled = true;
        if (NativeFileDrop.TryGetFirstFile(wParam, out var path))
            _ = OpenDroppedFile(path);
        return IntPtr.Zero;
    }

    private static void EnableFileDropOnVisualTree(DependencyObject root)
    {
        if (root is UIElement ui) ui.AllowDrop = true;
        if (root is ContentElement content) content.AllowDrop = true;
        if (root is not Visual) return;

        int count = VisualTreeHelper.GetChildrenCount(root);
        for (int i = 0; i < count; i++)
            EnableFileDropOnVisualTree(VisualTreeHelper.GetChild(root, i));
    }

    private static class NativeFileDrop
    {
        public const int WmDropFiles = 0x0233;
        private const uint WmCopyData = 0x004A;
        private const uint WmCopyGlobalData = 0x0049;
        private const uint MsgfltAllow = 1;

        public static void Enable(IntPtr hwnd)
        {
            DragAcceptFiles(hwnd, true);
            _ = ChangeWindowMessageFilterEx(hwnd, WmDropFiles, MsgfltAllow, IntPtr.Zero);
            _ = ChangeWindowMessageFilterEx(hwnd, WmCopyData, MsgfltAllow, IntPtr.Zero);
            _ = ChangeWindowMessageFilterEx(hwnd, WmCopyGlobalData, MsgfltAllow, IntPtr.Zero);
        }

        public static bool TryGetFirstFile(IntPtr dropHandle, out string path)
        {
            path = "";
            try
            {
                uint count = DragQueryFile(dropHandle, 0xFFFFFFFF, null, 0);
                if (count == 0) return false;

                uint len = DragQueryFile(dropHandle, 0, null, 0);
                if (len == 0) return false;

                var buffer = new StringBuilder((int)len + 1);
                if (DragQueryFile(dropHandle, 0, buffer, (uint)buffer.Capacity) == 0) return false;

                string candidate = buffer.ToString();
                if (!File.Exists(candidate)) return false;

                path = candidate;
                return true;
            }
            finally
            {
                DragFinish(dropHandle);
            }
        }

        [DllImport("shell32.dll")]
        private static extern void DragAcceptFiles(IntPtr hWnd, bool fAccept);

        [DllImport("shell32.dll", CharSet = CharSet.Unicode)]
        private static extern uint DragQueryFile(IntPtr hDrop, uint iFile, StringBuilder? lpszFile, uint cch);

        [DllImport("shell32.dll")]
        private static extern void DragFinish(IntPtr hDrop);

        [DllImport("user32.dll", SetLastError = true)]
        private static extern bool ChangeWindowMessageFilterEx(IntPtr hWnd, uint message, uint action, IntPtr changeInfo);
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
        bool ctrl = (Keyboard.Modifiers & ModifierKeys.Control) != 0;
        switch (e.Key)
        {
            case Key.F5: OnDebugRun(sender, e); e.Handled = true; break;
            case Key.F7: OnStepInto(sender, e); e.Handled = true; break;
            case Key.F8: OnStepOver(sender, e); e.Handled = true; break;
            case Key.F11 when shift: OnStepOut(sender, e); e.Handled = true; break;
            case Key.F9 when ctrl: OnRunToReturn(sender, e); e.Handled = true; break;
            case Key.F1: HelpDialog.ShowShortcuts(this); e.Handled = true; break;
        }
    }

    // ---- debugger ----
    private void OnDebugRun(object sender, RoutedEventArgs e)
    {
        if (_mdbg is not null) { if (_mdbg.IsStopped) _mdbg.Go(); return; }   // managed: continue from a stop
        if (_dbg is not null) { if (_dbg.IsStopped) _dbg.Go(); return; }   // native: continue only from a stop (else it skips the next stop)
        if (_result is null || _image is null) { MessageBox.Show(this, "Open a binary first.", "Debug", MessageBoxButton.OK, MessageBoxImage.Information); return; }
        if (_image.Format != BinaryFormat.Pe) { MessageBox.Show(this, "Only Windows PE targets can be debugged.", "Debug", MessageBoxButton.OK, MessageBoxImage.Information); return; }
        // A .NET assembly → source-level (C# line) debugging via the out-of-process ICorDebug host, not the
        // native Win32 debugger. The loaded image is the managed module (its .exe apphost is what we launch).
        if (_managed is not null) { StartManagedDebug(); return; }
        if (_image.IsDll)
        {
            // A DLL can't be launched directly — host it in an EXE (rundll32 by default, or a custom host)
            // that LoadLibrary's it, and break at the DLL's DllMain (or a chosen export) once it maps.
            var exports = _image.Symbols.Where(s => s.Kind == NamedSymbolKind.Export)
                                        .Select(s => (s.Name, s.Va)).OrderBy(e => e.Name, StringComparer.Ordinal).ToList();
            if (Dialogs.AskDebugDll(this, _image.FilePath, _image.Bitness, exports) is not { } opt) return;

            // A chosen export → break at that export (rundll32 calls it; a custom host is presumably the real
            // consumer that calls it). "Just load" → break at DllMain (RVA 0 = no DllMain → stop at the load event).
            bool breakIsEntry = opt.ChosenExportVa is null;   // DllMain → EntryPoint reason; an export → Breakpoint
            uint breakRva = opt.ChosenExportVa is ulong exportVa
                ? (uint)(exportVa - _image.ImageBase)
                : (uint)(_image.EntryVa - _image.ImageBase);

            var p = new DllDebugParams(opt.HostExe, opt.CommandLine, opt.WorkingDir, _image.FilePath, breakRva, breakIsEntry);
            _dllDebug = p;
            BeginDebug(d => d.LaunchDll(p.HostExe, p.CommandLine, p.WorkingDir, p.DllPath, p.BreakRva, p.BreakIsEntry));
            return;
        }
        _dllDebug = null;
        BeginDebug(d => d.Launch(_image.FilePath));
    }

    private void OnAttach(object sender, RoutedEventArgs e)
    {
        if (_dbg is not null || _mdbg is not null) { MessageBox.Show(this, "A debug session is already active.", "Attach", MessageBoxButton.OK, MessageBoxImage.Information); return; }
        if (NotForArm("Attach")) return;
        // No file required: with a binary open we rebase its analysis onto the process; without one we analyze
        // the process's own image after attaching. The bitness hint is 0 ("unknown") when nothing is open.
        if (Dialogs.AskProcess(this, _result?.Image.Bitness ?? 0) is uint pid) BeginDebug(d => d.Attach(pid));
    }

    private async void OnUnpack(object sender, RoutedEventArgs e)
    {
        if (_image is null) { MessageBox.Show(this, "Open a packed binary first.", "Unpack", MessageBoxButton.OK, MessageBoxImage.Information); return; }
        if (_image.Format != BinaryFormat.Pe) { MessageBox.Show(this, "Only Windows PE executables can be unpacked.", "Unpack", MessageBoxButton.OK, MessageBoxImage.Information); return; }
        if (_image.IsDll) { MessageBox.Show(this, "The unpacker targets EXEs; packed DLLs aren't supported yet.", "Unpack", MessageBoxButton.OK, MessageBoxImage.Information); return; }
        if (_dbg is not null) { MessageBox.Show(this, "Stop the current debug session before unpacking.", "Unpack", MessageBoxButton.OK, MessageBoxImage.Information); return; }
        if (ManagedPeInfo.TryRead(_image) is { } net)
        {
            MessageBox.Show(this,
                $"This is a {net.Describe()} managed assembly, not a natively packed binary — there is no native OEP " +
                "to dump, so native unpacking does not apply. Use the C# tab to decompile it, and the .NET tab to " +
                "extract embedded resources and assemblies.",
                "Unpack", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        var verdict = PackerDetector.Detect(_image);
        var dlg = new UnpackerDialog(this, _image.FilePath, _image.Bitness, _image.ImageBase, verdict);
        dlg.ShowDialog();
        if (dlg.OpenPath is { } p && File.Exists(p))
            await LoadFile(p);   // reopen the rebuilt PE through the normal load + analysis pipeline
    }

    private async void OnDumpProcess(object sender, RoutedEventArgs e)
    {
        // Deliberately attaches no debugger: the target is meant to run separately so its anti-debug passes and
        // it self-decrypts. An active debug session here would defeat the point, so require it stopped first.
        if (_dbg is not null) { MessageBox.Show(this, "Stop the current debug session first. The non-invasive dumper snapshots a separately-running process and never attaches a debugger.", "Dump Process", MessageBoxButton.OK, MessageBoxImage.Information); return; }

        ulong preferred = _image?.ImageBase ?? 0;
        string? dir = _image?.FilePath is { Length: > 0 } fp ? Path.GetDirectoryName(fp) : null;
        var dlg = new NonInvasiveDumpDialog(this, preferred, dir);
        dlg.ShowDialog();
        if (dlg.OpenPath is { } p && File.Exists(p))
            await LoadFile(p);   // reopen the dumped PE through the normal load + analysis pipeline
    }

    private async void OnDevirt(object sender, RoutedEventArgs e)
    {
        if (_image is null)
        {
            MessageBox.Show(this, "Open a decrypted PE or memory dump first.", "Devirtualizer", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        if (NotForArm("Devirtualizer")) return;

        Progress.Visibility = Visibility.Visible;
        Progress.IsIndeterminate = true;
        StatusText.Text = "Devirtualizer: analyzing VM...";
        try
        {
            var image = _image;
            var result = await Task.Run(() => DevirtEngine.Run(image));
            StatusText.Text = $"Devirtualizer: {result.Status} - {result.Message}";
            new DevirtReportDialog(this, image, result).ShowDialog();
        }
        catch (Exception ex)
        {
            StatusText.Text = "Devirtualizer failed.";
            MessageBox.Show(this, ex.Message, "Devirtualizer failed", MessageBoxButton.OK, MessageBoxImage.Error);
        }
        finally
        {
            Progress.Visibility = Visibility.Collapsed;
            Progress.IsIndeterminate = false;
        }
    }

    /// <summary>ASLR slide of the live debuggee relative to the static image (live base − static base), or 0
    /// when the view isn't showing live addresses.</summary>
    private ulong LiveSlide => _dbgViewLive && _dbg?.LiveResult is { } lr && _image is not null ? lr.Image.ImageBase - _image.ImageBase : 0;

    // F2 / gutter / context-menu breakpoint toggle. While the listing shows live (rebased) addresses the
    // engine is the source of truth; otherwise the address is a static VA we stash in the pre-run set. Either
    // way the static set is kept in sync, so breakpoints survive across Run / Restart and stay shown after exit.
    private void OnBreakpointToggle(ulong va)
    {
        if (_dbgViewLive && _dbg is { } d)
        {
            d.ToggleBreakpoint(va);                       // va is a live, rebased VA (plain software bp)
            ulong sva = va - LiveSlide;                   // mirror as a static VA so it persists across runs
            if (d.HasBreakpoint(va)) _pendingBreakpoints[sva] = new BpDef(); else _pendingBreakpoints.Remove(sva);
        }
        else if (!_pendingBreakpoints.Remove(va))         // pre-run / before the first stop: va is a static VA
            _pendingBreakpoints[va] = new BpDef();
        Linear.Refresh();
        Graph.Refresh();
        Debug.Refresh();
        RefreshBreakpointList();
    }

    /// <summary>Add or replace a hardware breakpoint at the caret (right-click → Hardware breakpoint…). Asks for
    /// kind/size, records it in the pre-run set (so it survives Run/Restart), and — if a session is live — drops
    /// any existing breakpoint at the address and programs the hardware one now.</summary>
    private void OnHardwareBreakpointRequest(ulong va)
    {
        if (Dialogs.AskHardwareBreakpoint(this) is not { } hw) return;
        ulong sva = va - LiveSlide;
        var def = _pendingBreakpoints.TryGetValue(sva, out var existing) ? existing : new BpDef();
        def.Hardware = true; def.Kind = hw.Kind; def.Size = hw.Size;
        _pendingBreakpoints[sva] = def;
        if (_dbgViewLive && _dbg is { } d)
        {
            if (d.HasBreakpoint(va)) d.Engine.RemoveBreakpoint(va);   // replace any software bp at this address
            d.Engine.SetHardwareBreakpoint(va, def.Kind, def.Size);
            d.Engine.ConfigureBreakpoint(va, def.Condition, def.HitMode, def.HitTarget, def.Enabled);
        }
        Linear.Refresh();
        Graph.Refresh();
        Debug.Refresh();
        RefreshBreakpointList();
    }

    /// <summary>Edit the condition / hit-count / enabled state of the breakpoint at <paramref name="va"/>
    /// (right-click → Edit breakpoint…, or the side list's Edit menu). No-op if there is no breakpoint there.</summary>
    private void OnEditBreakpointRequest(ulong va)
    {
        ulong sva = va - LiveSlide;
        if (!_pendingBreakpoints.TryGetValue(sva, out var def)) return;
        if (Dialogs.AskBreakpointEdit(this, def) is not { } updated) return;
        _pendingBreakpoints[sva] = updated;
        if (_dbgViewLive && _dbg is { } d && d.HasBreakpoint(va))
            d.Engine.ConfigureBreakpoint(va, updated.Condition, updated.HitMode, updated.HitTarget, updated.Enabled);
        Linear.Refresh();
        Graph.Refresh();
        Debug.Refresh();
        RefreshBreakpointList();
    }

    /// <summary>Arm the pre-run breakpoints on the live engine once the image is mapped (called at the first
    /// stop), translating each static VA by the live ASLR slide and applying its condition / hit-count / enabled
    /// state and (for hardware breakpoints) kind/size.</summary>
    private void ApplyPendingBreakpoints()
    {
        if (_dbg is null || _pendingBreakpoints.Count == 0) return;
        ulong slide = LiveSlide;
        foreach (var (sva, def) in _pendingBreakpoints)
        {
            ulong va = sva + slide;
            if (def.Hardware) _dbg.Engine.SetHardwareBreakpoint(va, def.Kind, def.Size);
            else _dbg.Engine.SetBreakpoint(va);
            _dbg.Engine.ConfigureBreakpoint(va, def.Condition, def.HitMode, def.HitTarget, def.Enabled);
        }
    }

    // ---- breakpoints side list ----

    /// <summary>Rebuild the always-visible Breakpoints side list. It is driven by the user's breakpoint set —
    /// not the raw engine list, which during a "Capture all" also holds the thousands of internal capture
    /// breakpoints — so it stays a clean view of breakpoints the user set. Addresses are rebased to live VAs
    /// while debugging so a double-click lands on the right line, and symbols resolve against the shown analysis.</summary>
    private void RefreshBreakpointList()
    {
        if (BreakpointList is null) return;   // not yet built (called during construction)
        ulong slide = LiveSlide;              // 0 unless the listing is showing live addresses
        var names = _dbgViewLive ? _dbg?.LiveResult : _result;
        BreakpointList.ItemsSource = _pendingBreakpoints
            .OrderBy(kv => kv.Key)
            .Select(kv =>
            {
                ulong va = kv.Key + slide;
                string name = names?.NameFor(va) ?? "";
                string extra = kv.Value.Describe();
                string label = extra.Length == 0 ? name
                    : name.Length == 0 ? extra
                    : $"{name}   {extra}";
                return new BreakpointItem(va, label);
            })
            .ToList();
    }

    private void NavigateToBreakpoint()
    {
        if (BreakpointList.SelectedItem is not BreakpointItem b) return;
        CenterTabs.SelectedIndex = 0;   // ensure the linear view is the one shown
        _nav.Navigate(b.Va);
    }

    // ---- live strings ----

    private bool StringsTabVisible => SideTabs.SelectedItem is TabItem { Header: "Strings" };

    /// <summary>While stopped in a live session, re-scan the debuggee's memory for strings and show them in the
    /// Strings panel (replacing the static set) — so decrypted/unpacked strings that aren't in the file appear.
    /// Scanned off the UI thread (the engine is frozen at the stop); a generation guard drops a result a newer
    /// stop or session-end has superseded, and an in-flight flag avoids piling up scans during fast stepping.</summary>
    private void RefreshLiveStrings()
    {
        if (!_dbgViewLive || _dbg is not { IsStopped: true } || _dbg.LiveResult is not { } live) return;
        if (_liveStringsScanning) { _liveStringsPending = true; return; }   // a stop landed mid-scan → rescan after it finishes
        _liveStringsScanning = true;
        _liveStringsPending = false;
        var img = live.Image;
        var eng = _dbg.Engine;
        var regs = eng.GetRegisters();   // captured on the UI thread; only memory reads happen off-thread below
        int gen = ++_liveStringsGen;
        Task.Run(() =>
        {
            List<FoundString>? found = null;
            int refCount = 0;
            try
            {
                var section = StringScanner.Scan(img, minLength: 4, maxResults: MaxStringRows, useVirtualSize: true);
                // The strings the *current call* is actually using — recovered by dereferencing the live
                // argument/register pointers (CDA.Modern-style). These reach heap/stack/other-module strings the
                // section sweep above can't see. Listed first so they're visible; deduped against the section set
                // by VA (a string that is in .rdata *and* referenced shows once, flagged referenced).
                var refs = ArgStringScanner.Scan(eng, regs);
                refCount = refs.Count;
                var seen = new HashSet<ulong>(refs.Select(r => r.Va));
                found = new List<FoundString>(refs.Count + section.Count);
                found.AddRange(refs);
                foreach (var s in section) if (seen.Add(s.Va)) found.Add(s);
            }
            catch { /* a memory read raced a resume / exit */ }
            finally { _liveStringsScanning = false; }
            Dispatcher.BeginInvoke(() =>
            {
                if (found is not null && gen == _liveStringsGen && _dbgViewLive)   // else superseded / raced exit
                {
                    _strings = new ObservableCollection<StringItem>(found.Take(MaxStringRows).Select(s => new StringItem(s)));
                    _stringsView = CollectionViewSource.GetDefaultView(_strings);
                    _stringsView.Filter = StringFilterPredicate;
                    StringList.ItemsSource = _stringsView;
                    // A per-stop header (counts + the IP it was scanned at) so it's visible that the list re-scans
                    // on each breakpoint; "+N ref" is how many strings the current call's pointers reached.
                    string refPart = refCount > 0 ? $" (+{refCount} ref)" : "";
                    StringHeader.Text = $"live · {_strings.Count:N0} strings{refPart} · scanned @ {_dbg?.CurrentIp:X}";
                }
                if (_liveStringsPending && StringsTabVisible) RefreshLiveStrings();   // a stop arrived during the scan
            });
        });
    }

    /// <summary>Populate the Strings panel from the static (file) analysis — the non-live set. Shared by the
    /// initial load, the post-exit revert (live process memory is gone once the debuggee ends), and a manual
    /// refresh outside a live stop.</summary>
    private void ShowStaticStrings(AnalysisResult result)
    {
        _strings = new ObservableCollection<StringItem>(result.Strings.Take(MaxStringRows).Select(s => new StringItem(s)));
        _stringsView = CollectionViewSource.GetDefaultView(_strings);
        _stringsView.Filter = StringFilterPredicate;
        StringList.ItemsSource = _stringsView;
        StringHeader.Text = $"{_strings.Count:N0} strings";
    }

    /// <summary>Manual Strings-panel refresh (⟳ Refresh button). At a live stop it re-scans the debuggee's
    /// process memory so decrypted/unpacked strings show; while the debuggee is running the scan is skipped
    /// (memory can't be read mid-run); with no live session — including after the debuggee exits — it rebuilds
    /// from the file's static strings.</summary>
    private void OnRefreshStrings(object sender, RoutedEventArgs e)
    {
        if (_dbgViewLive) RefreshLiveStrings();          // no-ops unless stopped (engine frozen)
        else if (_result is not null) ShowStaticStrings(_result);
    }

    /// <summary>When the user switches to the Strings tab at a stop, refresh it to the current live strings.
    /// Reads the tab off <paramref name="e"/> (not the named field, which may be unset during init) and ignores
    /// SelectionChanged bubbling up from the inner list boxes.</summary>
    private void OnSideTabChanged(object sender, SelectionChangedEventArgs e)
    {
        if (e.Source is TabControl { SelectedItem: TabItem { Header: "Strings" } }) RefreshLiveStrings();
    }

    private void OnBreakpointActivate(object sender, MouseButtonEventArgs e) => NavigateToBreakpoint();
    private void OnBreakpointJump(object sender, RoutedEventArgs e) => NavigateToBreakpoint();
    private void OnBreakpointRemove(object sender, RoutedEventArgs e) { if (BreakpointList.SelectedItem is BreakpointItem b) OnBreakpointToggle(b.Va); }
    private void OnBreakpointEditMenu(object sender, RoutedEventArgs e) { if (BreakpointList.SelectedItem is BreakpointItem b) OnEditBreakpointRequest(b.Va); }
    private void OnBreakpointListKey(object sender, KeyEventArgs e) { if (e.Key == Key.Delete && BreakpointList.SelectedItem is BreakpointItem b) { OnBreakpointToggle(b.Va); e.Handled = true; } }

    private void BeginDebug(Action<DebugSession> start)
    {
        _savedResult = _result;
        _dbgViewLive = false;
        _dbg = new DebugSession(Dispatcher, _result);   // _result may be null: attach with no file open
        _dbg.Stopped += OnDbgStopped;
        _dbg.Running += () => { StatusText.Text = "Running…"; DbgRunBtn.IsEnabled = false; SetStepButtons(false); };   // no continue/step while running
        _dbg.Exited += OnDbgExited;
        _dbg.Detached += OnDbgDetached;
        _dbg.CaptureFinished += OnCaptureFinished;
        _dbg.Output += m => StatusText.Text = m;
        Debug.SetSession(_dbg);
        DebugDock.Visibility = Visibility.Visible;
        _dbg.Engine.ExceptionFilter = _exceptionFilter;   // apply the persisted exception policy to this session
        _dbg.Engine.StopAtLoaderBreakpoint = LoaderBreakCheck.IsChecked == true;   // break before the entry point
        _dbg.Engine.HideFromDebugger = HideDebuggerCheck.IsChecked == true;        // anti-anti-debug layer
        StatusText.Text = "Starting debugger…";
        start(_dbg);
    }

    // Stepping is only valid from a stop; ignore it (button or key) while the debuggee is running, where it
    // would queue a resume that the loop consumes at the next stop — silently skipping that stop.
    private void OnStepInto(object sender, RoutedEventArgs e) { if (_mdbg is { IsStopped: true }) { _mdbg.StepInto(ManagedStepRange()); return; } if (_dbg is { IsStopped: true }) _dbg.StepInto(); }
    private void OnStepOver(object sender, RoutedEventArgs e) { if (_mdbg is { IsStopped: true }) { _mdbg.StepOver(ManagedStepRange()); return; } if (_dbg is { IsStopped: true }) _dbg.StepOver(); }
    private void OnStepOut(object sender, RoutedEventArgs e) { if (_mdbg is { IsStopped: true }) { _mdbg.StepOut(); return; } if (_dbg is { IsStopped: true }) _dbg.StepOut(); }

    /// <summary>The current C# statement's IL step range (from the shown method's map), for line-level stepping.</summary>
    private int[]? ManagedStepRange()
    {
        if (_mdbg?.LastStop?.Frames is { Length: > 0 } f
            && Managed.CurrentStatementStepRange(f[0].Token, f[0].IlOffset) is { } r)
            return [r.Start, r.End];
        return null;
    }

    /// <summary>Continue until the current function returns, stopping ON its ret (calls run at full speed). Plants
    /// one-shot breakpoints on every ret of the function the IP is in (via its CFG) and runs to whichever is hit
    /// first. Falls back to Step Out when the function or its rets can't be determined (unanalyzed/JIT code).</summary>
    private void OnRunToReturn(object sender, RoutedEventArgs e)
    {
        if (_dbg is not { IsStopped: true } || _result is null) return;
        ulong ip = _dbg.CurrentIp;
        var fn = FindFunction(ip);
        if (fn is not null)
        {
            try { CfgBuilder.Build(_result.Image, fn, null, NeutralDisasm.For(_result.Image, _result.Names, _dbg.LiveDecoder)); } catch { /* fall through to Step Out */ }
            // FindFunction returns the nearest preceding function start; only trust it if the IP is actually
            // inside one of its blocks — otherwise (an unanalyzed gap) we'd run to an unrelated function's rets.
            bool inFn = fn.Blocks.Any(b => ip >= b.Start && ip < b.End);
            if (inFn)
            {
                var rets = new List<ulong>();
                foreach (var b in fn.Blocks)
                    if (b.InstrVas.Count > 0 && _dbg.LiveDecoder is { } dec
                        && dec.TryDecodeAt(b.InstrVas[^1], out var last) && last.FlowControl == FlowControl.Return)
                        rets.Add(b.InstrVas[^1]);
                if (rets.Count > 0) { _dbg.RunToAny(rets); return; }
            }
        }
        StatusText.Text = "Continue to return: current function's ret is unknown — stepping out instead.";
        _dbg.StepOut();
    }

    private void SetStepButtons(bool on) { StepIntoBtn.IsEnabled = StepOverBtn.IsEnabled = StepOutBtn.IsEnabled = RunToRetBtn.IsEnabled = DetachBtn.IsEnabled = on; }

    // ---- execution coverage (block-level: one-shot breakpoints at every basic-block start) ----

    private void OnToggleCoverage(object sender, RoutedEventArgs e)
    {
        if (CoverageToggle.IsChecked == true)
        {
            if (_dbg is not { IsStopped: true } || !_dbgViewLive || _dbg.LiveResult is not { } live)
            {
                CoverageToggle.IsChecked = false;
                StatusText.Text = "Trace: start debugging and pause first, then enable ◴ Trace.";
                return;
            }
            _coverageEnabled = true;
            // Trace from where we are: on the next Continue/step the engine single-steps the loaded module and
            // records each instruction; nothing is planted up front, so recording starts exactly at this point.
            // Calls into system DLLs run at full speed and tracing resumes when they return.
            _dbg.StartTrace(live.Image.MinVa, live.Image.MaxVa);
            // Seed with the instruction we're stopped on so it lights up immediately (it shows amber as the
            // current IP until we step off it).
            if (_coveredInstrs.Add(_dbg.CurrentIp - LiveSlide)) ClearCoverageBtn.IsEnabled = true;
            StartCoverageTimer();
            Linear.Refresh();
            Graph.Refresh();
            StatusText.Text = $"Trace started at {_dbg.CurrentIp:X} — Continue (F5) or step to record the instruction path.";
        }
        else
        {
            // Stop tracing. Keep the accumulated highlights (Clear trace wipes them). Stop single-stepping:
            // directly if stopped, else ask the engine to drop the trace at the next event so the running program
            // isn't frozen and then runs clean at full speed.
            _coverageEnabled = false;
            StopCoverageTimer();
            if (_dbg is { IsStopped: true }) _dbg.StopTrace();
            else _dbg?.RequestStopTrace();
            ClearCoverageBtn.IsEnabled = _coveredInstrs.Count > 0;
            StatusText.Text = "Trace stopped.";
        }
    }

    private void OnClearCoverage(object sender, RoutedEventArgs e)
    {
        // Wipe the highlights and the engine's recorded instructions (no memory writes either way). The trace,
        // if still on, simply starts recording afresh from wherever execution goes next.
        _coveredInstrs.Clear();
        _dbg?.ClearCoveredPoints();
        ClearCoverageBtn.IsEnabled = false;
        Linear.Refresh();
        Graph.Refresh();
    }

    /// <summary>Pull the instruction VAs the engine has recorded so far and repaint. In trace mode each covered
    /// point is an executed instruction in the loaded module, mapped straight to static space; idempotent — the
    /// covered set only grows, so re-harvesting is cheap.</summary>
    private void HarvestCoverage()
    {
        if (_dbg is null) return;
        ulong slide = LiveSlide;
        int before = _coveredInstrs.Count;
        foreach (ulong liveVa in _dbg.CoveredPoints()) _coveredInstrs.Add(liveVa - slide);
        if (_coveredInstrs.Count != before)
        {
            ClearCoverageBtn.IsEnabled = true;
            Linear.Refresh();
            Graph.Refresh();   // the graph carries the same trace overlay; repaint it as coverage grows
        }
    }

    private void StartCoverageTimer()
    {
        _coverageTimer ??= new DispatcherTimer(TimeSpan.FromMilliseconds(400), DispatcherPriority.Background,
            (_, _) => { if (_coverageEnabled && _dbg is { IsStopped: false }) HarvestCoverage(); }, Dispatcher);
        _coverageTimer.Start();
    }

    private void StopCoverageTimer() => _coverageTimer?.Stop();
    private void OnDebugPause(object sender, RoutedEventArgs e) { if (_mdbg is not null) { _mdbg.Pause(); return; } _dbg?.Pause(); }
    private void OnDebugStop(object sender, RoutedEventArgs e) { if (_mdbg is not null) { EndManagedDebug(); return; } _dbg?.Stop(); }
    // Detach keeps the debuggee running; only valid from a stop (so breakpoints/hooks can be cleanly removed).
    private void OnDebugDetach(object sender, RoutedEventArgs e) { if (_mdbg is not null) { _mdbg.Detach(); EndManagedDebug(); return; } if (_dbg is { IsStopped: true }) _dbg.Detach(); }

    // ---- managed (.NET) source-level debugging ----

    /// <summary>Toggle a source breakpoint from the C# view, keyed by (method token, IL offset). Persists across
    /// the session; applied live if a managed session is running.</summary>
    private void OnManagedBreakpointToggle((int Token, int IlOffset) t)
    {
        string module = _image is not null ? Path.GetFileName(_image.FilePath) : "";
        var existing = _managedBps.FirstOrDefault(kv => kv.Value.Token == t.Token && kv.Value.IlOffset == t.IlOffset);
        if (existing.Value is not null)
        {
            _managedBps.Remove(existing.Key);
            _mdbg?.RemoveBreakpoint(existing.Key);
        }
        else
        {
            int id = _nextManagedBpId++;
            var bp = new BpLoc(module, t.Token, t.IlOffset, id);
            _managedBps[id] = bp;
            _mdbg?.SetBreakpoint(bp);
        }
        Managed.SetActiveBreakpoints(_managedBps.Values.Select(b => (b.Token, b.IlOffset)).ToList());
    }

    private void StartManagedDebug()
    {
        if (_image is null || _managed is null) return;
        string dll = _image.FilePath;
        string module = Path.GetFileName(dll);
        string exe = Path.ChangeExtension(dll, ".exe");

        // .NET Framework (desktop CLR) can't be launched via dbgshim (CoreCLR-only); the host uses the legacy
        // ICLRMetaHost + ICorDebug.CreateProcess path instead. A Framework target is itself a managed .exe.
        bool framework = !IsNetCoreTarget(dll);

        // Launch the sibling apphost .exe if present (its PE machine is the real bitness); else run via `dotnet <dll>`.
        // (A .NET Framework managed .exe is its own apphost, so it takes the .exe branch.)
        string target; string? args = null; int bitness;
        if (File.Exists(exe)) { target = exe; bitness = PeBitness(exe) ?? 64; }
        else if (framework)
        {
            // A .NET Framework assembly with no .exe is a library (no entry point) — the `dotnet <dll>` fallback
            // would load CoreCLR, which the desktop-CLR debugger can't attach to. Refuse clearly instead of hanging.
            MessageBox.Show(this,
                "This .NET Framework assembly has no runnable executable (it looks like a library). Open the program's .exe to debug it.",
                "Managed debug", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }
        else { target = "dotnet"; args = $"\"{dll}\""; bitness = 64; }

        string? hostPath = ManagedDebugHostLocator.Find(bitness);
        if (hostPath is null)
        {
            MessageBox.Show(this,
                $"The {(bitness == 32 ? "32-bit (win-x86)" : "64-bit (win-x64)")} managed-debug host was not found.\n\n" +
                "Build/publish DisasmStudio.ManagedDbgHost for that architecture (mdbghost\\win-x86 | win-x64 next to the app).",
                "Managed debug", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        // Re-key breakpoints to the launch module (they may have been created before a run).
        var rekeyed = _managedBps.Values.Select(b => b with { Module = module }).ToList();
        _managedBps.Clear();
        foreach (var b in rekeyed) _managedBps[b.Id] = b;

        // Only give the debuggee a console when it IS a console app — a GUI target would otherwise get a stray
        // blank console window behind its own.
        bool consoleApp = IsConsoleSubsystem(dll);

        var mdbg = new ManagedDebugSession(Dispatcher, hostPath, consoleApp);
        mdbg.Launched += () => StatusText.Text = $"Managed debug: running {module}…";
        mdbg.Stopped += OnManagedStopped;
        mdbg.Exited += OnManagedExited;
        mdbg.Error += OnManagedError;
        _mdbg = mdbg;

        ManagedDebugDock.Visibility = Visibility.Visible;
        ManagedDebug.Clear();
        StepIntoBtn.IsEnabled = StepOverBtn.IsEnabled = StepOutBtn.IsEnabled = DetachBtn.IsEnabled = true;
        CenterTabs.SelectedItem = ManagedTab;
        Managed.SetActiveBreakpoints(_managedBps.Values.Select(b => (b.Token, b.IlOffset)).ToList());

        // Optionally stop at the managed entry point (Main) — reuse the "Break at loader" toggle. Sent to the
        // host but not tracked as a user breakpoint (no gutter dot / side-list entry); Main runs once, so it's
        // effectively one-shot.
        var launchBps = _managedBps.Values.ToList();
        if (LoaderBreakCheck.IsChecked == true)
        {
            int ep = EntryToken(dll);
            if (ep != 0) launchBps.Add(new BpLoc(module, ep, 0, EntryBreakpointId));
        }

        mdbg.Launch(target, args, Path.GetDirectoryName(dll), launchBps, framework);
    }

    private const int EntryBreakpointId = -1;   // the implicit "stop at entry" breakpoint's id (not a user bp)

    /// <summary>True if the loaded managed target is .NET 5+/Core (which dbgshim can debug), false for .NET
    /// Framework. Core apps ship a <c>*.runtimeconfig.json</c> and target <c>.NETCoreApp</c>; Framework apps are a
    /// managed <c>.exe</c> targeting <c>.NETFramework</c> with neither.</summary>
    private bool IsNetCoreTarget(string dll)
    {
        if (File.Exists(Path.ChangeExtension(dll, ".runtimeconfig.json"))) return true;
        string tfm = _managed?.Metadata.TargetFramework ?? "";
        if (tfm.Contains(".NETCoreApp", StringComparison.OrdinalIgnoreCase) || tfm.Contains(".NETStandard", StringComparison.OrdinalIgnoreCase)) return true;
        if (tfm.Contains(".NETFramework", StringComparison.OrdinalIgnoreCase)) return false;
        // Unknown TFM: a managed .exe is the Framework shape (a Core managed module is a .dll + native apphost).
        return !Path.GetExtension(dll).Equals(".exe", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>True if the PE's subsystem is Windows CUI (a console app) — used to decide whether to give the
    /// debuggee a console window. Defaults to false (no console) on any read error.</summary>
    private static bool IsConsoleSubsystem(string path)
    {
        try
        {
            using var fs = File.OpenRead(path);
            using var pe = new System.Reflection.PortableExecutable.PEReader(fs);
            return pe.PEHeaders.PEHeader?.Subsystem == System.Reflection.PortableExecutable.Subsystem.WindowsCui;
        }
        catch { return false; }
    }

    /// <summary>The managed entry-point method token (0x06……) of an assembly, or 0 if it has no managed entry.</summary>
    private static int EntryToken(string dll)
    {
        try
        {
            using var fs = File.OpenRead(dll);
            using var pe = new System.Reflection.PortableExecutable.PEReader(fs);
            int tok = pe.PEHeaders.CorHeader?.EntryPointTokenOrRelativeVirtualAddress ?? 0;
            return (tok & 0xFF000000) == 0x06000000 ? tok : 0;   // only a MethodDef entry point
        }
        catch { return 0; }
    }

    private void OnManagedStopped(MdbgEvent stop)
    {
        string where = stop.Frames is { Length: > 0 } fr ? _managed?.MethodName(fr[0].Token) ?? "" : "";
        StatusText.Text = $"⛔ Managed stop ({stop.Reason})  {where}";
        if (_managed is not null) ManagedDebug.Show(stop, _managed.MethodName);
        if (stop.Frames is { Length: > 0 } f) NavigateManagedTo(f[0].Token, f[0].IlOffset);
    }

    /// <summary>Show a frame's method (navigating to it in the C# view if it isn't the one shown) and highlight
    /// its line. Falls back to an in-place highlight for a method with no tree node (compiler-generated).</summary>
    private void NavigateManagedTo(int token, int ilOffset)
    {
        if (_managed?.FindNode(token) is { } node) Managed.ShowMethodForStop(node, token, ilOffset);
        else Managed.ShowStop(token, ilOffset);
    }

    private void OnManagedExited(int code)
    {
        StatusText.Text = $"Managed target exited (code {code}).";
        EndManagedDebug();
    }

    /// <summary>Managed-debug error handler. A target whose manifest requests administrator rights can't be
    /// launched by a non-elevated DisasmStudio (CreateProcess can't elevate), so offer a one-click elevated relaunch.</summary>
    private void OnManagedError(string msg)
    {
        if (msg.Contains("ELEVATION_REQUIRED") || msg.Contains("0x800702E4"))
        {
            EndManagedDebug();
            StatusText.Text = "The target requires administrator rights.";
            if (MessageBox.Show(this,
                "This program requests administrator rights, and DisasmStudio is running as a standard user — so it can't launch it.\n\n" +
                "Relaunch DisasmStudio as administrator and reopen this file?",
                "Administrator rights required", MessageBoxButton.YesNo, MessageBoxImage.Warning) == MessageBoxResult.Yes)
                RelaunchElevated();
            return;
        }
        StatusText.Text = "Managed debug: " + msg;
    }

    /// <summary>Relaunch DisasmStudio elevated (UAC prompt), reopening the current file, then close this instance.</summary>
    private void RelaunchElevated()
    {
        try
        {
            var psi = new System.Diagnostics.ProcessStartInfo(Environment.ProcessPath ?? "DisasmStudio.exe")
            {
                UseShellExecute = true,   // required for the "runas" verb (UAC)
                Verb = "runas",
            };
            if (_image is not null) psi.ArgumentList.Add(_image.FilePath);   // `DisasmStudio <path>` auto-loads on start
            System.Diagnostics.Process.Start(psi);
            Application.Current.Shutdown();
        }
        catch (Exception ex)   // e.g. the user dismissed the UAC prompt (ERROR_CANCELLED)
        {
            StatusText.Text = "Relaunch as administrator was cancelled or failed: " + ex.Message;
        }
    }

    private void EndManagedDebug()
    {
        Managed.SetCurrentLine(-1);
        ManagedDebug.Clear();
        ManagedDebugDock.Visibility = Visibility.Collapsed;
        StepIntoBtn.IsEnabled = StepOverBtn.IsEnabled = StepOutBtn.IsEnabled = DetachBtn.IsEnabled = false;
        var m = _mdbg; _mdbg = null;
        // Tear down off the UI thread — quitting/killing the host (and any stuck ICorDebug cleanup) must never
        // freeze the app.
        if (m is not null) Task.Run(() => { try { m.Dispose(); } catch { } });
    }

    /// <summary>Double-click a call-stack frame → navigate to its method and highlight its C# line.</summary>
    private void OnManagedFrameActivated(int index)
    {
        if (_mdbg?.LastStop?.Frames is { } frames && index >= 0 && index < frames.Length)
            NavigateManagedTo(frames[index].Token, frames[index].IlOffset);
    }

    /// <summary>PE machine bitness of a file: 64 (PE32+) or 32 (PE32), or null if unreadable.</summary>
    private static int? PeBitness(string path)
    {
        try
        {
            using var fs = File.OpenRead(path);
            using var pe = new System.Reflection.PortableExecutable.PEReader(fs);
            var h = pe.PEHeaders;
            if (h.PEHeader?.Magic == System.Reflection.PortableExecutable.PEMagic.PE32Plus) return 64;   // PE32+ → x64
            // PE32: a managed AnyCPU assembly (IL-only, not 32-bit-required) runs as the OS bitness — x64 here — so
            // it needs the x64 host; only an x86 / 32-bit-preferred managed image (Requires32Bit set, which
            // 32-bit-preferred also sets) actually runs 32-bit. Native PE32 images are 32-bit.
            if (h.CorHeader is { } cor)
                return (cor.Flags & System.Reflection.PortableExecutable.CorFlags.Requires32Bit) != 0 ? 32 : 64;
            return 32;
        }
        catch { return null; }
    }

    // The theme's MenuItem template is flat (no submenu popup), so drop the Help items via the button's
    // ContextMenu — opened on left-click, placed below the button.
    /// <summary>Drop a menu of every section (and the PE header) to jump to its start in the linear view.</summary>
    private void OnSectionsMenu(object sender, RoutedEventArgs e)
    {
        if (_image is null || _result is null || sender is not Button b) return;
        var cm = new ContextMenu
        {
            PlacementTarget = b,
            Placement = System.Windows.Controls.Primitives.PlacementMode.Bottom,
        };

        void Add(string name, ulong va, bool code, bool isHeader, bool foldable)
        {
            var mi = new MenuItem { Header = $"{name,-10}  {va:X}   {(code ? "code" : "data")}" };
            mi.Click += (_, _) => JumpToSection(va, isHeader ? null : name, isHeader, foldable);
            cm.Items.Add(mi);
        }

        if (_image.HeaderRegion is { } hdr) Add("HEADER", hdr.StartVa, code: false, isHeader: true, foldable: hdr.FileSize > 0);
        foreach (var s in _image.Sections.OrderBy(s => s.StartVa))
            Add(s.Name, s.StartVa, s.IsExecutable, isHeader: false, foldable: !s.IsExecutable && s.FileSize > 0);

        b.ContextMenu = cm;
        cm.IsOpen = true;
    }

    /// <summary>Jump to a section start in the linear view. A not-yet-loaded data section / header is loaded
    /// into the listing first (re-analyses) so the jump lands on real disassembly rather than the hex view.
    /// Code sections (and already-loaded ones) jump straight there.</summary>
    private async void JumpToSection(ulong va, string? sectionName, bool isHeader, bool loadable)
    {
        if (_image is null || _result is null) return;

        bool needLoad = loadable &&
            ((isHeader && !_loadOptions.IncludeHeader) ||
             (sectionName is not null && !_loadOptions.IncludedDataSections.Contains(sectionName)));
        if (needLoad)
        {
            long before = _result.Linear.Count;
            var prevOptions = _loadOptions;
            var set = new HashSet<string>(_loadOptions.IncludedDataSections);
            if (!isHeader && sectionName is not null) set.Add(sectionName);
            _loadOptions = _loadOptions with { IncludedDataSections = set, IncludeHeader = _loadOptions.IncludeHeader || isHeader };
            CenterTabs.SelectedIndex = 0;                        // show the result in the linear view
            var outcome = await StartAnalysis(_image, va, 0, fresh: false);   // re-analyse with the section loaded in, land on it
            if (outcome == AnalyzeOutcome.Failed) { _loadOptions = prevOptions; return; }   // errored — undo the change
            if (outcome == AnalyzeOutcome.Applied)
                StatusText.Text = $"Loaded {sectionName ?? "HEADER"} into the listing: {before:N0} → {_result?.Linear.Count ?? before:N0} lines (@ {va:X})";
            return;
        }

        bool inListing = _result.Linear.Count > 0 && _result.Linear.VaAt(_result.Linear.IndexOf(va)) == va;
        if (inListing) CenterTabs.SelectedIndex = 0;   // Linear
        _nav.Navigate(va);
    }

    private void OnHelpMenu(object sender, RoutedEventArgs e)
    {
        if (sender is Button { ContextMenu: { } cm } b)
        {
            cm.PlacementTarget = b;
            cm.Placement = System.Windows.Controls.Primitives.PlacementMode.Bottom;
            cm.IsOpen = true;
        }
    }

    private void OnHelpShortcuts(object sender, RoutedEventArgs e) => HelpDialog.ShowShortcuts(this);
    private void OnHelpAbout(object sender, RoutedEventArgs e) => HelpDialog.ShowAbout(this);

    // Edit the x64dbg-style exception policy. Swaps in a fresh filter (atomic for the debug thread), applies
    // live to a running session, and persists for next time.
    private void OnExceptions(object sender, RoutedEventArgs e)
    {
        if (ExceptionDialog.Show(this, _exceptionFilter) is not { } edited) return;
        _exceptionFilter = edited;
        ExceptionStore.Save(edited);
        if (_dbg is not null) _dbg.Engine.ExceptionFilter = edited;   // atomic reference swap; in-flight Decide() finishes on the old one
    }

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
        if (_nav.Current is ulong va) CaptureFunctionAt(va);
    }

    // Capture the function containing va (used by "Capture Fn" and the right-click "Capture this function").
    private void CaptureFunctionAt(ulong va)
    {
        if (_dbg is null) { StatusText.Text = "Start debugging (Run) before capturing a function."; return; }
        if (_dbg.Capture is not null) { StatusText.Text = "Stop the current capture first."; return; }   // drain is async
        var fn = FindFunction(va);
        if (fn is null) { StatusText.Text = "No function at that address to capture."; return; }
        StartCapture(fn.Va);
    }

    private void OnCaptureSelectedFunc(object sender, RoutedEventArgs e)
    {
        if (FuncList.SelectedItem is FunctionItem fi) CaptureFunctionAt(fi.Va);
    }

    private void OnFuncRightClick(object sender, MouseButtonEventArgs e)
    {
        // Select the row under the cursor so the context menu acts on what was right-clicked.
        var dep = e.OriginalSource as DependencyObject;
        while (dep is not null and not DataGridRow) dep = System.Windows.Media.VisualTreeHelper.GetParent(dep);
        if (dep is DataGridRow row) row.IsSelected = true;
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

        _captureEdges = -1; _captureGraphBuiltAt = 0; _captureCommented.Clear();
        Debug.ClearCapture(); Debug.SelectCaptureTab();
        CaptureBtn.Content = "⦿ Capturing…";
        _captureTimer ??= new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(300) };
        _captureTimer.Tick -= OnCaptureTick; _captureTimer.Tick += OnCaptureTick;
        _captureTimer.Start();
        // Persist the buffered log from a background thread, not the UI tick — flushing is disk I/O and takes a
        // lock the engine thread also writes under, so doing it on the UI tick can briefly stall the UI.
        _captureFlushTimer?.Dispose();
        _captureFlushTimer = new System.Threading.Timer(_ => { try { _dbg?.Capture?.FlushLog(); } catch { } }, null, 1000, 1000);
        string scope = funcVa == 0 ? "all functions" : cap.NameOf(funcVa);
        string freq = once ? "first call" : "every call";
        string args = argsOnly ? ", args only" : "";
        StatusText.Text = $"Capturing {scope} ({freq}{args}) → {cap.CurrentLogPart} (split into ~5 MB parts as it grows)";
        _dbg.Go();   // run so captures start flowing
    }

    private void StopCapture()
    {
        _captureTimer?.Stop();
        _captureFlushTimer?.Dispose(); _captureFlushTimer = null;
        OnCaptureTick(null, EventArgs.Empty);   // final drain of any pending records
        // Build the final call graph once now: the per-tick rebuild is gated on the tab being visible and
        // throttled, so the graph may be stale (or never built). Snapshot before StopCapture nulls Capture.
        if (_dbg?.Capture is { } cap) RebuildCaptureGraph(cap);
        _dbg?.StopCapture();
        CaptureBtn.Content = "⦿ Capture";
        StatusText.Text = "Capture stopped.";
    }

    /// <summary>A capture finished draining on the engine thread (async stop). Rebuild the graph once more so it
    /// includes the edges captured during the drain window. Skip if a new capture has since started (don't let a
    /// stale finished-capture clobber the new one's graph/throttle state) or the session is gone.</summary>
    private void OnCaptureFinished(DisasmStudio.Debug.FunctionCapture finished)
    {
        if (_dbg is { Capture: null }) RebuildCaptureGraph(finished);
    }

    /// <summary>Rebuild the Call Graph tree from the current capture edge set and record when (for throttling).
    /// Expensive — an unbounded TreeView reconstruction — so callers gate it on visibility/cadence.</summary>
    private void RebuildCaptureGraph(DisasmStudio.Debug.FunctionCapture cap)
    {
        _captureEdges = cap.EdgeCount;
        _captureGraphBuiltAt = Environment.TickCount64;
        Debug.RebuildCallGraph(cap.EdgesSnapshot(), cap.NameOf);
    }

    private void OnCaptureTick(object? sender, EventArgs e)
    {
        var cap = _dbg?.Capture;
        if (cap is null) return;
        bool is32 = _dbg!.Engine.Is32;

        // (The log is flushed on a background timer, not here — disk I/O must not stall the UI tick.)
        var recs = cap.DrainPending();   // records queued since the last tick (bounded; full history is in the file)
        if (recs.Count > 0)
        {
            Debug.AppendCapture(recs, is32);   // bounded recent view — does not retain the whole capture
            bool addedComment = false;
            if (_result?.Comments is IDictionary<ulong, string> comments)
                foreach (var r in recs)
                    if (!r.IsReturn && _captureCommented.Add(r.CalleeVa))
                        { comments[r.CalleeVa] = FunctionCapture.ArgComment(r, is32); addedComment = true; }
            if (addedComment) Linear.Refresh();   // re-render only when a NEW inline comment actually appeared
        }

        // Rebuild the call graph lazily. It's an unbounded TreeView reconstruction (and EdgesSnapshot deep-copies
        // the whole edge set under the engine's lock), so doing it every tick — especially while its tab is
        // hidden — is the main cause of UI jank in a long capture. Only rebuild when the Call Graph tab is
        // actually visible AND at most every CaptureGraphIntervalMs; while it's hidden we leave _captureEdges
        // stale so the first eligible tick (or StopCapture) refreshes it.
        if (cap.EdgeCount != _captureEdges && Debug.CallGraphTabVisible
            && Environment.TickCount64 - _captureGraphBuiltAt >= CaptureGraphIntervalMs)
            RebuildCaptureGraph(cap);

        // Live progress so the user sees it working, without the panel holding the whole capture.
        if (cap.Active) StatusText.Text = $"Capturing… {cap.TotalCount:N0} events → {cap.CurrentLogPart ?? "(log unavailable)"}";
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
            CoverageToggle.IsEnabled = true;   // execution-coverage recording can now be armed
            RestartBtn.IsEnabled = _image is not null;   // a fileless attach has no binary to relaunch
            ApplyPendingBreakpoints();   // arm breakpoints set on the static listing before launch, now that memory exists
            if (_image is null)   // attach-without-file: label the window from the analyzed process image
            {
                var img = _result.Image;
                string fn = Path.GetFileName(img.FilePath);
                Title = $"DisasmStudio — {fn} (attached)";
                FileInfo.Text = $"{fn}  ·  attached  ·  {img.ArchName}  ·  base {img.ImageBase:X}";
            }
        }
        DbgRunBtn.Content = "▶ Continue"; DbgRunBtn.IsEnabled = true; SetStepButtons(true);   // Run doubles as Continue (F5) during a session
        Linear.SetCurrentIp(_dbg.CurrentIp);
        Linear.Refresh();
        Debug.Refresh();
        RefreshBreakpointList();   // now showing live (rebased) breakpoints; reflects the pre-run set just armed
        if (_coverageEnabled)
        {
            // Record the instruction we stopped on, so a Step (Into/Over/Out) or a breakpoint stop contributes to
            // the trace too — not only the continuous single-step a Continue drives. Stored in static space.
            bool added = _coveredInstrs.Add(_dbg.CurrentIp - LiveSlide);
            HarvestCoverage();   // repaints (Refresh) when it adds anything
            if (added) { ClearCoverageBtn.IsEnabled = true; Linear.Refresh(); }   // ensure the stepped row paints
        }
        // Re-scan process memory for strings on every stop except a pure single-step (where it would thrash) —
        // unless the Strings tab is showing, in which case scan then too so stepping updates it live.
        if (_dbg.LastReason != StopReason.Step || StringsTabVisible) RefreshLiveStrings();
        if (CenterTabs.SelectedIndex == 1) OpenGraph(_dbg.CurrentIp);   // graph follows RIP too
        string? name = _result?.NameFor(_dbg.CurrentIp);
        string extra = _dbg.LastReason == StopReason.Exception ? $" (code 0x{_dbg.LastExceptionCode:X8})" : "";
        StatusText.Text = $"{_dbg.LastReason}{extra} @ {_dbg.CurrentIp:X}{(name is null ? "" : "   " + name)}";
    }

    /// <summary>Common UI teardown when a debug session ends — whether the debuggee exited or we detached from
    /// it. Drains/closes any capture, drops the live view, restores the static (pre-run) analysis + listing, and
    /// hides the debugger dock. The caller sets the status line (exit code vs. "still running").</summary>
    private void TeardownDebugSessionUi()
    {
        _captureTimer?.Stop();
        _captureFlushTimer?.Dispose(); _captureFlushTimer = null;
        OnCaptureTick(null, EventArgs.Empty);   // flush the last records to the panel
        if (_dbg?.Capture is { } cap) RebuildCaptureGraph(cap);   // final graph before capture state is dropped
        _dbg?.AbortCapture();   // drop capture state and close the log (the engine already removed its breakpoints)
        CaptureBtn.Content = "⦿ Capture"; CaptureBtn.IsEnabled = false; CaptureFnBtn.IsEnabled = false; OnceCheck.IsEnabled = false; RetCheck.IsEnabled = false; DerefCheck.IsEnabled = false;
        RestartBtn.IsEnabled = false; DbgRunBtn.Content = "▶ Run"; DbgRunBtn.IsEnabled = true; SetStepButtons(false);   // re-enable for a fresh Run
        // Trace is per-session: turn it off so a Restart doesn't keep single-stepping into the next run. Keep
        // _coveredInstrs (static VAs) so the run's highlights persist for inspection on the static listing; the
        // user re-enables ◴ Trace if they want more. The engine's trace state is gone with the session.
        StopCoverageTimer();
        _coverageEnabled = false;
        CoverageToggle.IsEnabled = false;
        if (CoverageToggle.IsChecked == true) CoverageToggle.IsChecked = false;   // programmatic: does not fire Click
        Linear.SetCurrentIp(0);
        Hex.WriteByteAt = null;
        _dbg = null; _dbgViewLive = false;   // gutter now reads the static pre-run set again (IsBreakpointAt stays wired)
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
        else   // attach-without-file: no prior analysis to return to — reset to the empty state
        {
            _result = null; _savedResult = null;
            _funcStarts = [];
            ClearLists();
            Linear.SetResult(null);
            Hex.SetImage(null);
            _nav.Reset();
            Title = "DisasmStudio";
            FileInfo.Text = "";
        }
        RefreshBreakpointList();   // back to the static pre-run set (kept in sync, so it persists for the next Run)
    }

    /// <summary>Debugger detached but left the process running. Same teardown as an exit, but no restart and a
    /// status line that makes clear the program is still alive.</summary>
    private void OnDbgDetached()
    {
        TeardownDebugSessionUi();
        StatusText.Text = "Debugger detached — the process is still running.";
    }

    private void OnDbgExited(int code)
    {
        TeardownDebugSessionUi();
        StatusText.Text = $"Debuggee exited (code {code}).";

        if (_restartPending)
        {
            _restartPending = false;
            var img = _image;
            if (_dllDebug is { } p)
                Dispatcher.BeginInvoke(() => BeginDebug(d => d.LaunchDll(p.HostExe, p.CommandLine, p.WorkingDir, p.DllPath, p.BreakRva, p.BreakIsEntry)));
            else if (img is { Format: BinaryFormat.Pe })
                Dispatcher.BeginInvoke(() => BeginDebug(d => d.Launch(img.FilePath)));
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
            Title = "Open binary or source",
            Filter = "Binaries|*.exe;*.dll;*.sys;*.so;*.elf;*.o;*.bin;*.dat|" +
                     "Source / text|*.cs;*.il;*.c;*.cpp;*.h;*.hpp;*.java;*.vb;*.txt;*.json;*.xml|All files|*.*",
        };
        if (dlg.ShowDialog(this) != true) return;
        await LoadFile(dlg.FileName);
    }

    private async void OnOpenProject(object sender, RoutedEventArgs e)
    {
        var dlg = new OpenFileDialog { Title = "Open project", Filter = "DisasmStudio project|*.dsproj|All files|*.*" };
        if (dlg.ShowDialog(this) != true) return;
        await LoadProject(dlg.FileName);
    }

    private async void OnFileDrop(object sender, DragEventArgs e)
    {
        if (!TryGetDroppedFile(e, out var path))
        {
            e.Effects = DragDropEffects.None;
            e.Handled = true;
            StatusText.Text = "Drop ignored: drag a file into DisasmStudio.";
            return;
        }

        e.Effects = DragDropEffects.Copy;
        e.Handled = true;
        await OpenDroppedFile(path);
    }

    private void OnFileDragOver(object sender, DragEventArgs e)
    {
        e.Effects = HasFileDrop(e) ? DragDropEffects.Copy : DragDropEffects.None;
        e.Handled = true;
    }

    private static bool HasFileDrop(DragEventArgs e) =>
        e.Data.GetDataPresent(DataFormats.FileDrop, autoConvert: true)
        || e.Data.GetDataPresent("FileNameW", autoConvert: true)
        || e.Data.GetDataPresent("FileName", autoConvert: true);

    private static bool TryGetDroppedFile(DragEventArgs e, out string path)
    {
        path = "";
        return TryGetFilePath(e.Data.GetData(DataFormats.FileDrop, autoConvert: true), out path)
            || TryGetFilePath(e.Data.GetData("FileNameW", autoConvert: true), out path)
            || TryGetFilePath(e.Data.GetData("FileName", autoConvert: true), out path);
    }

    private static bool TryGetFilePath(object? data, out string path)
    {
        path = "";
        if (data is string candidate) return TryUseFile(candidate, out path);
        if (data is not string[] paths) return false;

        foreach (string item in paths)
            if (TryUseFile(item, out path))
                return true;

        return false;
    }

    private static bool TryUseFile(string candidate, out string path)
    {
        path = "";
        if (string.IsNullOrWhiteSpace(candidate)) return false;
        candidate = candidate.TrimEnd('\0');
        if (!File.Exists(candidate)) return false;

        path = candidate;
        return true;
    }

    private async Task OpenDroppedFile(string path)
    {
        long now = Environment.TickCount64;
        if (string.Equals(_lastDroppedPath, path, StringComparison.OrdinalIgnoreCase) && now - _lastDropTick < 1000)
            return;

        _lastDroppedPath = path;
        _lastDropTick = now;
        StatusText.Text = $"Opening {Path.GetFileName(path)}...";

        try
        {
            if (string.Equals(Path.GetExtension(path), ".dsproj", StringComparison.OrdinalIgnoreCase))
                await LoadProject(path);
            else
                await LoadFile(path);
        }
        catch (Exception ex)
        {
            StatusText.Text = $"Drop failed: {ex.Message}";
            MessageBox.Show(this, ex.Message, "Drop failed", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    private async Task LoadProject(string path)
    {
        ProjectFile proj;
        try { proj = ProjectFile.Load(path); }
        catch (Exception ex) { MessageBox.Show(this, ex.Message, "Open project failed", MessageBoxButton.OK, MessageBoxImage.Warning); return; }

        IBinaryImage image;
        try
        {
            image = proj.Format == "Raw"
                ? RawImage.Load(proj.BinaryPath, proj.RawBaseVa, proj.RawBitness,
                                proj.RawEntryVa != 0 ? proj.RawEntryVa : proj.RawBaseVa,
                                Enum.TryParse<Architecture>(proj.RawArch, out var a) ? a
                                    : proj.RawBitness == 64 ? Architecture.X64 : Architecture.X86,
                                null)
                : proj.Format == "PE memory"
                ? PeMemoryImage.Load(proj.BinaryPath, proj.RawBaseVa)
                : BinaryLoader.Load(proj.BinaryPath);
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, $"Couldn't load the binary referenced by this project:\n{proj.BinaryPath}\n\n{ex.Message}",
                "Open project failed", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        _projectPath = path;
        _loadOptions = new AnalysisOptions
        {
            IncludedDataSections = proj.LoadedSections is { Count: > 0 } ls ? new HashSet<string>(ls) : new HashSet<string>(),
            IncludeHeader = proj.LoadHeader,
        };
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
            RawBaseVa = _image.Format == BinaryFormat.Raw || _image.FormatName == "PE memory" ? _image.ImageBase : 0,
            RawBitness = _image.Format == BinaryFormat.Raw ? _image.Bitness : 0,
            RawEntryVa = _image.Format == BinaryFormat.Raw ? _image.EntryVa : 0,
            RawArch = _image.Format == BinaryFormat.Raw ? _image.Arch.ToString() : null,
            CurrentVa = _nav.Current ?? _image.EntryVa,
            CenterTab = CenterTabs.SelectedIndex,
            LoadedSections = _loadOptions.IncludedDataSections.Count > 0 ? _loadOptions.IncludedDataSections.ToList() : null,
            LoadHeader = _loadOptions.IncludeHeader,
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
        // Works on _result (the live analysis when fileless-attached), so only that is required — the default
        // filename comes from _result.Image (the file, or the attached process's module path).
        if (_result is null) { MessageBox.Show(this, "Open a binary or attach to a process first.", "Save ASM", MessageBoxButton.OK, MessageBoxImage.Information); return; }
        // ASM export works for ARM too — it streams the same linear listing the view shows (Capstone-backed).
        var dlg = new SaveFileDialog { Title = "Save disassembly", Filter = "Assembly listing|*.asm|Text|*.txt|All files|*.*",
            FileName = ExportBaseName() + ".asm" };
        if (dlg.ShowDialog(this) != true) return;
        var r = _result;
        await RunExport(dlg.FileName, "disassembly", (w, p, ct) => SourceExporter.WriteAsm(w, r, p, ct));
    }

    private async void OnSaveC(object sender, RoutedEventArgs e)
    {
        if (_result is null) { MessageBox.Show(this, "Open a binary or attach to a process first.", "Save C", MessageBoxButton.OK, MessageBoxImage.Information); return; }
        if (_result.Image.Is8051) { MessageBox.Show(this, "C export isn't available for 8051/MCS-51 (no IL/decompiler). Use \"Save disassembly\" for the ASM listing.", "Save C", MessageBoxButton.OK, MessageBoxImage.Information); return; }
        var dlg = new SaveFileDialog
        {
            Title = "Save C",
            Filter = "Pseudo-C, readable|*.c|Compilable C|*.c|Text|*.txt|All files|*.*",
            FileName = ExportBaseName() + ".c",
        };
        if (dlg.ShowDialog(this) != true) return;
        var r = _result;
        bool comp = dlg.FilterIndex == 2;
        await RunExport(dlg.FileName, comp ? "compilable C" : "Pseudo-C",
            comp ? (w, p, ct) => SourceExporter.WriteCompilableC(w, r, p, ct)
                 : (w, p, ct) => SourceExporter.WriteC(w, r, p, ct));
    }

    /// <summary>Default filename base for whole-program exports: the loaded file's name, or the attached
    /// process's module name when fileless. Falls back to "disasm" for the synthesized "(attached process)"
    /// placeholder (no real module path), and replaces any invalid filename characters.</summary>
    private string ExportBaseName()
    {
        string name = Path.GetFileNameWithoutExtension(_result?.Image.FilePath ?? "");
        if (string.IsNullOrWhiteSpace(name) || name.StartsWith('(')) return "disasm";
        foreach (char c in Path.GetInvalidFileNameChars()) name = name.Replace(c, '_');
        return name;
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

    /// <summary>The devirtualizer and debugger are x86/x64-only (they depend on Iced semantics / the Win64
    /// ABI). Returns true — after telling the user — when the loaded image is a non-x86 raw blob (ARM-family
    /// or 8051), so the caller bails. Those images still have linear disassembly, the CFG graph, the hex
    /// view, cross-references and ASM export.</summary>
    private bool NotForArm(string feature)
    {
        if (_result?.Image.IsNonX86 != true) return false;
        string arch = _result.Image.Is8051 ? "an 8051" : "an ARM";
        MessageBox.Show(this, $"{feature} is available for x86/x64 targets only — this is {arch} image. " +
            "Linear disassembly, the CFG graph, the hex view, cross-references and ASM export all work.",
            feature, MessageBoxButton.OK, MessageBoxImage.Information);
        return true;
    }

    private async Task LoadFile(string path)
    {
        // Source/text files (e.g. a saved .cs) open in the read-only source viewer, not the binary/disasm pipeline.
        if (SourceViewerWindow.IsSourceFile(path))
        {
            new SourceViewerWindow(path) { Owner = this }.Show();
            return;
        }

        _projectPath = null; // opening a binary directly starts an unsaved session
        IBinaryImage image;
        FirmwareScan? firmware = null;
        try
        {
            var fmt = BinaryLoader.Detect(path);
            if (fmt == BinaryFormat.Unknown)
            {
                // A headerless blob: sniff it for a firmware layout so the base/bitness/entry can be suggested,
                // then let the user confirm or override. Detection is best-effort — fall back to a plain raw load.
                FirmwareScan scan;
                try { scan = FirmwareScanner.Scan(path); }
                catch { scan = FirmwareScan.NotFirmware; }
                long fileLength = new FileInfo(path).Length;
                // Sniff a sample for ARM/Thumb so the dialog can pre-select the architecture (user confirms).
                Architecture? armGuess = null;
                try
                {
                    using var fs = File.OpenRead(path);
                    var sample = new byte[(int)Math.Min(fs.Length, 0x40000)];
                    fs.ReadExactly(sample);
                    armGuess = ArmHeuristics.Detect(sample);
                }
                catch { /* detection is best-effort */ }
                var opt = Dialogs.AskRawOptions(this, scan, fileLength, armGuess);
                if (opt is null) return;
                image = RawImage.Load(path, opt.Value.BaseVa, opt.Value.Bitness, opt.Value.EntryVa,
                                      opt.Value.Arch, scan.IsFirmware ? scan.Symbols : null);
                if (scan.IsFirmware) firmware = scan;
            }
            else if (fmt == BinaryFormat.Pe && LooksLikeMemoryDumpPath(path) && PeMemoryImage.TryLoad(path, out var mem))
            {
                image = mem;
            }
            else image = BinaryLoader.Load(path);
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, ex.Message, "Open failed", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        // IDA-style: let the user fold optional non-code sections / the PE header into the listing.
        var opts = Dialogs.AskLoadSections(this, image, AnalysisOptions.None);
        if (opts is null) { (image as IDisposable)?.Dispose(); return; }   // cancelled
        _loadOptions = opts;
        await StartAnalysis(image);

        // Report what the firmware sniffer found (and where the entry landed) once analysis has settled.
        if (firmware is not null) StatusText.Text = firmware.Summary;

        // Nudge toward the right tool for the freshly-loaded PE: the managed decompiler for .NET, the unpacker
        // when it looks natively packed.
        if (image.Format == BinaryFormat.Pe)
        {
            try
            {
                if (ManagedPeInfo.TryRead(image) is { } net)
                    StatusText.Text = $"{net.Describe()} managed assembly — open the C# tab to decompile, or the .NET tab to extract embedded resources/assemblies.";
                else { var v = PackerDetector.Detect(image); if (v.IsPacked) StatusText.Text = $"{v.Notes}  Use Unpack… to recover it."; }
            }
            catch { /* detection is best-effort */ }
        }
    }

    private static bool LooksLikeMemoryDumpPath(string path)
    {
        string name = Path.GetFileName(path);
        string ext = Path.GetExtension(path);
        return name.Contains("_fault_dump", StringComparison.OrdinalIgnoreCase)
            || name.Contains("_memdump", StringComparison.OrdinalIgnoreCase)
            || ext.Equals(".dmp", StringComparison.OrdinalIgnoreCase)
            || ext.Equals(".mem", StringComparison.OrdinalIgnoreCase)
            || ext.Equals(".bin", StringComparison.OrdinalIgnoreCase);
    }

    private enum AnalyzeOutcome { Applied, Cancelled, Failed }

    private async Task<AnalyzeOutcome> StartAnalysis(IBinaryImage image, ulong? initialVa = null, int initialTab = 0, bool fresh = true)
    {
        // On a fresh load, retire the previous file-backed image once the new one is up and its analysis stopped.
        var prevImage = fresh ? _image : null;
        var prevDone = _analysisDone;

        _cts?.Cancel();
        _cts = new CancellationTokenSource();
        var token = _cts.Token;

        _image = image;
        if (fresh)
        {
            // A new file: wipe the old session. A re-analyse after a patch/undo keeps the current
            // lists and navigation visible until the new results replace them (no empty flash).
            _result = null;
            _dllDebug = null;   // a stale DLL-host config must not leak into a later EXE's Restart
            _pendingBreakpoints.Clear();   // breakpoints belong to the old file's addresses
            // Trace highlights belong to the old image's addresses — drop them.
            _coverageEnabled = false;
            _coveredInstrs.Clear(); StopCoverageTimer();
            if (CoverageToggle is not null) { CoverageToggle.IsChecked = false; CoverageToggle.IsEnabled = false; ClearCoverageBtn.IsEnabled = false; }
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
            var opts = _loadOptions;
            var task = Task.Run(() => AnalysisEngine.Analyze(image, opts, progress, token), token);
            _analysisDone = SilentlyAwait(task);
            var result = await task;
            if (token.IsCancellationRequested) return AnalyzeOutcome.Cancelled;

            _result = result;
            PopulateLists(result);
            Linear.SetResult(result);
            Hex.SetImage(image);
            if (fresh) ProbeManaged(image);   // light up the C#/.NET tabs when this PE is a managed assembly
            SavePatchedBtn.IsEnabled = image.IsDirty;
            UndoBtn.IsEnabled = image.CanUndo;
            _funcStarts = result.Functions.Select(f => f.Va).ToArray();

            ulong target = initialVa ?? (image.EntryVa != 0 ? image.EntryVa
                : result.Functions.Count > 0 ? result.Functions[0].Va : image.MinVa);
            // Don't override the C# tab that ProbeManaged just switched to for a managed assembly.
            if (initialTab is >= 0 and <= 3 && !ReferenceEquals(CenterTabs.SelectedItem, ManagedTab))
                CenterTabs.SelectedIndex = initialTab;
            _nav.Navigate(target);

            // The UI now references the new image and the previous analysis was cancelled — wait for it to
            // actually stop, then release the previous file-backed mapping. Skipped while debugging, where the
            // live session still reads the static image through LiveProcessImage. Disposal is safe-by-default
            // (a disposed mapping reads as 0), so even a stray reader can't crash.
            if (prevImage is not null && !ReferenceEquals(prevImage, image) && _dbg is null)
            {
                await prevDone;
                (prevImage as IDisposable)?.Dispose();
            }
            return AnalyzeOutcome.Applied;
        }
        catch (OperationCanceledException) { return AnalyzeOutcome.Cancelled; }
        catch (Exception ex)
        {
            MessageBox.Show(this, ex.Message, "Analysis failed", MessageBoxButton.OK, MessageBoxImage.Error);
            return AnalyzeOutcome.Failed;
        }
        finally
        {
            Progress.Visibility = Visibility.Collapsed;
            Progress.IsIndeterminate = false;
        }
    }

    /// <summary>Await a task purely for its completion (success/cancel/fault); the real outcome is handled by
    /// the direct awaiter. Used to know when a cancelled analysis has actually stopped reading its image.</summary>
    private static async Task SilentlyAwait(Task t) { try { await t; } catch { } }

    protected override void OnClosed(EventArgs e)
    {
        base.OnClosed(e);
        _cts?.Cancel();
        try { _mdbg?.Dispose(); } catch { }   // stop the out-of-process managed-debug host (+ its debuggee) cleanly
        _managed?.Dispose();
        (_image as IDisposable)?.Dispose();
        (_savedResult?.Image as IDisposable)?.Dispose();   // static image held across a debug session
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

        ShowStaticStrings(result);

        _exports = new ObservableCollection<ExportItem>(result.Image.Symbols
            .Where(s => s.Kind == NamedSymbolKind.Export)
            .OrderBy(s => s.Name, StringComparer.OrdinalIgnoreCase)
            .Select(s => new ExportItem(s)));
        _exportsView = CollectionViewSource.GetDefaultView(_exports);
        _exportsView.Filter = ExportFilterPredicate;
        ExportList.ItemsSource = _exportsView;

        ImportList.ItemsSource = result.Image.Imports.Select(i => new ImportItem(i)).ToList();

        BuildSearchIndex(result);

        var sectionRows = new List<SectionItem>();
        if (result.Image.HeaderRegion is { } hdr)
            sectionRows.Add(new SectionItem(hdr, _loadOptions.IncludeHeader, isHeader: true));
        sectionRows.AddRange(result.Image.Sections.Select(s =>
            new SectionItem(s, _loadOptions.IncludedDataSections.Contains(s.Name))));
        SectionList.ItemsSource = sectionRows;

        ResTree.ItemsSource = result.Image.Resources is { Roots.Count: > 0 } res
            ? res.Roots.Select(r => new ResourceNodeVm(r, r.Id)).ToList()
            : null;
        ResPreviewHost.Content = null;
        ResSaveBtn.IsEnabled = false;
        _selectedResource = null;
        ResHeader.Text = result.Image.Resources is { Roots.Count: > 0 } ? "Select a resource" : "No resources";
        RefreshBreakpointList();
    }

    private void ClearLists()
    {
        FuncList.ItemsSource = null;
        StringList.ItemsSource = null;
        StringHeader.Text = "";
        ExportList.ItemsSource = null;
        ImportList.ItemsSource = null;
        SectionList.ItemsSource = null;
        ResTree.ItemsSource = null;
        ResPreviewHost.Content = null;
        ResSaveBtn.IsEnabled = false;
        _selectedResource = null;
        ResHeader.Text = "Select a resource";
        XrefList.ItemsSource = null;
        BreakpointList.ItemsSource = null;
        _searchIndex = [];
        SearchResults.ItemsSource = null;
        SearchRefs.ItemsSource = null;
        SearchBox.Text = "";
        SearchHeader.Text = "";
        SearchRefHeader.Text = "Select a result to list references";
        Graph.Clear();
        _graphFn = null;
        Decompiler.Clear();

        // Managed (.NET) views: retire the previous assembly and hide the tabs until the next probe re-shows them.
        Managed.Clear();
        _managed?.Dispose();
        _managed = null;
        _managedSeq++;   // cancel any in-flight managed load for the old file
        ManagedTab.Visibility = Visibility.Collapsed;
        DotNetTab.Visibility = Visibility.Collapsed;
        NetResList.ItemsSource = null;
        NetInfo.Text = "";
        NetSaveBtn.IsEnabled = false;
        NetExtractAllBtn.IsEnabled = false;
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
        // But if the section/header was folded into the listing, stay on Linear — that's where the user put it.
        if (_dbg is null && !_result.Image.IsExecutableVa(va) && !IsLoadedIntoListing(va) && CenterTabs.SelectedIndex == 0)
            CenterTabs.SelectedIndex = 2;
    }

    /// <summary>True if <paramref name="va"/> lies in a non-code region the user folded into the listing.</summary>
    private bool IsLoadedIntoListing(ulong va)
    {
        if (_image is null) return false;
        if (_loadOptions.IncludeHeader && _image.HeaderRegion is { } h
            && va >= h.StartVa && va < h.StartVa + (ulong)h.FileSize) return true;
        return _image.SectionAt(va) is { } s && _loadOptions.IncludedDataSections.Contains(s.Name);
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
        // The decompiler covers x86/x64 (Iced) and the whole ARM family (Capstone). 8051 has no IL/pseudo-C
        // path — gate it here so DecompilerView never builds an Iced decoder over 8051 bytes.
        if (_result?.Image.Is8051 == true)
        {
            MessageBox.Show(this, "Pseudo-C decompilation isn't available for 8051/MCS-51. Linear disassembly, " +
                "the CFG graph, the hex view and cross-references all work.",
                "Decompiler", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
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
        if (va < _result.Image.MinVa || va >= _result.Image.MaxVa) return null;   // outside the analyzed image (e.g. a foreign module during debug)
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
        else if (_result.Image.IsNonX86)
        {
            // ARM/8051 analysis records no data xrefs, so every string is "unreferenced" here. Rather than
            // dropping to hex, show the string itself in the linear listing — its VA is a data line that
            // renders as db "…", so the click lands on the code view at the string. (These are raw blobs
            // whose one section is executable, so OnNavigated's hex-redirect guard won't fire.)
            CenterTabs.SelectedIndex = 0;          // Linear
            _nav.Navigate(si.Va);
        }
        else
        {
            CenterTabs.SelectedIndex = 2;          // genuinely unreferenced data — show in hex
            _nav.Navigate(si.Va);
        }
    }

    // ---- unified Search / find-references panel ----

    /// <summary>Build the flat search index from the static analysis: discovered functions, imports (at their IAT
    /// slot), exports, and every scanned string. Strings carry their byte length so a reference into the middle of
    /// a merged literal is still found. Rebuilt on each load; the list stays static across a debug session (like
    /// the Functions/Exports lists), so it always reflects the file's addresses.</summary>
    private void BuildSearchIndex(AnalysisResult result)
    {
        var items = new List<SearchResultItem>(
            result.Functions.Count + result.Image.Imports.Count + result.Strings.Count + 16);
        foreach (var f in result.Functions)
            items.Add(new SearchResultItem(f.Va, "fn", f.Name));
        foreach (var i in result.Image.Imports)
            items.Add(new SearchResultItem(i.IatVa, "imp", Demangler.Demangle(i.Name)));
        foreach (var s in result.Image.Symbols.Where(s => s.Kind == NamedSymbolKind.Export))
            items.Add(new SearchResultItem(s.Va, "exp", Demangler.Demangle(s.Name)));
        foreach (var s in result.Strings)
            items.Add(new SearchResultItem(s.Va, "str", s.Text, s.Wide ? s.Length * 2 : s.Length));

        _searchIndex = items;
        SearchResults.ItemsSource = null;
        SearchRefs.ItemsSource = null;
        SearchHeader.Text = items.Count > 0 ? $"{items.Count:N0} searchable — type to filter" : "";
        SearchRefHeader.Text = "Select a result to list references";
    }

    private void OnSearchFilter(object sender, TextChangedEventArgs e)
    {
        string q = SearchBox.Text.Trim();
        if (q.Length == 0)
        {
            SearchResults.ItemsSource = null;
            SearchHeader.Text = _searchIndex.Count > 0 ? $"{_searchIndex.Count:N0} searchable — type to filter" : "";
            return;
        }

        // Match name/string text or the hex address. Take one extra to detect (and report) the cap without
        // rendering an unbounded list on a broad query.
        var matches = _searchIndex
            .Where(it => it.Text.Contains(q, StringComparison.OrdinalIgnoreCase)
                      || it.Address.Contains(q, StringComparison.OrdinalIgnoreCase))
            .Take(MaxSearchRows + 1)
            .ToList();
        bool capped = matches.Count > MaxSearchRows;
        if (capped) matches.RemoveAt(matches.Count - 1);
        SearchResults.ItemsSource = matches;
        SearchHeader.Text = capped
            ? $"showing first {MaxSearchRows:N0} matches — narrow the query"
            : $"{matches.Count:N0} match(es)";
    }

    private void OnSearchResultSelected(object sender, SelectionChangedEventArgs e)
    {
        if (SearchResults.SelectedItem is SearchResultItem it) ShowReferences(it);
    }

    /// <summary>List every reference to the selected result in the lower pane, with the enclosing function for
    /// context. Uses the same range + pointer-slot resolution as the Strings panel, so a reference into the
    /// middle of a string, or one reached only through a pointer table, is still found.</summary>
    private void ShowReferences(SearchResultItem it)
    {
        if (_result is null) return;

        ulong end = it.Va + (ulong)it.ByteLength;                 // point targets have ByteLength 1 ⇒ To(Va)
        var refs = _result.Xrefs.ToRange(it.Va, end);
        if (refs.Count == 0 && _result.StringPointerSlots.TryGetValue(it.Va, out var slot))
            refs = _result.Xrefs.To(slot).ToList();

        SearchRefs.ItemsSource = refs.Select(x => new ReferenceItem(x, ContextFor(x.From))).ToList();
        string preview = it.Text.Length > 32 ? it.Text[..32] + "…" : it.Text;
        SearchRefHeader.Text = $"{it.Va:X}  {preview} — {refs.Count} ref(s)";
    }

    /// <summary>Human-readable orientation for a referencing address: its enclosing function, else its section.</summary>
    private string ContextFor(ulong va)
    {
        if (FindFunction(va) is { } fn) return fn.Name;
        return _result?.Image.SectionAt(va)?.Name ?? "";
    }

    private void OnSearchResultActivate(object sender, MouseButtonEventArgs e)
    {
        if (SearchResults.SelectedItem is not SearchResultItem it || _result is null) return;
        // An import has no code at its IAT slot (navigating there just drops into hex) — jump to the first
        // caller instead. Every other kind has meaningful code/data at its VA, so go to the definition.
        if (it.Kind == "imp" && _result.Xrefs.To(it.Va) is { Count: > 0 } callers)
        {
            CenterTabs.SelectedIndex = 0;
            _nav.Navigate(callers[0].From);
            return;
        }
        _nav.Navigate(it.Va);
    }

    private void OnSearchRefActivate(object sender, MouseButtonEventArgs e)
    {
        if (SearchRefs.SelectedItem is not ReferenceItem r) return;
        CenterTabs.SelectedIndex = 0;          // show the referencing code in the linear listing
        _nav.Navigate(r.Va);
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
        // Plain navigation: a non-folded data section lands in the hex view (it isn't in the listing).
        // Right-click → "Jump + fold into listing" (or the toolbar "Sections ▾") to fold it into linear.
        if (SectionList.SelectedItem is SectionItem se) _nav.Navigate(se.Va);
    }

    /// <summary>Select the section row under the cursor so the right-click menu acts on it.</summary>
    private void OnSectionRightClick(object sender, MouseButtonEventArgs e)
    {
        var dep = e.OriginalSource as DependencyObject;
        while (dep is not null and not ListBoxItem) dep = System.Windows.Media.VisualTreeHelper.GetParent(dep);
        if (dep is ListBoxItem row) row.IsSelected = true;
    }

    /// <summary>Right-click menu: jump to the section, loading a non-code section into the linear listing.</summary>
    private void OnSectionJumpFold(object sender, RoutedEventArgs e)
    {
        if (SectionList.SelectedItem is SectionItem se)
            JumpToSection(se.Va, se.IsHeader ? null : se.Name, se.IsHeader, se.CanToggle);
        else
            StatusText.Text = "Select a section first, then right-click → Show in listing.";
    }

    /// <summary>Right-click menu: plain jump (a non-folded data section opens in Hex).</summary>
    private void OnSectionJumpHex(object sender, RoutedEventArgs e)
    {
        if (SectionList.SelectedItem is SectionItem se) _nav.Navigate(se.Va);
    }

    /// <summary>Toggle whether a non-code section / the PE header is folded into the listing, then re-analyse
    /// (keeping the current view) so the change takes effect.</summary>
    private async void OnSectionLoadToggle(object sender, RoutedEventArgs e)
    {
        if (_image is null || _result is null) return;
        if (sender is not CheckBox cb || cb.DataContext is not SectionItem item || !item.CanToggle) return;
        bool on = cb.IsChecked == true;
        if (item.Loaded == on) return;   // no-op (e.g. event fired during list rebuild)

        var prevOptions = _loadOptions;
        item.Loaded = on;
        var set = new HashSet<string>(_loadOptions.IncludedDataSections);
        bool header = _loadOptions.IncludeHeader;
        if (item.IsHeader) header = on;
        else if (on) set.Add(item.Name); else set.Remove(item.Name);
        _loadOptions = _loadOptions with { IncludedDataSections = set, IncludeHeader = header };

        // On enable, jump to the section in the linear view so the change is visibly applied (it usually lands
        // at a high address you'd otherwise have to scroll to); on disable, stay put.
        long before = _result.Linear.Count;
        var outcome = await StartAnalysis(_image, on ? item.Va : _nav.Current, on ? 0 : CenterTabs.SelectedIndex, fresh: false);
        if (outcome == AnalyzeOutcome.Failed)   // re-analysis errored — undo the option + checkbox change
        {
            _loadOptions = prevOptions;
            item.Loaded = !on;
            cb.IsChecked = !on;
            return;
        }
        if (outcome == AnalyzeOutcome.Applied)
            StatusText.Text = on
                ? $"Loaded {item.Name} into the listing: {before:N0} → {_result?.Linear.Count ?? before:N0} lines (@ {item.Va:X})"
                : $"Removed {item.Name}: {before:N0} → {_result?.Linear.Count ?? before:N0} lines";
    }

    // ---- resources ----
    private void OnResourceSelected(object sender, RoutedPropertyChangedEventArgs<object> e) =>
        ShowResource(e.NewValue as ResourceNodeVm);

    private void ShowResource(ResourceNodeVm? vm)
    {
        _selectedResource = vm is { IsLeaf: true } ? vm : null;
        if (vm is null || vm.Data is not { } d || _image is null)
        {
            ResHeader.Text = vm is null ? "Select a resource" : vm.Display;
            ResPreviewHost.Content = null;
            ResSaveBtn.IsEnabled = false;
            return;
        }
        var bytes = _image.ReadBytesAtVa(d.DataVa, d.Size);
        ResHeader.Text = $"{vm.Display}   VA {d.DataVa:X}   {bytes.Length:N0} B   cp{d.CodePage}";
        ResPreviewHost.Content = ResourcePreview.Build(bytes, vm.TypeId);
        ResSaveBtn.IsEnabled = bytes.Length > 0;
    }

    private void OnResourceActivate(object sender, MouseButtonEventArgs e)
    {
        if (ResTree.SelectedItem is ResourceNodeVm { Data: { } d }) _nav.Navigate(d.DataVa);
    }

    private void OnSaveResource(object sender, RoutedEventArgs e)
    {
        if (_selectedResource is not { Data: { } d } vm || _image is null) return;
        var bytes = _image.ReadBytesAtVa(d.DataVa, d.Size);
        var dlg = new SaveFileDialog { Title = "Save resource", FileName = SuggestResourceName(vm) };
        if (dlg.ShowDialog(this) != true) return;
        try { File.WriteAllBytes(dlg.FileName, bytes); StatusText.Text = $"Saved resource to {dlg.FileName}"; }
        catch (Exception ex) { MessageBox.Show(this, ex.Message, "Save failed", MessageBoxButton.OK, MessageBoxImage.Error); }
    }

    /// <summary>A default filename for saving a leaf resource. Text types keep a readable extension; binary
    /// types (whose bytes are a packed DIB, not a standalone file) save as raw .bin to avoid a misleading name.</summary>
    private static string SuggestResourceName(ResourceNodeVm vm) => "resource" + vm.TypeId switch
    {
        ResourceTree.RT_MANIFEST => ".xml",
        ResourceTree.RT_HTML => ".html",
        _ => ".bin",
    };

    // ---- managed (.NET) assembly path ----

    /// <summary>If the freshly-analyzed PE is a managed assembly, build its model on a background thread and
    /// (once done) reveal the C# and .NET tabs. Seq-guarded so a newer file open discards a stale result.</summary>
    private void ProbeManaged(IBinaryImage image)
    {
        if (image.Format != BinaryFormat.Pe || ManagedPeInfo.TryRead(image) is null) return;

        // Detected synchronously: reveal and switch to the C# view NOW (with a loading note) so the user never
        // lands on the native disassembly — for a managed image that's just the mscoree stub and looks like a
        // garbage/encrypted dump. The heavy decompiler load then fills it in; if it fails, we revert to native.
        Managed.ShowLoading("// loading .NET decompiler…");
        ManagedTab.Visibility = Visibility.Visible;
        DotNetTab.Visibility = Visibility.Visible;
        CenterTabs.SelectedItem = ManagedTab;
        StatusText.Text = ".NET assembly — loading decompiler…";

        int seq = ++_managedSeq;
        var captured = image;
        Task.Run(() => { ManagedAssembly.TryLoad(captured, out var a); return a; }).ContinueWith(t =>
        {
            var asm = t.IsCompletedSuccessfully ? t.Result : null;
            Dispatcher.Invoke(() =>
            {
                if (seq != _managedSeq || !ReferenceEquals(_image, captured)) { asm?.Dispose(); return; }
                if (asm is null)
                {
                    // Decompiler couldn't load it — hide the managed tabs and fall back to the native view.
                    Managed.Clear();
                    ManagedTab.Visibility = Visibility.Collapsed;
                    DotNetTab.Visibility = Visibility.Collapsed;
                    CenterTabs.SelectedIndex = 0;
                    StatusText.Text = ".NET assembly detected, but the decompiler could not load it — showing the native view.";
                    return;
                }
                _managed = asm;
                Managed.SetAssembly(asm);
                PopulateManagedTabs(asm);
                StatusText.Text = $".NET assembly: {asm.Metadata.Name} — showing decompiled C# (native disasm is only the .NET loader stub).";
            });
        });
    }

    private void PopulateManagedTabs(ManagedAssembly asm)
    {
        var m = asm.Metadata;
        NetInfo.Text = $"{m.Name}  ·  v{m.Version}  ·  {m.TargetFramework}  ·  {(m.IsILOnly ? "IL-only" : "mixed-mode")}\n" +
                       $"{asm.Resources.Count} embedded resource(s)   ·   references: {string.Join(", ", m.ReferencedAssemblies.Take(6))}";
        NetResList.ItemsSource = asm.Resources;
        NetSaveBtn.IsEnabled = false;
        NetExtractAllBtn.IsEnabled = asm.Resources.Count > 0;
    }

    private void OnNetResourceSelected(object sender, SelectionChangedEventArgs e)
        => NetSaveBtn.IsEnabled = NetResList.SelectedItem is ManagedResourceEntry;

    private void OnNetResourceActivate(object sender, MouseButtonEventArgs e) => SaveSelectedManagedResource();
    private void OnNetSaveResource(object sender, RoutedEventArgs e) => SaveSelectedManagedResource();

    private void SaveSelectedManagedResource()
    {
        if (NetResList.SelectedItem is not ManagedResourceEntry r) return;
        var dlg = new SaveFileDialog { Title = "Save resource", FileName = SafeResourceFileName(r.Name), Filter = "All files|*.*" };
        if (dlg.ShowDialog(this) != true) return;
        try { File.WriteAllBytes(dlg.FileName, r.GetBytes()); StatusText.Text = $"Saved {dlg.FileName}"; }
        catch (Exception ex) { MessageBox.Show(this, ex.Message, "Save failed", MessageBoxButton.OK, MessageBoxImage.Error); }
    }

    private void OnNetExtractAll(object sender, RoutedEventArgs e)
    {
        if (_managed is not { } asm || asm.Resources.Count == 0) return;
        var dlg = new OpenFolderDialog { Title = "Extract all embedded resources to…" };
        if (dlg.ShowDialog(this) != true) return;
        int ok = 0, fail = 0;
        foreach (var r in asm.Resources)
        {
            try
            {
                var bytes = r.GetBytes();
                if (bytes.Length == 0) continue;
                File.WriteAllBytes(Path.Combine(dlg.FolderName, SafeResourceFileName(r.Name)), bytes);
                ok++;
            }
            catch { fail++; }
        }
        StatusText.Text = $"Extracted {ok} resource(s) to {dlg.FolderName}" + (fail > 0 ? $"  ({fail} failed)" : "");
    }

    /// <summary>A filesystem-safe name for an extracted managed resource (which may be an inner "blob :: key").</summary>
    private static string SafeResourceFileName(string name)
    {
        string s = string.Concat(name.Split(Path.GetInvalidFileNameChars())).Replace(" :: ", "__");
        if (s.Length > 120) s = s[^120..];
        return s.Length == 0 ? "resource.bin" : s;
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

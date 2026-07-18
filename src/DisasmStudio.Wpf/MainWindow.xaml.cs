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
using DisasmStudio.Core.Analysis.Signatures;
using DisasmStudio.Core.IL;
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
    // User markup (renames / comments / bookmarks), keyed by static VA. The single source of truth for the
    // session: re-applied to each (re-)analysis result via UseMarkup so edits survive a patch/undo re-analysis,
    // and saved into the .dsproj. Reset on a fresh file open; loaded from the project on OpenProject.
    private Markup _markup = new();
    private AnalysisOptions _loadOptions = AnalysisOptions.None;   // optional non-code sections / PE header folded into the listing
    private ResourceNodeVm? _selectedResource;                    // current leaf in the Resources tree (for Save)
    private ManagedAssembly? _managed;                            // the .NET model when the open image is a managed assembly
    private int _managedSeq;                                      // guards the async managed-load against a newer file open
    // Unified undo stack: byte patches / hex edits (kept in lock-step with the image's own undo stack) plus
    // model edits like "create function". Ctrl+Z / the Undo button pop the most recent entry, whatever its kind.
    private readonly Stack<EditEntry> _changeStack = new();
    private abstract record EditEntry;
    private sealed record ByteEdit(ulong Start, ulong End, bool IsPatch) : EditEntry;               // patch → RepairIndex, hex → InvalidateView
    private sealed record CreateFunctionEdit(ulong StaticVa, bool AddedName) : EditEntry;  // user "create function here" (StaticVa = unslid)

    private DebugSession? _dbg;
    // "Toggle jump" state. While debugging, the current-IP conditional jump is coloured from the REAL live flags
    // (cached here on each stop) and a toggle flips those flags so the debuggee takes the other path. Anywhere
    // else it's a static what-if: a per-jump assumed direction (static VA → true = taken/green, false = red).
    private (ulong Va, bool Taken)? _curJump;                       // current-IP jump evaluated from real flags
    private readonly Dictionary<ulong, bool> _jumpAssume = new();   // static what-if assumptions, keyed in static VA
    // Managed (.NET source-level) debugging: a separate out-of-process ICorDebug session. Breakpoints are kept
    // by (method token + IL offset) rather than address, and persist across the session; they are sent to the
    // host on launch (as pending) and live while stopped.
    private ManagedDebugSession? _mdbg;
    private bool _mdbgFramework;          // the live managed session's target is .NET Framework (desktop CLR), not Core
    private bool _mdbgTargetIsGui;        // target is a GUI (WinForms/WPF) app — the case where a managed debugger disables the top-level handler
    private bool _mdbgNativeOfferDeclined; // user already declined the "run under the native debugger" offer this session
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
    private bool _openingGraph;              // guards OnCenterTabChanged from re-opening the graph at the caret during an explicit "open in graph"
    private CallGraph? _callGraph;           // whole-program static call graph, built lazily on first Call Graph tab view
    private EntropyData? _entropy;           // per-block + per-section byte entropy, built lazily on first Entropy tab view
    private int _entropyGen;                 // bumps per file/build so a stale background compute discards its result

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
    private const int MaxInsnMatches = 2000;            // cap the Find-instruction result list; the header notes when it stopped early
    private CancellationTokenSource? _findInsnCts;      // cancels an in-flight instruction scan when a newer search starts
    private List<InsnMatchItem> _findResults = [];      // current Find-tab match rows (for live hit marking)
    private readonly HashSet<ulong> _pendingCoveragePoints = [];   // static VAs to hit-trace; armed with coverage bps on each Run
    private bool _findTraceArmed;                       // coverage bps for the Find matches are currently live on the engine
    private bool _findHitsOnly;                         // Find list is filtered to only the hit matches
    private int _findShownHits;                         // hit count last reflected in the filtered view (to refresh only on change)
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
            // Build after the ElementName-bound chip Tags have resolved (not yet in the ctor).
            BuildSideAccordionMap();
            SyncAccordionToSelection();
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
        Linear.OpenInGraphRequested += OpenGraphTab;
        Linear.OpenInDecompilerRequested += va => { OpenDecompiler(va); CenterTabs.SelectedIndex = 3; };
        Linear.PatchRequested += OnPatchInstruction;
        Linear.RenameRequested += OnRename;
        Linear.CommentRequested += OnSetComment;
        Linear.BookmarkToggleRequested += OnToggleBookmark;
        Linear.CreateFunctionRequested += OnCreateFunction;
        Linear.IsFunctionStart = va => _result?.FunctionByVa.ContainsKey(va) == true;
        // Bookmarks are static-VA markup; show them even while the live view is up (read-only). `va - LiveSlide`
        // maps the shown (possibly live) address back to static space, where the session markup is keyed.
        Linear.IsBookmarkAt = va => _markup.Bookmarks.Contains(va - LiveSlide);
        Hex.Edited += OnHexEdited;
        Hex.RenameRequested += OnRename;
        Hex.CommentRequested += OnSetComment;
        Hex.BookmarkToggleRequested += OnToggleBookmark;
        Hex.SelectionChanged += OnHexFocused;                 // click / drag / keyboard → status + xrefs
        Hex.NavigateRequested += va => _nav.Navigate(va);     // double-click → jump every view
        Hex.FindRequested += HexFind;                         // right-click → Find… (mirrors Ctrl+F)
        Hex.FindNextRequested += () => HexFindAgain(prev: false);
        Hex.FindPreviousRequested += () => HexFindAgain(prev: true);
        Hex.MemoryBreakpointRequested += OnMemoryBreakpointRequested;   // right-click → data breakpoint on selection
        // Memory Map strip: click a block → select its table row and navigate every view (gaps don't navigate).
        MemMapStrip.RegionActivated += i =>
        {
            MemMapGrid.SelectedIndex = i;                      // fires OnMemMapGridSelected → syncs the strip highlight
            if (MemMapGrid.SelectedItem is not null) MemMapGrid.ScrollIntoView(MemMapGrid.SelectedItem);
            if (MemMapGrid.SelectedItem is MemoryMapItem m && !m.IsGap) _nav.Navigate(m.Va);
        };
        Graph.BlockSelected += va => _nav.Navigate(va);
        Graph.NavigateRequested += va => _nav.Navigate(va);   // double-click / Enter on a call → follow to the callee
        Graph.RenameRequested += OnRename;
        Graph.CommentRequested += OnSetComment;
        Graph.BookmarkToggleRequested += OnToggleBookmark;
        // "Toggle jump" (shared by the linear, graph and decompiler panes): flips the deciding CPU flags on the
        // current-IP jump while debugging, else a static what-if; JumpMark tells each view how to colour the
        // jump's line (green/red). All three share one handler and one mark set, keyed by VA, so a toggle from
        // any pane shows in all of them — the decompiler colours the branch/if/while line carrying that Jcc's VA.
        Linear.ToggleJumpRequested += OnToggleJump;
        Graph.ToggleJumpRequested += OnToggleJump;
        Decompiler.ToggleJumpRequested += OnToggleJump;
        Linear.JumpMark = JumpMarkAt;
        Graph.JumpMark = JumpMarkAt;
        Decompiler.JumpMark = JumpMarkAt;
        Decompiler.NavigateRequested += va => _nav.Navigate(va);
        Decompiler.SelectionChanged += OnDecompilerFocused;
        Decompiler.RenameRequested += OnRename;
        Decompiler.CommentRequested += OnSetComment;
        Decompiler.BookmarkToggleRequested += OnToggleBookmark;
        CallGraphPanel.NavigateRequested += va => _nav.Navigate(va);
        CallGraphPanel.CurrentVa = () => _nav.Current ?? 0;   // for the panel's "⌖ Here" / Follow re-rooting
        Linear.ShowInCallGraphRequested += ShowInCallGraph;
        Linear.EmulateFunctionRequested += OnEmulateFunction;
        Decompiler.EmulateFunctionRequested += OnEmulateFunction;
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
        // The decompiler (all IL levels + pseudo-C) shares the SAME breakpoint/trace state and handlers as the
        // linear view — assign the same delegate instances — so breakpoints, the trace tint and run-control work
        // from the decompiler tab and stay in lockstep with the listing. Each pseudo-C/IL line acts on its source
        // instruction's VA (DecompLine.Va), translated by the handlers via LiveSlide exactly like the listing.
        Decompiler.BreakpointToggleRequested += OnBreakpointToggle;
        Decompiler.HardwareBreakpointRequested += OnHardwareBreakpointRequest;
        Decompiler.EditBreakpointRequested += OnEditBreakpointRequest;
        Decompiler.RunToCursorRequested += va => _dbg?.RunToCursor(va);
        Decompiler.RunToReturnRequested += () => OnRunToReturn(this, new RoutedEventArgs());
        Decompiler.CaptureFunctionRequested += CaptureFunctionAt;
        Decompiler.IsBreakpointAt = Linear.IsBreakpointAt;
        Decompiler.IsHardwareBreakpointAt = Linear.IsHardwareBreakpointAt;
        Decompiler.IsInstrHit = Linear.IsInstrHit;
        // Managed (.NET) source-level breakpoints: toggle from the C# view, navigate the call stack.
        Managed.BreakpointToggleRequested += OnManagedBreakpointToggle;
        ManagedDebug.FrameActivated += OnManagedFrameActivated;
        Linear.RunToCursorRequested += va => _dbg?.RunToCursor(va);
        Linear.RunToReturnRequested += () => OnRunToReturn(this, new RoutedEventArgs());
        Linear.CaptureFunctionRequested += CaptureFunctionAt;
        Linear.StatusRequested += msg => StatusText.Text = msg;
        Debug.NavigateRequested += va => _nav.Navigate(va);
        Debug.MemoryBreakpointRequested += OnMemoryBreakpointRequested;   // Memory tab right-click → data breakpoint
        PreviewKeyDown += OnWindowPreviewKeyDown;
        PreviewMouseDown += OnWindowMouseDown;
    }

    // Mouse back/forward thumb buttons walk the address history, like a browser.
    private void OnWindowMouseDown(object sender, MouseButtonEventArgs e)
    {
        if (e.ChangedButton == MouseButton.XButton1) { _nav.Back(); e.Handled = true; }
        else if (e.ChangedButton == MouseButton.XButton2) { _nav.Forward(); e.Handled = true; }
    }

    // The app runs elevated (requireAdministrator); WPF's OLE drag-and-drop can't receive files from a
    // normal-integrity Explorer (UIPI blocks it). Use the native shell path (WM_DROPFILES) instead, which works
    // across integrity levels via the ChangeWindowMessageFilterEx allow-list in NativeFileDrop. Wired at Loaded so
    // any OLE IDropTarget WPF may have registered already exists and can be revoked — otherwise it would swallow
    // WM_DROPFILES and neither path would work once elevated. No AllowDrop is set anywhere in this window.
    private void EnableFileDrop() => Loaded += (_, _) => EnableNativeFileDrop();

    private bool _nativeDropReady;
    private void EnableNativeFileDrop()
    {
        if (_nativeDropReady || PresentationSource.FromVisual(this) is not HwndSource source) return;
        _nativeDropReady = true;
        IntPtr hwnd = source.Handle;
        NativeFileDrop.Enable(hwnd);
        source.AddHook(OnNativeMessage);
        // A default-AllowDrop TextBox realized later (e.g. a side-tab's filter box on first view) can make WPF
        // re-register an OLE drop target on our hwnd, which would swallow WM_DROPFILES. Re-assert (revoke + accept)
        // on each activation — it's cheap and idempotent — so the native drop path stays live.
        Activated += (_, _) => NativeFileDrop.Enable(hwnd);
    }

    private IntPtr OnNativeMessage(IntPtr hwnd, int msg, IntPtr wParam, IntPtr lParam, ref bool handled)
    {
        if (msg != NativeFileDrop.WmDropFiles) return IntPtr.Zero;

        handled = true;
        if (NativeFileDrop.TryGetFirstFile(wParam, out var path))
            _ = OpenDroppedFile(path);
        return IntPtr.Zero;
    }

    private static class NativeFileDrop
    {
        public const int WmDropFiles = 0x0233;
        private const uint WmCopyData = 0x004A;
        private const uint WmCopyGlobalData = 0x0049;
        private const uint MsgfltAllow = 1;

        public static void Enable(IntPtr hwnd)
        {
            _ = RevokeDragDrop(hwnd);   // drop any WPF OLE IDropTarget so the shell delivers WM_DROPFILES to us instead
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

        [DllImport("ole32.dll")]
        private static extern int RevokeDragDrop(IntPtr hwnd);
    }

    private void OnWindowPreviewKeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Z && (Keyboard.Modifiers & ModifierKeys.Control) != 0
            && Keyboard.FocusedElement is not TextBox)   // let text fields keep their own undo
        {
            UndoLastEdit();
            e.Handled = true;
            return;
        }
        // Alt+Left / Alt+Right walk the address history like a browser. (With Alt held, the real key is in SystemKey.)
        // Require Alt alone, and stay out of the way of text fields (e.g. the address / filter / search boxes).
        Key key = e.Key == Key.System ? e.SystemKey : e.Key;
        if (Keyboard.Modifiers == ModifierKeys.Alt && key is Key.Left or Key.Right
            && Keyboard.FocusedElement is not TextBox)
        {
            if (key == Key.Left) _nav.Back(); else _nav.Forward();
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
            case Key.F when ctrl:
                // Context-aware: on the Hex tab, Ctrl+F finds bytes; elsewhere it opens the instruction Find tab.
                if (CenterTabs.SelectedIndex == 2 && _image is not null) HexFind();
                else { SideTabs.SelectedItem = FindTab; FindInsnBox.Focus(); }
                e.Handled = true; break;
            case Key.F3 when CenterTabs.SelectedIndex == 2 && _image is not null:
                HexFindAgain(prev: shift); e.Handled = true; break;   // Shift+F3 = previous
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

    /// <summary>The decoder to lift/emulate/export with: the live one while the view shows a running process
    /// (reads its memory), else null so the default file-backed decoder is used. Same rule as the decompiler view.</summary>
    private IInstructionDecoder? AnalysisDecoder => _dbgViewLive ? _dbg?.LiveDecoder : null;

    // F2 / gutter / context-menu breakpoint toggle. While the listing shows live (rebased) addresses the
    // engine is the source of truth; otherwise the address is a static VA we stash in the pre-run set. Either
    // way the static set is kept in sync, so breakpoints survive across Run / Restart and stay shown after exit.
    private void OnBreakpointToggle(ulong va)
    {
        // A software memory (range) breakpoint isn't a single-VA int3 — remove it through its own engine path
        // (the Delete key / gutter toggle both route here). Keyed by static VA like the rest of the set.
        ulong memSva = va - LiveSlide;
        if (_pendingBreakpoints.TryGetValue(memSva, out var memDef) && memDef.Memory)
        {
            _pendingBreakpoints.Remove(memSva);
            if (_dbgViewLive && _dbg is { } dm) dm.Engine.RemoveMemoryBreakpoint(va);
            Linear.Refresh();
            Graph.Refresh();
            Decompiler.Refresh();
            Debug.Refresh();
            RefreshBreakpointList();
            return;
        }
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
        Decompiler.Refresh();
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
        Decompiler.Refresh();
        Debug.Refresh();
        RefreshBreakpointList();
    }

    /// <summary>Set a software memory (data) breakpoint over the highlighted byte range in a hex view — break on
    /// read / write / either. Records it in the pre-run set (keyed by static VA, so it survives Run/Restart for a
    /// module address) and, if a session is live, arms it on the process now via page protection.</summary>
    private void OnMemoryBreakpointRequested((ulong Lo, ulong Hi, MemAccess Access) w)
    {
        ulong start = w.Lo, len = w.Hi - w.Lo + 1;
        ulong sva = start - LiveSlide;
        var def = _pendingBreakpoints.TryGetValue(sva, out var existing) ? existing : new BpDef();
        def.Memory = true; def.Hardware = false; def.MemAccess = w.Access; def.MemLength = (int)len;
        _pendingBreakpoints[sva] = def;
        if (_dbgViewLive && _dbg is { } d)
            d.Engine.SetMemoryBreakpoint(start, len, w.Access);
        Linear.Refresh();
        Graph.Refresh();
        Decompiler.Refresh();
        Debug.Refresh();
        RefreshBreakpointList();
        StatusText.Text = $"Memory breakpoint ({w.Access}) at {start:X}..{w.Hi:X}  ({len} bytes)"
            + (_dbgViewLive ? "" : " — will arm on run");
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
        Decompiler.Refresh();
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
            if (def.Memory)   // software memory (range) breakpoint — page protection, no int3 / condition
            {
                if (def.Enabled) _dbg.Engine.SetMemoryBreakpoint(va, (ulong)def.MemLength, def.MemAccess);
                continue;
            }
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
                return new BreakpointItem(va, label, kv.Value.Enabled);
            })
            .ToList();
    }

    private void NavigateToBreakpoint()
    {
        if (BreakpointList.SelectedItem is not BreakpointItem b) return;
        CenterTabs.SelectedIndex = 0;   // ensure the linear view is the one shown
        _nav.Navigate(b.Va);
    }

    // ---- interactive markup: rename / comment / bookmark (persisted in the .dsproj) ----

    /// <summary>Rename the symbol at <paramref name="va"/> (blank resets it to the machine name).</summary>
    private void OnRename(ulong va)
    {
        if (_result is null || va == 0) return;
        string current = _result.NameFor(va) ?? "";
        string? name = Dialogs.AskText(this, "Rename symbol", $"New name for {va:X} (blank to reset):", current);
        if (name is null) return;   // cancelled
        _result.SetName(va, name);   // update the displayed result (static or live) immediately
        MirrorToStaticMarkup(m => { ulong sva = va - LiveSlide; if (name.Length == 0) m.Names.Remove(sva); else m.Names[sva] = name; });
        RefreshAfterMarkup(namesChanged: true);
        StatusText.Text = name.Length == 0 ? $"Reset name at {va - LiveSlide:X}" : $"Renamed {va - LiveSlide:X} → {name}";
    }

    /// <summary>Set (or, when blank, clear) an inline comment at <paramref name="va"/>.</summary>
    private void OnSetComment(ulong va)
    {
        if (_result is null || va == 0) return;
        string current = _result.Comments.TryGetValue(va, out var c) ? c : "";
        string? text = Dialogs.AskText(this, "Set comment", $"Comment at {va:X} (blank to clear):", current, multiline: true);
        if (text is null) return;
        _result.SetComment(va, text);
        MirrorToStaticMarkup(m => { ulong sva = va - LiveSlide; if (text.Length == 0) m.Comments.Remove(sva); else m.Comments[sva] = text; });
        RefreshAfterMarkup(namesChanged: false);
        StatusText.Text = text.Length == 0 ? $"Cleared comment at {va - LiveSlide:X}" : $"Commented {va - LiveSlide:X}";
    }

    /// <summary>Toggle a bookmark at <paramref name="va"/> (keyed in static space so it persists across runs).</summary>
    private void OnToggleBookmark(ulong va)
    {
        if (va == 0) return;
        ulong sva = va - LiveSlide;
        bool now = _markup.Bookmarks.Add(sva) || !_markup.Bookmarks.Remove(sva);
        RefreshBookmarkList();
        Linear.Refresh();
        Graph.Refresh();
        StatusText.Text = now ? $"Bookmarked {sva:X}" : $"Removed bookmark {sva:X}";
    }

    /// <summary>Colour the linear + graph views use for a jump's line: true = green (goes / assumed taken), false =
    /// red (falls through / assumed not-taken), null = untoggled (blue). The current-IP jump is coloured from the
    /// real live flags; every other jump from its static what-if assumption.</summary>
    private bool? JumpMarkAt(ulong va)
    {
        if (_curJump is { } cj && cj.Va == va) return cj.Taken;                 // real flags win at the current IP
        return _jumpAssume.TryGetValue(va - LiveSlide, out var v) ? v : (bool?)null;
    }

    /// <summary>Re-evaluate, from the real live flags, whether the conditional jump at the current IP will be taken,
    /// and cache it for the branch colouring. Cleared unless we're stopped on a flag-based Jcc.</summary>
    private void RecomputeCurrentJump()
    {
        _curJump = null;
        if (_dbg is not { IsStopped: true } || _dbg.LiveDecoder is not { } dec) return;
        if (!dec.TryDecodeAt(_dbg.CurrentIp, out var i) || !JccEval.CanToggle(i.ConditionCode)) return;
        if (_dbg.Engine.GetRegisters() is not { } regs) return;
        ulong fl = regs[regs.Is32 ? "eflags" : "rflags"];
        if (JccEval.Evaluate(i.ConditionCode, fl) is bool taken) _curJump = (_dbg.CurrentIp, taken);
    }

    /// <summary>"Toggle jump": send a conditional jump the other way. Stopped on that jump in the debugger it flips
    /// the real EFLAGS bit(s) that decide it (so the debuggee actually takes the other path); anywhere else it flips
    /// a static what-if assumption. Either way the branch line recolours green (taken) / red (not-taken).</summary>
    private void OnToggleJump(ulong va)
    {
        if (va == 0) return;
        // Real flag flip — only valid on the instruction we're stopped at (the one whose flags are live).
        if (_dbg is { IsStopped: true } && va == _dbg.CurrentIp && _dbg.LiveDecoder is { } dec
            && dec.TryDecodeAt(va, out var i) && JccEval.CanToggle(i.ConditionCode)
            && _dbg.Engine.GetRegisters() is { } regs)
        {
            string fn = regs.Is32 ? "eflags" : "rflags";
            _dbg.Engine.SetRegister(fn, JccEval.FlipToInvert(i.ConditionCode, regs[fn]));
            RecomputeCurrentJump();                                        // recolour from the new real flags
            Linear.Refresh(); Graph.Refresh(); Decompiler.Refresh(); Debug.Refresh();   // Debug.Refresh so the flags grid updates too
            StatusText.Text = $"Flipped {JccEval.FlipDescription(i.ConditionCode)} — jump @ {va:X} {(_curJump?.Taken == true ? "will be taken" : "falls through")}";
            return;
        }
        // Static what-if: flip this jump's assumed direction (first toggle → taken/green).
        ulong sva = va - LiveSlide;
        bool taken = _jumpAssume.TryGetValue(sva, out var cur) ? !cur : true;
        _jumpAssume[sva] = taken;
        Linear.Refresh(); Graph.Refresh(); Decompiler.Refresh();
        StatusText.Text = $"Jump {sva:X} assumed {(taken ? "taken (green)" : "not taken (red)")}";
    }

    /// <summary>"Create function here": register the caret address as a function start so an isolated block can
    /// be listed, navigated and decompiled (its CFG/extent is discovered lazily on view). Persisted in the
    /// session markup (survives reload / re-analysis via <see cref="AnalysisResult.UseMarkup"/>) and pushed on
    /// the undo stack so Ctrl+Z / ↶ Undo removes it. Then opens the decompiler on the new function.</summary>
    private void OnCreateFunction(ulong va)
    {
        if (_result is null || va == 0) return;
        if (_result.FunctionByVa.ContainsKey(va)) { StatusText.Text = $"{va - LiveSlide:X} is already a function"; return; }
        var (fn, addedName) = _result.AddFunction(va);
        ulong sva = va - LiveSlide;                                     // markup is keyed in static space (like bookmarks)
        _markup.Functions.Add(sva);
        _funcStarts = _result.Functions.Select(f => f.Va).ToArray();    // AddFunction inserts sorted, so this stays ordered
        RefreshAfterMarkup(namesChanged: true);                        // rebuild label lines, function rows, search index, decompiler cache
        _changeStack.Push(new CreateFunctionEdit(sva, addedName));
        UpdatePatchButtons();
        _nav.Navigate(va);                                             // caret to the new function header
        // Show its pseudo-C — except 8051, which has no decompiler path (OpenDecompiler would just show a notice).
        if (_result.Image.Is8051 != true) { OpenDecompiler(va); CenterTabs.SelectedIndex = 3; }
        StatusText.Text = $"Created function {fn.Name}";
    }

    /// <summary>When editing while the live view is up, mirror the edit into the session (static) markup so it
    /// persists — the displayed live result carries its own overlay. When not debugging the displayed result IS
    /// bound to the session markup, so no mirroring is needed.</summary>
    private void MirrorToStaticMarkup(Action<Markup> edit) { if (_dbgViewLive) edit(_markup); }

    /// <summary>Repaint/rebuild every pane that bakes names or comments into its content after a markup edit.</summary>
    private void RefreshAfterMarkup(bool namesChanged)
    {
        Linear.RefreshAfterPatch();     // rebuild label lines (new/changed names) + repaint; also shows comments
        Graph.Rebuild();                // operand names/comments are baked into the block tokens → rebuild
        Decompiler.InvalidateCache();   // emitted lines baked in the old names/comments → re-render current fn
        if (namesChanged && _result is not null)
        {
            RefreshFunctionRows();      // the function list shows Function.Name snapshots
            BuildSearchIndex(_result);  // search index text includes function names
        }
    }

    /// <summary>Rebuild just the Functions list rows (FunctionItem snapshots the name, so an in-place rename
    /// needs fresh rows). Mirrors the function/import portion of <see cref="PopulateLists"/>.</summary>
    private void RefreshFunctionRows()
    {
        if (_result is null) return;
        var funcRows = _result.Functions.Select(f => new FunctionItem(f, _result.Image.SectionAt(f.Va)?.Name ?? ""));
        var importRows = _result.Image.Imports.Select(i =>
            new FunctionItem(i.IatVa, Demangler.Demangle(i.Name), _result.Image.SectionAt(i.IatVa)?.Name ?? ""));
        _functions = new ObservableCollection<FunctionItem>(funcRows.Concat(importRows).OrderBy(x => x.Va));
        _functionsView = CollectionViewSource.GetDefaultView(_functions);
        _functionsView.Filter = FuncFilterPredicate;
        FuncList.ItemsSource = _functionsView;
    }

    /// <summary>Rebuild the Bookmarks side list from the session markup, resolving each address to its name.</summary>
    private void RefreshBookmarkList()
    {
        if (BookmarkList is null) return;   // not yet built (called during construction)
        ulong slide = LiveSlide;
        var names = _dbgViewLive ? _dbg?.LiveResult : _result;
        BookmarkList.ItemsSource = _markup.Bookmarks
            .OrderBy(v => v)
            .Select(sva =>
            {
                ulong va = sva + slide;
                string name = names?.NameFor(va) ?? "";
                string cmt = _markup.Comments.TryGetValue(sva, out var c) ? c : "";
                string label = name.Length > 0 && cmt.Length > 0 ? $"{name}   ; {cmt}" : name.Length > 0 ? name : cmt;
                return new BookmarkItem(va, label);
            })
            .ToList();
    }

    private void NavigateToBookmark()
    {
        if (BookmarkList.SelectedItem is not BookmarkItem b) return;
        CenterTabs.SelectedIndex = 0;   // ensure the linear view is the one shown
        _nav.Navigate(b.Va);
    }

    private void OnBookmarkActivate(object sender, MouseButtonEventArgs e) => NavigateToBookmark();
    private void OnBookmarkJump(object sender, RoutedEventArgs e) => NavigateToBookmark();
    private void OnBookmarkRemove(object sender, RoutedEventArgs e) { if (BookmarkList.SelectedItem is BookmarkItem b) OnToggleBookmark(b.Va); }
    private void OnBookmarkListKey(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Delete && BookmarkList.SelectedItem is BookmarkItem b) { OnToggleBookmark(b.Va); e.Handled = true; }
    }

    // ---- IL emulator (deobfuscation): resolve constants / decrypt data / fold opaque predicates ----

    private async void OnEmulateFunction(ulong va)
    {
        if (_result is null) return;
        if (_result.Image.IsArm || _result.Image.Is8051)
        {
            MessageBox.Show(this, "Emulation currently supports x86/x64 functions only.", "Emulate", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        var fn = FindFunction(va);
        if (fn is null) { StatusText.Text = "No function at that address to emulate."; return; }

        StatusText.Text = $"Emulating {fn.Name}…";
        var result = _result;
        var decoder = AnalysisDecoder;   // read process memory when emulating a running function
        EmulationResult er;
        try { er = await Task.Run(() => DisasmStudio.Core.IL.Decompiler.Emulate(fn, result, decoder: decoder)); }
        catch (Exception ex) { StatusText.Text = "Emulation failed: " + ex.Message; return; }
        if (!ReferenceEquals(_result, result)) return;   // the image changed while emulating

        StatusText.Text = $"Emulation {er.Status}: {er.Values.Count} value(s), {er.Branches.Count} branch(es), {er.MemoryWrites.Count} decrypted byte(s).";
        var dlg = new EmulationDialog(this, fn.Name, er, v => _result?.NameFor(v),
            onNavigate: v => { CenterTabs.SelectedIndex = 0; _nav.Navigate(v); },
            onApplyComments: () => ApplyEmulationComments(er),
            onApplyPatch: () => ApplyEmulationPatch(er));
        dlg.Show();
    }

    /// <summary>Attach the emulator's resolved constants and folded predicates as inline comments (via the
    /// Phase-A markup overlay, so they persist and show in every pane).</summary>
    private void ApplyEmulationComments(EmulationResult er)
    {
        if (_result is null) return;
        void Set(ulong v, string text) { _result!.SetComment(v, text); MirrorToStaticMarkup(m => m.Comments[v - LiveSlide] = text); }
        foreach (var v in er.Values.Values) Set(v.Va, $"= 0x{(ulong)v.Value:X} (emulated)");
        foreach (var b in er.Branches.DistinctBy(b => b.Va))
            Set(b.Va, b.Taken ? "opaque: always taken (emulated)" : "opaque: never taken (emulated)");
        RefreshAfterMarkup(namesChanged: false);
        StatusText.Text = "Applied emulation results as comments.";
    }

    /// <summary>Write the emulator's decrypted bytes back into the image (as file-offset patches, undoable via
    /// the change stack) and re-analyze so the decrypted strings surface in the Strings list.</summary>
    private async void ApplyEmulationPatch(EmulationResult er)
    {
        if (_result is null || _image is null || er.MemoryWrites.Count == 0) return;
        int patched = 0;
        foreach (var (start, bytes) in ContiguousRuns(er.MemoryWrites))
            if (_image.PatchVa(start, bytes)) { _changeStack.Push(new ByteEdit(start, start + (ulong)bytes.Length, false)); patched += bytes.Length; }
        UpdatePatchButtons();
        StatusText.Text = $"Patched {patched:N0} decrypted byte(s); re-analyzing to surface decrypted strings…";
        await StartAnalysis(_image, _nav.Current, CenterTabs.SelectedIndex, fresh: false);
    }

    /// <summary>Group sorted written bytes into maximal contiguous [start, bytes] runs for patching.</summary>
    private static List<(ulong Start, byte[] Bytes)> ContiguousRuns(SortedDictionary<ulong, byte> writes)
    {
        var runs = new List<(ulong, byte[])>();
        List<byte>? cur = null;
        ulong start = 0, prev = 0;
        foreach (var (addr, b) in writes)
        {
            if (cur is null || addr != prev + 1) { if (cur is not null) runs.Add((start, cur.ToArray())); cur = []; start = addr; }
            cur.Add(b);
            prev = addr;
        }
        if (cur is not null) runs.Add((start, cur.ToArray()));
        return runs;
    }

    // ---- library-function signatures (FLIRT/FID-lite) ----

    /// <summary>Write masked prologue signatures for this binary's named functions to a .sig file (default:
    /// the auto-scanned <c>signatures/</c> folder). Opening another binary then auto-names matching functions.</summary>
    private void OnGenerateSignatures(object sender, RoutedEventArgs e)
    {
        if (_result is null) { MessageBox.Show(this, "Open a binary first.", "Generate signatures", MessageBoxButton.OK, MessageBoxImage.Information); return; }
        var sigs = SignatureMatcher.Generate(_result);
        if (sigs.Count == 0)
        {
            MessageBox.Show(this, "No named functions to generate signatures from. Rename some functions (N), or open a binary with symbols/exports, first.\n\n(ARM/8051 images aren't supported.)",
                "Generate signatures", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        try { Directory.CreateDirectory(SignatureLibrary.DefaultDirectory); } catch { }
        var dlg = new SaveFileDialog
        {
            Title = "Save signatures",
            Filter = "Signature file|*.sig",
            InitialDirectory = Directory.Exists(SignatureLibrary.DefaultDirectory) ? SignatureLibrary.DefaultDirectory : null,
            FileName = ExportBaseName() + ".sig",
        };
        if (dlg.ShowDialog(this) != true) return;
        try
        {
            var lines = new List<string> { $"# {sigs.Count} signatures generated from {Path.GetFileName(_result.Image.FilePath)} ({_result.Image.ArchName})" };
            lines.AddRange(sigs.Select(s => s.Serialize()));
            File.WriteAllLines(dlg.FileName, lines);
        }
        catch (Exception ex) { MessageBox.Show(this, ex.Message, "Generate signatures failed", MessageBoxButton.OK, MessageBoxImage.Warning); return; }
        SignatureLibrary.Reload();   // pick up the new file for the next binary opened
        bool inFolder = string.Equals(Path.GetDirectoryName(Path.GetFullPath(dlg.FileName)),
            Path.GetFullPath(SignatureLibrary.DefaultDirectory), StringComparison.OrdinalIgnoreCase);
        StatusText.Text = $"Wrote {sigs.Count:N0} signatures to {dlg.FileName}." +
            (inFolder ? " They'll auto-name matching functions in binaries you open next." : " Move it into the 'signatures' folder to auto-apply it.");
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
        if (e.Source is not TabControl tc) return;
        if (tc.SelectedItem is TabItem { Header: "Strings" }) RefreshLiveStrings();
        else if (tc.SelectedItem is TabItem { Header: "Call Graph" }) EnsureCallGraph();
        else if (tc.SelectedItem is TabItem { Header: "Entropy" }) EnsureEntropy();
        SyncAccordionToSelection();
    }

    // ---- Right-side accordion navigator ----
    // The side panels live in a header-less TabControl (SideTabs); navigation is driven by chip
    // RadioButtons grouped under collapsible Expander groups. Each TabItem maps to its (group, chip)
    // so we can drive selection either way. _syncingAccordion breaks the chip<->tab feedback loop.
    private readonly Dictionary<TabItem, (Expander Group, RadioButton Chip)> _sidePanels = new();
    private bool _syncingAccordion;

    private void BuildSideAccordionMap()
    {
        foreach (var group in new[] { NavGroup, SymGroup, DataGroup, MarksGroup, FormatGroup })
            foreach (var chip in FindChips(group))
                if (chip.Tag is TabItem tab)
                    _sidePanels[tab] = (group, chip);
    }

    private static IEnumerable<RadioButton> FindChips(Expander group)
    {
        if (group.Content is Panel p)
            foreach (var child in p.Children)
                if (child is RadioButton rb) yield return rb;
    }

    /// <summary>A chip was clicked: show its panel. The reverse sync (checking the chip, expanding its
    /// group) is handled by SyncAccordionToSelection when the tab selection changes.</summary>
    private void OnSidePanelChip(object sender, RoutedEventArgs e)
    {
        if (_syncingAccordion) return;
        if (sender is RadioButton { Tag: TabItem tab }) SideTabs.SelectedItem = tab;
    }

    /// <summary>Reflect the currently-selected side tab into the accordion: check its chip and expand
    /// its group (collapsing the others), so programmatic jumps (Xrefs, Find, Call Graph…) stay in sync.</summary>
    private void SyncAccordionToSelection()
    {
        if (_syncingAccordion) return;
        if (SideTabs.SelectedItem is not TabItem tab || !_sidePanels.TryGetValue(tab, out var map)) return;
        _syncingAccordion = true;
        try
        {
            map.Chip.IsChecked = true;
            ExpandOnly(map.Group);
        }
        finally { _syncingAccordion = false; }
    }

    /// <summary>Accordion rule: expanding a group collapses the others and selects one of its panels
    /// (unless the active panel already belongs to it), so exactly one group is open at a time.</summary>
    private void OnGroupExpanded(object sender, RoutedEventArgs e)
    {
        // NavGroup's IsExpanded="True" fires this during XAML load, before the other group fields are
        // assigned — the map is built later (in Loaded, once chip Tag bindings resolve), so an empty
        // map means "not ready yet".
        if (_syncingAccordion || _sidePanels.Count == 0 || sender is not Expander group) return;
        ExpandOnly(group);
        // If the active panel is already in this group, keep it; otherwise activate the group's first
        // visible chip so the content matches the newly-opened group.
        if (SideTabs.SelectedItem is TabItem sel && _sidePanels.TryGetValue(sel, out var m) && ReferenceEquals(m.Group, group))
            return;
        foreach (var chip in FindChips(group))
            if (chip.Visibility == Visibility.Visible && chip.Tag is TabItem tab)
            {
                SideTabs.SelectedItem = tab;   // fires OnSideTabChanged → SyncAccordionToSelection checks the chip
                break;
            }
    }

    private void ExpandOnly(Expander open)
    {
        foreach (var group in new[] { NavGroup, SymGroup, DataGroup, MarksGroup, FormatGroup })
            group.IsExpanded = ReferenceEquals(group, open);
    }

    /// <summary>Show/hide the contextual FORMAT chips (.NET, Obj-C) to mirror their TabItem visibility,
    /// and hide the whole FORMAT group when neither applies. Called wherever DotNetTab/ObjCTab
    /// visibility changes (file load, managed probe, Mach-O Obj-C probe).</summary>
    private void RefreshFormatChips()
    {
        DotNetChip.Visibility = DotNetTab.Visibility;
        ObjCChip.Visibility = ObjCTab.Visibility;
        bool any = DotNetTab.Visibility == Visibility.Visible || ObjCTab.Visibility == Visibility.Visible;
        FormatGroup.Visibility = any ? Visibility.Visible : Visibility.Collapsed;
        if (!any && FormatGroup.IsExpanded) NavGroup.IsExpanded = true;   // don't leave an empty group open
    }

    private bool CallGraphTabVisible => SideTabs.SelectedItem is TabItem { Header: "Call Graph" };

    /// <summary>Build the whole-program call graph on first view (it iterates every call xref, so it's built
    /// lazily rather than on every analysis) and hand it to the panel. Attaching is idempotent, so re-selecting
    /// the tab preserves the current root; when Follow is on it re-roots at the address you're viewing.</summary>
    private void EnsureCallGraph()
    {
        if (_result is null) return;
        _callGraph ??= CallGraph.Build(_result);
        CallGraphPanel.Attach(_result, _callGraph);
        if (CallGraphPanel.Follow && _nav.Current is ulong cur) CallGraphPanel.SetRoot(cur);
    }

    /// <summary>Compute the file's byte-entropy on first view of the Entropy tab (a whole-file scan, so it's
    /// built lazily off the UI thread, not on every load) and hand it to the graph + per-section table. Cached
    /// per file; the generation guard drops a result whose file was swapped out while it was still computing.</summary>
    private async void EnsureEntropy()
    {
        if (_result is null || _entropy is not null) return;
        var img = _result.Image;
        int gen = ++_entropyGen;
        EntropyGraph.SetData(null);
        EntropySectionGrid.ItemsSource = null;
        EntropyHeader.Text = "Computing entropy…";
        try
        {
            var data = await Task.Run(() => EntropyData.Build(img));
            if (gen != _entropyGen) return;   // a different file was loaded while we were computing — discard
            _entropy = data;
            EntropyGraph.SetData(data);
            EntropySectionGrid.ItemsSource = data.Sections;
            EntropyHeader.Text =
                $"File entropy: {data.Overall:F2} bits/byte  ·  0–8 across file offset; high (≈8) = compressed / encrypted / packed. Hover the graph for offset + value.";
        }
        catch (Exception ex)
        {
            if (gen == _entropyGen) EntropyHeader.Text = $"Entropy unavailable: {ex.Message}";
        }
    }

    /// <summary>Root the call graph at the function containing <paramref name="va"/> and switch to its tab.
    /// Select the tab first (that builds/attaches the graph), then set the root so it isn't reset by the switch.</summary>
    private void ShowInCallGraph(ulong va)
    {
        foreach (var it in SideTabs.Items)
            if (it is TabItem { Header: "Call Graph" } tab) { SideTabs.SelectedItem = tab; break; }
        EnsureCallGraph();               // no-op build if the tab-switch already did it
        CallGraphPanel.SetRoot(va);      // final root wins
    }

    private void OnBreakpointActivate(object sender, MouseButtonEventArgs e) => NavigateToBreakpoint();
    private void OnBreakpointJump(object sender, RoutedEventArgs e) => NavigateToBreakpoint();
    private void OnBreakpointRemove(object sender, RoutedEventArgs e) { if (BreakpointList.SelectedItem is BreakpointItem b) OnBreakpointToggle(b.Va); }
    private void OnBreakpointEditMenu(object sender, RoutedEventArgs e) { if (BreakpointList.SelectedItem is BreakpointItem b) OnEditBreakpointRequest(b.Va); }
    private void OnBreakpointListKey(object sender, KeyEventArgs e) { if (e.Key == Key.Delete && BreakpointList.SelectedItem is BreakpointItem b) { OnBreakpointToggle(b.Va); e.Handled = true; } }

    /// <summary>Tick-box in the Breakpoints list → enable / disable the breakpoint (kept in the set, not armed when
    /// off).</summary>
    private void OnBreakpointEnabledToggle(object sender, RoutedEventArgs e)
    {
        if (sender is CheckBox cb && cb.DataContext is BreakpointItem b) SetBreakpointEnabled(b.Va, cb.IsChecked == true);
    }

    /// <summary>Context-menu "Enable / disable" → flip the selected breakpoint's enabled state.</summary>
    private void OnBreakpointToggleEnabledMenu(object sender, RoutedEventArgs e)
    {
        if (BreakpointList.SelectedItem is BreakpointItem b) ToggleBreakpointEnabled(b.Va);
    }

    /// <summary>Flip the enabled state of the breakpoint at <paramref name="va"/> — from the Breakpoints list's
    /// context-menu "Enable / disable".</summary>
    private void ToggleBreakpointEnabled(ulong va)
    {
        if (_pendingBreakpoints.TryGetValue(va - LiveSlide, out var def)) SetBreakpointEnabled(va, !def.Enabled);
    }

    /// <summary>Enable / disable the breakpoint at <paramref name="va"/> (a live VA while debugging, else static)
    /// without removing it: flips <see cref="BpDef.Enabled"/> so it persists / re-arms next run, and applies the
    /// change to the live engine now — memory (range) bps arm/disarm via page protection, int3 / hardware bps via
    /// <c>ConfigureBreakpoint</c> (ArmAddr / DisarmAddr / Dr reprogram).</summary>
    private void SetBreakpointEnabled(ulong va, bool enabled)
    {
        ulong sva = va - LiveSlide;
        if (!_pendingBreakpoints.TryGetValue(sva, out var def)) return;
        def.Enabled = enabled;
        if (_dbgViewLive && _dbg is { } d)
        {
            if (def.Memory)
            {
                if (enabled) d.Engine.SetMemoryBreakpoint(va, (ulong)def.MemLength, def.MemAccess);
                else d.Engine.RemoveMemoryBreakpoint(va);
            }
            else d.Engine.ConfigureBreakpoint(va, def.Condition, def.HitMode, def.HitTarget, enabled);
        }
        Linear.Refresh();
        Graph.Refresh();
        Decompiler.Refresh();
        Debug.Refresh();
        RefreshBreakpointList();
    }

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
            Decompiler.Refresh();
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
        UpdateFindHits();   // reset the ● hit markers in the Find list too
        Linear.Refresh();
        Graph.Refresh();
        Decompiler.Refresh();
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
            Decompiler.Refresh();
        }
        UpdateFindHits();   // refresh the ● hit markers in the Find list
    }

    private void StartCoverageTimer()
    {
        _coverageTimer ??= new DispatcherTimer(TimeSpan.FromMilliseconds(400), DispatcherPriority.Background,
            (_, _) => { if ((_coverageEnabled || _findTraceArmed) && _dbg is { IsStopped: false }) HarvestCoverage(); }, Dispatcher);
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
        _mdbgFramework = framework;
        _mdbgTargetIsGui = !consoleApp;
        _mdbgNativeOfferDeclined = false;

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
        var top = stop.Frames is { Length: > 0 } fr ? fr[0] : null;
        string where = top is null ? "" : FrameLabel(top);
        string detail = string.IsNullOrEmpty(stop.Message) ? "" : "  " + stop.Message;   // exception "Type: message"
        StatusText.Text = $"⛔ Managed stop ({stop.Reason}){(where.Length > 0 ? "  " + where : "")}{detail}";
        if (_managed is not null) ManagedDebug.Show(stop, FrameLabel);
        if (top is not null) NavigateManagedTo(top);

        // A .NET Framework desktop app (WinForms/WPF) relies on a top-level exception handler that the CLR disables
        // while a MANAGED debugger is attached — so an exception it would normally absorb (often a harmless native
        // SEHException surfaced through a UI control at startup) escapes here as unhandled and the program can't run
        // on. The native (assembly-level) debugger doesn't set Debugger.IsAttached, so the app keeps swallowing it
        // and runs — restoring the pre-2.14 behavior. Offer that for a GUI target (a console target has no such
        // handler, so its unhandled exception is a real crash worth showing).
        if (stop.Reason == Mdbg.ReasonException && _mdbgFramework && _mdbgTargetIsGui && !_mdbgNativeOfferDeclined)
            OfferNativeForFrameworkStartupCrash(stop);
    }

    /// <summary>Label a managed stack frame. A frame in the opened assembly resolves to its C# method name; a frame
    /// in any other module (the BCL / a dependency, for which we have no decompiled model) shows as
    /// <c>module!0xtoken</c> — never a name mis-resolved against the opened assembly's metadata.</summary>
    private string FrameLabel(MdbgFrame f)
    {
        if (_managed is not null && string.Equals(f.Module, OpenedModuleName(), StringComparison.OrdinalIgnoreCase))
            return _managed.MethodName(f.Token);
        return $"{f.Module}!0x{f.Token:X8}";
    }

    private string OpenedModuleName() => _image is not null ? Path.GetFileName(_image.FilePath) : "";

    /// <summary>Show a frame's method (navigating to it in the C# view if it isn't the one shown) and highlight its
    /// line — but only for a frame in the opened assembly; a BCL/dependency frame has no decompiled view, so just
    /// clear the current-line highlight instead of jumping to whatever method shares that token here.</summary>
    private void NavigateManagedTo(MdbgFrame f)
    {
        if (_managed is null || !string.Equals(f.Module, OpenedModuleName(), StringComparison.OrdinalIgnoreCase))
        {
            Managed.SetCurrentLine(-1);
            return;
        }
        if (_managed.FindNode(f.Token) is { } node) Managed.ShowMethodForStop(node, f.Token, f.IlOffset);
        else Managed.ShowStop(f.Token, f.IlOffset);
    }

    /// <summary>A .NET Framework target hit an unhandled exception at startup under the source-level debugger —
    /// the classic "managed debugger disables WinForms' top-level handler" case. Offer to relaunch it under the
    /// native debugger, which runs it (the pre-2.14 flow).</summary>
    private void OfferNativeForFrameworkStartupCrash(MdbgEvent stop)
    {
        if (_image is null) return;
        string prog = OpenedModuleName();
        string what = string.IsNullOrEmpty(stop.Message) ? "an unhandled exception" : stop.Message!;
        var choice = MessageBox.Show(this,
            $"{prog} threw {what} during startup under the source-level (C#) debugger.\n\n" +
            "This is expected for .NET Framework desktop apps (WinForms/WPF): the CLR disables their top-level " +
            "exception handler while a managed debugger is attached, so a startup exception the app would normally " +
            "absorb — often a harmless native SEHException from a UI control — escapes here and stops it. The " +
            "program runs fine outside this debugger.\n\n" +
            "Run it under the native (assembly-level) debugger instead? It launches and runs the program with " +
            "anti-anti-debug (Hide from debugger) enabled so its own anti-debug checks don't stop it; you can " +
            "set assembly-level breakpoints, and the C# decompilation stays available for reading.",
            "Managed debug — .NET Framework app stopped at startup", MessageBoxButton.YesNo, MessageBoxImage.Warning);
        if (choice != MessageBoxResult.Yes) { _mdbgNativeOfferDeclined = true; return; }   // don't nag again this session
        string exe = _image.FilePath;
        EndManagedDebug();
        // This app just tripped an anti-debug check the CLR unmasked (the managed debugger disabled the handler
        // that normally absorbs it) — i.e. it's a protected/anti-debug binary. A plain native launch would trip
        // its NATIVE anti-debug too: e.g. the NtClose "close an invalid handle" trick raises STATUS_INVALID_HANDLE
        // (0xC0000008) only under a debugger and would immediately stop us. Turn on the anti-anti-debug (hide)
        // layer so those checks are neutralized and the program actually runs. Reflect it in the checkbox (which
        // BeginDebug reads) so the state is visible and the user can turn it off for the next run.
        HideDebuggerCheck.IsChecked = true;
        BeginDebug(d => d.Launch(exe));
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
            NavigateManagedTo(frames[index]);
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
            if (_result is not null)
                foreach (var r in recs)
                    if (!r.IsReturn && _captureCommented.Add(r.CalleeVa))
                        { _result.AddMachineComment(r.CalleeVa, FunctionCapture.ArgComment(r, is32)); addedComment = true; }
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
            Decompiler.LiveDecoder = _dbg.LiveDecoder;   // decompile over process memory (the file decoder can't read it)
            Hex.SetImage(_result.Image);
            Hex.WriteByteAt = (va, b) => _dbg?.Engine.WriteMemory(va, [b]) ?? false;   // editable live memory
            CaptureBtn.IsEnabled = true; CaptureFnBtn.IsEnabled = true; OnceCheck.IsEnabled = true; RetCheck.IsEnabled = true; DerefCheck.IsEnabled = true;
            CoverageToggle.IsEnabled = true;   // execution-coverage recording can now be armed
            RestartBtn.IsEnabled = _image is not null;   // a fileless attach has no binary to relaunch
            ApplyPendingBreakpoints();   // arm breakpoints set on the static listing before launch, now that memory exists
            ArmCoverageTrace();          // arm hit-tracing (Find-tab "Trace hits") on the same first stop
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
        RecomputeCurrentJump();   // colour the current conditional jump from the live flags (auto, before any toggle)
        Linear.Refresh();
        Debug.Refresh();
        RefreshBreakpointList();   // now showing live (rebased) breakpoints; reflects the pre-run set just armed
        if (_coverageEnabled)
        {
            // Record the instruction we stopped on, so a Step (Into/Over/Out) or a breakpoint stop contributes to
            // the trace too — not only the continuous single-step a Continue drives. Stored in static space.
            bool added = _coveredInstrs.Add(_dbg.CurrentIp - LiveSlide);
            HarvestCoverage();   // repaints (Refresh) when it adds anything
            if (added) { ClearCoverageBtn.IsEnabled = true; Linear.Refresh(); Decompiler.Refresh(); }   // ensure the stepped row paints
        }
        else if (_findTraceArmed) HarvestCoverage();   // hit-trace: pull the traced sites hit since the last stop
        // Re-scan process memory for strings on every stop except a pure single-step (where it would thrash) —
        // unless the Strings tab is showing, in which case scan then too so stepping updates it live.
        if (_dbg.LastReason != StopReason.Step || StringsTabVisible) RefreshLiveStrings();
        if (CenterTabs.SelectedIndex == 1) OpenGraph(_dbg.CurrentIp, center: false);   // graph follows RIP too (SetCurrentIp centres it)
        if (CenterTabs.SelectedIndex == 3) { OpenDecompiler(_dbg.CurrentIp); Decompiler.SetCurrentIp(_dbg.CurrentIp); }   // decompiler follows RIP: reframe + amber IP line
        string? name = _result?.NameFor(_dbg.CurrentIp);
        string extra = _dbg.LastReason switch
        {
            StopReason.Exception => $" (code 0x{_dbg.LastExceptionCode:X8})",
            StopReason.MemoryBreakpoint => $" ({(_dbg.Engine.LastMemoryHitAccess switch { 1 => "write", 8 => "execute", _ => "read" })} {_dbg.Engine.LastMemoryHitVa:X})",
            _ => "",
        };
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
        if (_findTraceArmed) HarvestCoverage();   // capture the final hit-trace results before the session drops
        _findTraceArmed = false;                  // keep _pendingCoveragePoints so a Restart re-arms the same sites
        StopCoverageTimer();
        _coverageEnabled = false;
        CoverageToggle.IsEnabled = false;
        if (CoverageToggle.IsChecked == true) CoverageToggle.IsChecked = false;   // programmatic: does not fire Click
        Linear.SetCurrentIp(0);
        Decompiler.SetCurrentIp(0);   // clear the decompiler's amber IP band too
        Decompiler.LiveDecoder = null;   // back to the static file image; the next decompile uses the file decoder
        _curJump = null;   // no live flags now — drop the current-IP jump colour (static what-if marks persist)
        Hex.WriteByteAt = null;
        _dbg = null; _dbgViewLive = false;   // gutter now reads the static pre-run set again (IsBreakpointAt stays wired)
        Graph.Clear(); _graphFn = null;
        Debug.SetSession(null);
        DebugDock.Visibility = Visibility.Collapsed;
        if (_savedResult is not null && _image is not null)
        {
            _result = _savedResult; _savedResult = null;
            _result.UseMarkup(_markup);   // re-apply any renames made during the session (they were mirrored into _markup)
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
        RefreshBookmarkList();     // re-resolve bookmark names in static space
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
        _changeStack.Push(new ByteEdit(va, end, true));
        RepairIndex(va, end);          // local re-decode of just this region — no full re-sweep
        UpdatePatchButtons();
    }

    private void OnHexEdited(ulong va)
    {
        // Hex byte edits stay view-local (no linear re-index — typing must stay snappy on huge files);
        // tracked so undo stays in lock-step with the image's undo stack.
        _changeStack.Push(new ByteEdit(va, va + 1, false));
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
        // Byte edits push to _changeStack in lock-step with the image's own undo stack, and create-function
        // edits push there too (without touching the image), so the stack is the single source of "can undo".
        UndoBtn.IsEnabled = _changeStack.Count > 0;
    }

    private void OnUndoPatch(object sender, RoutedEventArgs e) => UndoLastEdit();

    /// <summary>Undo the most recent edit — a byte patch/hex edit (reverted through the image's undo stack) or
    /// a "create function" (the function is removed). LIFO across both kinds.</summary>
    private void UndoLastEdit()
    {
        if (_changeStack.Count == 0) return;
        // Peek first: a byte edit that can't be reverted right now must stay on the stack (don't drop it).
        switch (_changeStack.Peek())
        {
            case ByteEdit b:
                if (_image is null || !_image.CanUndo) return;
                _changeStack.Pop();
                _image.Undo();
                if (b.IsPatch) RepairIndex(b.Start, b.End); else Hex.InvalidateView();
                break;
            case CreateFunctionEdit c:
                _changeStack.Pop();
                // Remove from the displayed result at its shown VA — the static VA rebased by the current slide,
                // so this is correct whether or not a debug session is active now vs. when it was created.
                _result?.RemoveFunction(c.StaticVa + LiveSlide, c.AddedName);
                _markup.Functions.Remove(c.StaticVa);
                if (c.AddedName) _markup.Names.Remove(c.StaticVa);   // drop any rename left on the address we created
                if (_result is not null) _funcStarts = _result.Functions.Select(f => f.Va).ToArray();
                RefreshAfterMarkup(namesChanged: true);
                StatusText.Text = $"Removed function sub_{c.StaticVa:X}";
                break;
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
            Filter = "Binaries|*.exe;*.dll;*.sys;*.so;*.elf;*.o;*.dylib;*.bin;*.dat|" +
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
        _markup = proj.Markup?.Clone() ?? new Markup();   // restore user renames/comments/bookmarks (applied in StartAnalysis)
        _loadOptions = new AnalysisOptions
        {
            IncludedDataSections = proj.LoadedSections is { Count: > 0 } ls ? new HashSet<string>(ls) : new HashSet<string>(),
            IncludeHeader = proj.LoadHeader,
        };
        // Re-apply saved byte edits to the pristine image BEFORE analysis, so the disassembly decodes the patched
        // bytes and "Save patched binary…" / IsDirty light up. Keyed by file offset — stable for the same binary.
        if (proj.Patches is { Count: > 0 })
            foreach (var run in proj.Patches) image.Patch(run.Offset, run.Bytes);
        var outcome = await StartAnalysis(image, proj.CurrentVa != 0 ? proj.CurrentVa : null, proj.CenterTab);
        // The fresh analysis wiped the cross-run breakpoint / trace / jump-toggle sets (they belonged to the old
        // file); re-arm them from the project now that the new result exists.
        if (outcome == AnalyzeOutcome.Applied) RestoreSessionState(proj);
        RefreshBookmarkList();
        Title = $"DisasmStudio — {Path.GetFileNameWithoutExtension(_projectPath)} ({Path.GetFileName(image.FilePath)})";
    }

    /// <summary>Re-arm the live-session state a v7 project carries — breakpoints, the execution trace, and the
    /// static "toggle jump" what-ifs — after the fresh analysis (which cleared them). Byte patches were already
    /// re-applied to the image before analysis. All keyed in static VA space, matching the re-analysis.</summary>
    private void RestoreSessionState(ProjectFile proj)
    {
        _pendingBreakpoints.Clear();
        if (proj.Breakpoints is { Count: > 0 })
            foreach (var (va, def) in proj.Breakpoints) _pendingBreakpoints[va] = def;

        _coveredInstrs.Clear();
        if (proj.Trace is { Count: > 0 })
            foreach (var va in proj.Trace) _coveredInstrs.Add(va);

        _jumpAssume.Clear();
        if (proj.JumpAssumptions is { Count: > 0 })
            foreach (var (va, taken) in proj.JumpAssumptions) _jumpAssume[va] = taken;

        RefreshBreakpointList();
        ClearCoverageBtn.IsEnabled = _coveredInstrs.Count > 0;
        UpdatePatchButtons();
        // Repaint so the restored breakpoint dots, coverage tint and jump marks show across all code views.
        Linear.Refresh(); Graph.Refresh(); Decompiler.Refresh();
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
            Markup = _markup.IsEmpty ? null : _markup,
            // v7 live-session state (all null when empty so the file stays minimal / round-trips with older readers).
            Breakpoints = _pendingBreakpoints.Count > 0 ? new Dictionary<ulong, BpDef>(_pendingBreakpoints) : null,
            Trace = _coveredInstrs.Count > 0 ? _coveredInstrs.ToList() : null,
            Patches = CoalescePatches(_image.Patches),
            JumpAssumptions = _jumpAssume.Count > 0 ? new Dictionary<ulong, bool>(_jumpAssume) : null,
        };
        try { proj.Save(path); }
        catch (Exception ex) { MessageBox.Show(this, ex.Message, "Save project failed", MessageBoxButton.OK, MessageBoxImage.Warning); return; }

        _projectPath = path;
        Title = $"DisasmStudio — {Path.GetFileNameWithoutExtension(_projectPath)} ({Path.GetFileName(_image.FilePath)})";
        StatusText.Text = $"Saved project to {path}";
    }

    /// <summary>Group the image's byte edits (file offset → value) into contiguous runs for compact project
    /// storage, so N adjacent edited bytes become one base64 blob rather than N entries. Null when clean.</summary>
    private static List<PatchRun>? CoalescePatches(IReadOnlyDictionary<int, byte> patches)
    {
        if (patches.Count == 0) return null;
        var offsets = patches.Keys.ToArray();
        Array.Sort(offsets);
        var runs = new List<PatchRun>();
        int start = offsets[0];
        var run = new List<byte> { patches[start] };
        for (int i = 1; i < offsets.Length; i++)
        {
            if (offsets[i] == offsets[i - 1] + 1) { run.Add(patches[offsets[i]]); continue; }
            runs.Add(new PatchRun(start, run.ToArray()));
            start = offsets[i];
            run = [patches[start]];
        }
        runs.Add(new PatchRun(start, run.ToArray()));
        return runs;
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
            if (dlg.FilterIndex == 2) SourceExporter.WriteCompilableCFunction(sw, _result, fn, AnalysisDecoder);
            else SourceExporter.WriteCFunction(sw, _result, fn, AnalysisDecoder);
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
        _markup = new Markup();   // a new binary starts with no user renames/comments/bookmarks
        SignatureLibrary.Reload();   // re-scan signatures/*.sig so newly-added files apply to this binary
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
            else if (fmt == BinaryFormat.Pe && ShouldLoadAsMemoryImage(path) && PeMemoryImage.TryLoad(path, out var mem))
            {
                image = mem;
            }
            else if (fmt == BinaryFormat.MachO && MachOFat.TryList(path, out var slices) && slices.Count > 1)
            {
                // A fat/universal Mach-O — let the user pick which architecture slice to open.
                var pick = Dialogs.AskMachOSlice(this, slices);
                if (pick is null) return;   // cancelled
                image = MachOImage.Load(path, pick.Value.Offset);
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

    /// <summary>Whether a PE file should be interpreted as a raw memory image (sections at their virtual addresses)
    /// rather than a normal on-disk executable. Explicit dump names/extensions are trusted; an ambiguous <c>.bin</c>
    /// is decided by content (<see cref="PeMemoryImage.LooksLikeMemoryImage(string)"/>) so an ordinary executable
    /// that merely has a .bin extension still loads correctly as a program instead of rendering as garbage.</summary>
    private static bool ShouldLoadAsMemoryImage(string path)
    {
        string name = Path.GetFileName(path);
        string ext = Path.GetExtension(path);
        if (name.Contains("_fault_dump", StringComparison.OrdinalIgnoreCase)
            || name.Contains("_memdump", StringComparison.OrdinalIgnoreCase)
            || ext.Equals(".dmp", StringComparison.OrdinalIgnoreCase)
            || ext.Equals(".mem", StringComparison.OrdinalIgnoreCase))
            return true;   // named as a dump → trust it
        if (ext.Equals(".bin", StringComparison.OrdinalIgnoreCase))
            return PeMemoryImage.LooksLikeMemoryImage(path);   // ambiguous → decide by byte layout
        return false;
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
            _jumpAssume.Clear();           // jump what-if assumptions belong to the old file's addresses too
            // Trace highlights belong to the old image's addresses — drop them.
            _coverageEnabled = false;
            _coveredInstrs.Clear(); StopCoverageTimer();
            if (CoverageToggle is not null) { CoverageToggle.IsChecked = false; CoverageToggle.IsEnabled = false; ClearCoverageBtn.IsEnabled = false; }
            // The hit-trace set belongs to the old file's addresses — drop it and clear the Find list.
            _pendingCoveragePoints.Clear(); _findTraceArmed = false; _findResults = []; _findHitsOnly = false; _findShownHits = 0;
            if (FindInsnResults is not null) { FindInsnResults.ItemsSource = null; FindInsnHeader.Text = ""; }
            if (FindTraceBtn is not null) FindTraceBtn.IsEnabled = false;
            if (FindHitsOnly is not null) { FindHitsOnly.IsChecked = false; FindHitsOnly.IsEnabled = false; }
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
            result.UseMarkup(_markup);   // overlay user renames/comments (and re-apply function-start renames) onto the fresh analysis
            _callGraph = null;           // rebuilt lazily against the new result on the next Call Graph tab view
            PopulateLists(result);       // also invalidates _entropy (recomputed lazily on the next Entropy tab view)
            Linear.SetResult(result);
            Hex.SetImage(image);
            if (fresh) ProbeManaged(image);   // light up the C#/.NET tabs when this PE is a managed assembly
            if (fresh) ProbeObjC(image);      // light up the Obj-C tab when this Mach-O carries Objective-C metadata
            SavePatchedBtn.IsEnabled = image.IsDirty;
            UndoBtn.IsEnabled = _changeStack.Count > 0;   // unified stack: also stays live for a pending create-function edit
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

        var mmRows = BuildMemoryMap(result.Image);
        MemMapGrid.ItemsSource = mmRows;
        MemMapStrip.SetRegions(mmRows);

        ResTree.ItemsSource = result.Image.Resources is { Roots.Count: > 0 } res
            ? res.Roots.Select(r => new ResourceNodeVm(r, r.Id)).ToList()
            : null;
        ResPreviewHost.Content = null;
        ResSaveBtn.IsEnabled = false;
        _selectedResource = null;
        ResHeader.Text = result.Image.Resources is { Roots.Count: > 0 } ? "Select a resource" : "No resources";
        RefreshBreakpointList();
        RefreshBookmarkList();

        // The result/image just changed (new file, re-analysis after a patch, or a live/static debug swap) — drop
        // any cached entropy so the next Entropy-tab view recomputes; bump the generation to discard an in-flight
        // background compute for the previous image. Refresh immediately if the Entropy tab is currently open.
        _entropy = null; _entropyGen++;
        if (SideTabs.SelectedItem is TabItem { Header: "Entropy" }) EnsureEntropy();
    }

    /// <summary>Build the Memory Map rows for the loaded image: the header (if any) + every section, sorted by
    /// VA, with a synthetic <c>&lt;gap&gt;</c> row inserted for each stretch of unmapped address space between
    /// mapped regions. Format-agnostic — it consumes only the unified <see cref="Section"/> list.</summary>
    private static List<MemoryMapItem> BuildMemoryMap(IBinaryImage img)
    {
        var regions = new List<(Section Sec, bool Header)>();
        if (img.HeaderRegion is { } hdr) regions.Add((hdr, true));
        foreach (var s in img.Sections) regions.Add((s, false));
        regions.Sort((a, b) => a.Sec.StartVa.CompareTo(b.Sec.StartVa));

        var rows = new List<MemoryMapItem>();
        ulong cursor = 0;
        bool first = true;
        foreach (var (sec, isHeader) in regions)
        {
            if (!first && sec.StartVa > cursor)
                rows.Add(new MemoryMapItem(cursor, sec.StartVa));   // unmapped gap before this region
            rows.Add(new MemoryMapItem(sec, isHeader));
            cursor = first ? sec.EndVa : Math.Max(cursor, sec.EndVa);   // Max guards overlapping/contained sections
            first = false;
        }
        return rows;
    }

    private void ClearLists()
    {
        FuncList.ItemsSource = null;
        StringList.ItemsSource = null;
        StringHeader.Text = "";
        ExportList.ItemsSource = null;
        ImportList.ItemsSource = null;
        SectionList.ItemsSource = null;
        MemMapGrid.ItemsSource = null;
        MemMapStrip.SetRegions([]);
        _entropy = null; _entropyGen++;   // bump drops any in-flight background compute
        EntropyGraph.SetData(null);
        EntropySectionGrid.ItemsSource = null;
        EntropyHeader.Text = "";
        ResTree.ItemsSource = null;
        ResPreviewHost.Content = null;
        ResSaveBtn.IsEnabled = false;
        _selectedResource = null;
        ResHeader.Text = "Select a resource";
        XrefList.ItemsSource = null;
        BreakpointList.ItemsSource = null;
        BookmarkList.ItemsSource = null;
        CallGraphPanel.Clear();
        _callGraph = null;
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

        // Objective-C (Mach-O) view: hide the tab until the next probe re-shows it.
        ObjCTab.Visibility = Visibility.Collapsed;
        ObjCTree.ItemsSource = null;
        RefreshFormatChips();
    }

    // ---- navigation ----
    private void OnNavigated(ulong va)
    {
        AddrBox.Text = va.ToString("X");
        BackBtn.IsEnabled = _nav.CanGoBack;
        FwdBtn.IsEnabled = _nav.CanGoForward;
        if (_result is null || _image is null) return;

        Linear.GoToVa(va);          // raises SelectionChanged → xrefs/status update
        HexGoTo(va);                // scroll to AND highlight the whole instruction's bytes
        // Reflect a navigation in an already-open graph without recentring: SetFunction frames a new function,
        // and a same-function nav (e.g. a graph block-click echoing back) only re-highlights, so the view
        // doesn't lurch under the cursor.
        if (CenterTabs.SelectedIndex == 1) OpenGraph(va, center: false);
        if (CenterTabs.SelectedIndex == 3) OpenDecompiler(va);
        if (CallGraphTabVisible) CallGraphPanel.NavigatedTo(va);   // re-root the call graph when Follow is on

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

    // Selecting a line in the decompiler focuses that address (status + xrefs) and — so switching back to the
    // linear listing lands on the matching instruction — moves the (hidden) linear caret there too. Quiet:
    // GoToVa doesn't steal focus, and the decompiler's own GoToVa sync doesn't raise SelectionChanged, so
    // this never loops.
    private void OnDecompilerFocused(ulong va)
    {
        OnAddressFocused(va);
        Linear.GoToVa(va, focus: false);
    }

    // Selecting a byte in the hex view focuses that address (status + xrefs) and moves the (hidden) linear
    // caret there too, so switching back to Linear/Graph/Decompiler lands on the matching instruction. Quiet:
    // Linear.GoToVa doesn't steal focus and doesn't re-navigate, and Hex.GoTo doesn't raise SelectionChanged,
    // so this never loops. (Mirrors OnDecompilerFocused.)
    private void OnHexFocused(ulong va)
    {
        OnAddressFocused(va);
        Linear.GoToVa(va, focus: false);
    }

    // Point the hex view at `va`, highlighting the whole instruction (all its opcode bytes), not just the first.
    // The instruction's length is the gap to the next listing line; data lines and non-boundary VAs get one byte.
    private void HexGoTo(ulong va)
    {
        int len = 1;
        if (_result is not null)
        {
            var idx = _result.Linear;
            long line = idx.IndexOf(va);
            if (idx.VaAt(line) == va && !idx.IsDataAt(line))
            {
                long rawLen = line + 1 < idx.Count ? (long)(idx.VaAt(line + 1) - va) : 1;
                len = (int)Math.Clamp(rawLen, 1, 16);   // x86/x64 max instruction length is 15 bytes
            }
        }
        Hex.GoTo(va, select: true, length: len);
    }

    // ---- hex byte search (Ctrl+F on the Hex tab; F3 / Shift+F3 to repeat) ----
    private void HexFind()
    {
        if (_image is null) return;
        if (Dialogs.AskSearchPattern(this) is not { } q) return;
        ShowFindResult(Hex.Search(q.Pattern, q.Mask, forward: true), q.Display);
    }

    private void HexFindAgain(bool prev)
    {
        if (_image is null) return;
        ShowFindResult(Hex.SearchAgain(forward: !prev), null);
    }

    private void ShowFindResult(HexView.FindResult result, string? query)
    {
        string what = query ?? "pattern";
        StatusText.Text = result switch
        {
            HexView.FindResult.Found => $"Found {what}",
            HexView.FindResult.FoundWrapped => $"Found {what} (wrapped)",
            HexView.FindResult.NotFound => query is null ? "No more matches" : $"Not found: {what}",
            _ => StatusText.Text,
        };
    }

    private void ShowXrefs(ulong va)
    {
        if (_result is null) return;
        var list = _result.Xrefs.To(va).Select(x => new XrefItem(x)).ToList();
        XrefList.ItemsSource = list;
        string? name = _result.NameFor(va);
        XrefHeader.Text = $"{va:X}{(name is null ? "" : $"  {name}")} — {list.Count} xref(s)";
    }

    private void OpenGraph(ulong va, bool center)
    {
        var fn = FindFunction(va);
        if (fn is null || _result is null) return;
        // Rebuild only when the function changes (object identity differs across the static↔live swap too).
        bool changed = !ReferenceEquals(fn, _graphFn);
        bool firstFrame = _graphFn is null;   // nothing shown yet → fit-to-view once for a sensible default frame
        // Two very different callers funnel through here while a session is live: the debugger following its own
        // IP on a step/stop (va == CurrentIp), and the *user* following a call/branch to some other instruction
        // (va != CurrentIp). Only the IP-follow reframes on the current instruction (resetting the zoom when it
        // crosses into a new function); a user-follow must behave exactly like it does when NOT debugging — keep
        // the current zoom and snap the followed target to the centre — instead of yanking back to the IP.
        bool followingIp = _dbg is not null && va == _dbg.CurrentIp;
        // Fit-to-view only on the very first function shown (while debugging, the IP-follow below frames it). Once
        // a graph is up and the user has a zoom they like, following a call to another function KEEPS that zoom and
        // just snaps the target to the middle (below) — the view no longer resizes to each function's size.
        if (changed) { Graph.SetFunction(_result, fn, _dbg?.LiveDecoder, autoFit: firstFrame && _dbg is null); _graphFn = fn; }
        // Keep the IP marker current, but only let it reframe the view when we're actually following the IP
        // (a step/stop). On a user-follow it refreshes the marker without recentring, so the target centring below
        // wins and the user's zoom survives.
        if (_dbg is not null) Graph.SetCurrentIp(_dbg.CurrentIp, resetZoom: followingIp && changed, center: followingIp);
        // Mirror the caret and centre the navigation target. On a function change (that wasn't the non-debug
        // initial fit) centre the target at the preserved zoom — in a live session too; on a same-function nav
        // centre only when explicitly asked, so a graph block-click echoing back doesn't lurch the view. The
        // IP-follow already framed its own instruction, so don't double-centre on it.
        Graph.SetSelected(va, center: followingIp ? false : (changed ? !(firstFrame && _dbg is null) : center));
    }

    /// <summary>Open the CFG graph for <paramref name="va"/> and switch to the Graph tab. The guard stops the
    /// tab-change handler re-opening the graph at the (possibly stale) linear caret and overriding this target.</summary>
    private void OpenGraphTab(ulong va)
    {
        _openingGraph = true;
        try { OpenGraph(va, center: true); CenterTabs.SelectedIndex = 1; }
        finally { _openingGraph = false; }
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
        if (fn is not null && _result is not null) { Decompiler.SetFunction(_result, fn); Decompiler.GoToVa(va); }
    }

    // Populate the graph / decompiler when the user switches to that tab (they build lazily).
    private void OnCenterTabChanged(object sender, SelectionChangedEventArgs e)
    {
        if (e.Source is not TabControl || _result is null || _openingGraph) return;
        // Land on whatever instruction is highlighted in the linear listing (its caret), falling back to the
        // navigation address — so switching to Graph/Decompiler syncs to your current selection, and (for the
        // graph) scrolls it into view, not just to the last explicit jump.
        ulong va = Linear.CaretVa != 0 ? Linear.CaretVa : _nav.Current ?? 0;
        if (va == 0) return;
        if (CenterTabs.SelectedIndex == 1) OpenGraph(va, center: true);
        else if (CenterTabs.SelectedIndex == 2) HexGoTo(va);   // land on the current caret, whole instruction highlighted
        else if (CenterTabs.SelectedIndex == 3) { OpenDecompiler(va); if (_dbg is { IsStopped: true }) Decompiler.SetCurrentIp(_dbg.CurrentIp); }
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
        OpenGraphTab(fi.Va);
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

    // ---- Find instruction: static asm-text search over the whole listing ----

    private void OnFindInsnKeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Enter) { RunInstructionSearch(); e.Handled = true; }
    }

    /// <summary>Scan every decoded instruction for the query text (case- and spacing-insensitive substring)
    /// off the UI thread and list the matches; clicking one navigates to it. Cancels any in-flight scan.</summary>
    private async void RunInstructionSearch()
    {
        if (_result is null) { FindInsnResults.ItemsSource = null; _findResults = []; FindTraceBtn.IsEnabled = false; FindHitsOnly.IsEnabled = false; FindHitsOnly.IsChecked = false; _findHitsOnly = false; FindInsnHeader.Text = "Load a file first"; return; }
        string q = FindInsnBox.Text.Trim();
        if (q.Length == 0) { FindInsnResults.ItemsSource = null; _findResults = []; FindTraceBtn.IsEnabled = false; FindHitsOnly.IsEnabled = false; FindHitsOnly.IsChecked = false; _findHitsOnly = false; FindInsnHeader.Text = ""; return; }

        _findInsnCts?.Cancel();
        var cts = _findInsnCts = new CancellationTokenSource();
        var ct = cts.Token;
        FindInsnHeader.Text = "searching…";

        string needle = Norm(q);
        var r = _result;
        try
        {
            var (rows, capped) = await Task.Run(() => ScanInstructions(r, needle, ct), ct);
            if (ct.IsCancellationRequested) return;
            _findResults = rows;
            _findHitsOnly = false; FindHitsOnly.IsChecked = false; _findShownHits = 0;   // fresh results: show all
            FindInsnResults.ItemsSource = rows;
            FindTraceBtn.IsEnabled = rows.Count > 0;
            FindHitsOnly.IsEnabled = rows.Count > 0;
            FindInsnHeader.Text = rows.Count == 0
                ? "no matches"
                : capped ? $"first {MaxInsnMatches:N0} matches (stopped early) — narrow the query"
                         : $"{rows.Count:N0} match(es)";
            UpdateFindHits();   // reflect any sites already recorded by a running/earlier trace
        }
        catch (OperationCanceledException) { /* superseded by a newer search */ }
    }

    /// <summary>Decode+format every instruction line through the architecture-neutral seam (x86/x64/ARM/8051)
    /// and collect those whose text contains the already-normalized needle. Runs on a background thread with
    /// its own decoder (decoders are not thread-safe). Returns the matches and whether the cap was hit.</summary>
    private static (List<InsnMatchItem> Rows, bool Capped) ScanInstructions(AnalysisResult r, string needle, CancellationToken ct)
    {
        var rows = new List<InsnMatchItem>();
        var dis = NeutralDisasm.For(r.Image, r.Names);
        try
        {
            long count = r.Linear.Count;
            for (long i = 0; i < count; i++)
            {
                if ((i & 0xFFFF) == 0) ct.ThrowIfCancellationRequested();
                if (r.Linear.IsDataAt(i)) continue;                       // instructions only
                ulong va = r.Linear.VaAt(i);
                var toks = dis.Format(va);                                // reused buffer — concat before the next Format
                if (toks.Count == 0) continue;
                string text = string.Concat(toks.Select(t => t.Text));
                if (Norm(text).Contains(needle, StringComparison.Ordinal))
                {
                    rows.Add(new InsnMatchItem(va, text.Trim()));
                    if (rows.Count >= MaxInsnMatches) return (rows, true);
                }
            }
        }
        finally { (dis as IDisposable)?.Dispose(); }                      // the ARM (Capstone) decoder is disposable
        return (rows, false);
    }

    /// <summary>Lowercase and drop all whitespace so a query matches regardless of the formatter's spacing
    /// (e.g. "cmp eax, 5" ≡ "cmp     eax,5").</summary>
    private static string Norm(string s)
    {
        var sb = new StringBuilder(s.Length);
        foreach (char c in s) if (!char.IsWhiteSpace(c)) sb.Append(char.ToLowerInvariant(c));
        return sb.ToString();
    }

    // Wired to both SelectionChanged (single click / arrow-key browse) and MouseDoubleClick (re-jump), so a
    // click on a match jumps straight to it. RoutedEventArgs is the common base of both event-arg types.
    private void OnFindInsnActivate(object sender, RoutedEventArgs e)
    {
        if (FindInsnResults.SelectedItem is InsnMatchItem it && _result is not null)
        {
            CenterTabs.SelectedIndex = 0;   // show the match in the linear listing
            _nav.Navigate(it.Va);
        }
    }

    /// <summary>Instrument every current match for hit-tracing. The set is remembered and armed with silent
    /// one-shot coverage breakpoints automatically on each Run (or immediately if a session is already paused);
    /// as each site executes it is marked ● in the list and tinted in the listing. Replaces any previous set.</summary>
    private void OnFindTraceHits(object sender, RoutedEventArgs e)
    {
        if (_findResults.Count == 0) { FindInsnHeader.Text = "nothing to trace — search first"; return; }

        _pendingCoveragePoints.Clear();
        foreach (var m in _findResults) { m.Hit = false; _pendingCoveragePoints.Add(m.Va); }
        _findShownHits = 0;
        if (_findHitsOnly) RefreshFindView();   // hits were just reset — clear the filtered view too

        if (_dbg is { IsStopped: true } && _dbgViewLive)
        {
            _dbg.ClearCoverage();          // drop any prior coverage instrumentation + recorded hits
            _coveredInstrs.Clear();
            _findTraceArmed = false;
            ArmCoverageTrace();            // plant on the current matches from here
            Linear.Refresh(); Graph.Refresh(); Decompiler.Refresh();
        }

        FindInsnHeader.Text = _findTraceArmed
            ? $"tracing {_pendingCoveragePoints.Count:N0} site(s) — Continue (F5); hits mark ●"
            : $"{_pendingCoveragePoints.Count:N0} site(s) will be traced on Run";
    }

    /// <summary>Plant silent one-shot coverage breakpoints on the pending trace sites (translated to live VAs)
    /// and start harvesting hits. Requires a paused live session; a no-op otherwise (armed at the next stop).</summary>
    private void ArmCoverageTrace()
    {
        if (_findTraceArmed || _dbg is not { IsStopped: true } || !_dbgViewLive || _pendingCoveragePoints.Count == 0) return;
        ulong slide = LiveSlide;
        _dbg.SetCoveragePoints(_pendingCoveragePoints.Select(v => v + slide));
        _findTraceArmed = true;
        ClearCoverageBtn.IsEnabled = true;
        StartCoverageTimer();
    }

    /// <summary>Mark each Find row hit/not-hit from the covered-instruction set (static VAs) and show the count.</summary>
    private void UpdateFindHits()
    {
        if (_findResults.Count == 0) return;
        int hit = 0;
        foreach (var m in _findResults) { bool h = _coveredInstrs.Contains(m.Va); m.Hit = h; if (h) hit++; }
        if (_findTraceArmed || hit > 0)
            FindInsnHeader.Text = $"{_findResults.Count:N0} match(es) · {hit:N0} hit";
        if (_findHitsOnly && hit != _findShownHits) RefreshFindView();   // surface newly-hit rows in the filtered view
        _findShownHits = hit;
    }

    /// <summary>Toggle the Find list between all matches and only the hit ones ("Hits only").</summary>
    private void OnFindHitsOnly(object sender, RoutedEventArgs e)
    {
        _findHitsOnly = FindHitsOnly.IsChecked == true;
        RefreshFindView();
    }

    /// <summary>Point the Find list at either every match or only the hit ones, per the "Hits only" toggle.</summary>
    private void RefreshFindView()
    {
        FindInsnResults.ItemsSource = _findHitsOnly ? _findResults.Where(m => m.Hit).ToList() : _findResults;
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

    /// <summary>Memory Map table double-click → navigate every view to the region start (gaps don't navigate).</summary>
    private void OnMemMapActivate(object sender, MouseButtonEventArgs e)
    {
        if (MemMapGrid.SelectedItem is MemoryMapItem m && !m.IsGap) _nav.Navigate(m.Va);
    }

    /// <summary>Memory Map table selection → highlight the matching block in the strip.</summary>
    private void OnMemMapGridSelected(object sender, SelectionChangedEventArgs e)
    {
        MemMapStrip.SelectedIndex = MemMapGrid.SelectedIndex;
    }

    /// <summary>Select the Memory Map row under the cursor so the right-click menu acts on it.</summary>
    private void OnMemMapRightClick(object sender, MouseButtonEventArgs e)
    {
        var dep = e.OriginalSource as DependencyObject;
        while (dep is not null and not DataGridRow) dep = System.Windows.Media.VisualTreeHelper.GetParent(dep);
        if (dep is DataGridRow row) row.IsSelected = true;
    }

    /// <summary>Disable the section actions when the selected row is a &lt;gap&gt; (or nothing is selected). The
    /// whole-image "Dump image as PE" item is independent of the selection — it needs only a stopped live session.</summary>
    private void OnMemMapMenuOpening(object sender, RoutedEventArgs e)
    {
        bool ok = MemMapGrid.SelectedItem is MemoryMapItem { IsGap: false };
        bool liveStopped = _dbgViewLive && _dbg is { IsStopped: true };
        if (sender is ContextMenu cm)
            foreach (var it in cm.Items)
                if (it is MenuItem mi)
                    mi.IsEnabled = ReferenceEquals(mi, DumpImagePeMenuItem) ? liveStopped : ok;
    }

    /// <summary>Dump the selected section's bytes to a file — the on-disk raw bytes when static, or the live
    /// process-memory bytes during a debug session (whichever image the views are showing). Patches are overlaid.</summary>
    private void OnDumpSection(object sender, RoutedEventArgs e)
    {
        if (MemMapGrid.SelectedItem is not MemoryMapItem m || m.IsGap) return;
        var img = _result?.Image ?? _image;
        if (img is null) return;
        // The row carries only a VA — re-find the section; the HEADER row isn't in Sections, so fall back to it.
        var sec = img.SectionAt(m.Va) ?? (img.HeaderRegion is { } h && h.StartVa == m.Va ? h : null);
        if (sec is null) { StatusText.Text = $"No section at {m.Va:X}"; return; }
        int count = sec.FileSize > 0 ? sec.FileSize : (int)Math.Min(sec.VirtualSize, (ulong)int.MaxValue);
        if (count <= 0) { StatusText.Text = $"{sec.Name}: nothing to dump (no bytes)"; return; }
        var bytes = img.ReadBytesAtVa(sec.StartVa, count);
        var baseName = Path.GetFileNameWithoutExtension(_image?.FilePath ?? "image");
        var dlg = new SaveFileDialog
        {
            Title = "Dump section",
            FileName = $"{baseName}_{SanitizeSectionName(sec.Name)}.bin",
            Filter = "Binary|*.bin|All files|*.*",
        };
        if (dlg.ShowDialog(this) != true) return;
        try { File.WriteAllBytes(dlg.FileName, bytes); StatusText.Text = $"Dumped {sec.Name} ({bytes.Length} bytes) to {dlg.FileName}"; }
        catch (Exception ex) { MessageBox.Show(this, ex.Message, "Dump failed", MessageBoxButton.OK, MessageBoxImage.Error); }
    }

    /// <summary>Dump the running image to a clean, re-openable PE using the same dump → IAT-rebuild → PeBuilder
    /// pipeline the generic unpacker uses (<see cref="DisasmStudio.Debug.Unpacking.LivePeDump"/>), driven from the
    /// Memory Map. Only during a stopped live session: the current instruction pointer — typically where a section
    /// execute breakpoint just broke — is baked as the OEP. This is the manual unpacking workflow: arm "Break on
    /// execute (section)" on the packed section, let it break when the unpacked code first runs, then dump here.</summary>
    private void OnDumpImageAsPe(object sender, RoutedEventArgs e)
    {
        if (!_dbgViewLive || _dbg is not { IsStopped: true } d)
        {
            StatusText.Text = "Dump image as PE needs a live debug session that is stopped (run or attach, then break).";
            return;
        }
        var eng = d.Engine;
        // OEP = the current instruction pointer (where an execute breakpoint / manual break landed).
        ulong oep = eng.GetRegisters()?.Ip ?? eng.EntryPoint;
        ulong preferredBase = _image?.ImageBase ?? eng.ImageBase;
        var baseName = Path.GetFileNameWithoutExtension(_image?.FilePath ?? "image");
        var dlg = new SaveFileDialog
        {
            Title = "Dump image as PE",
            FileName = $"{baseName}_dumped.exe",
            Filter = "Executable|*.exe|All files|*.*",
        };
        if (dlg.ShowDialog(this) != true) return;

        StatusText.Text = $"Dumping live image at OEP {oep:X} and rebuilding imports…";
        DisasmStudio.Debug.Unpacking.LivePeDump.Result res;
        try { res = DisasmStudio.Debug.Unpacking.LivePeDump.Build(eng, oep, preferredBase); }
        catch (Exception ex)
        {
            StatusText.Text = "Dump as PE failed.";
            MessageBox.Show(this, ex.Message, "Dump image as PE", MessageBoxButton.OK, MessageBoxImage.Error);
            return;
        }

        if (!res.Ok || res.Bytes.Length == 0)
        {
            StatusText.Text = "Dump as PE failed — could not dump/parse the live image.";
            MessageBox.Show(this, "Could not dump or parse the live image.\n\n" + res.Log,
                "Dump image as PE", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        try { File.WriteAllBytes(dlg.FileName, res.Bytes); }
        catch (Exception ex)
        {
            StatusText.Text = "Dump as PE failed.";
            MessageBox.Show(this, ex.Message, "Dump image as PE", MessageBoxButton.OK, MessageBoxImage.Error);
            return;
        }

        StatusText.Text = $"Dumped image as PE (OEP {res.Oep:X}; imports {res.ImportsResolved} resolved, {res.ImportsUnresolved} unresolved) → {dlg.FileName}";
        MessageBox.Show(this,
            $"Wrote {Path.GetFileName(dlg.FileName)}.\n\nOEP {res.Oep:X} · {res.ImportsResolved} imports resolved, " +
            $"{res.ImportsUnresolved} unresolved · {res.SizeOfImage:X} bytes of image.\n\n" +
            "Open it when you're done debugging (opening a file ends the live view).",
            "Dump image as PE", MessageBoxButton.OK, MessageBoxImage.Information);
    }

    /// <summary>Set a software memory breakpoint over the whole selected section. Reuses the pending/live
    /// mem-bp flow — the row's Va/EndVa are already in the displayed (static-or-live) space it expects.</summary>
    private void SetSectionMemBp(MemAccess access)
    {
        if (MemMapGrid.SelectedItem is not MemoryMapItem m || m.IsGap || m.SizeBytes == 0) return;
        OnMemoryBreakpointRequested((m.Va, m.EndVa - 1, access));
    }

    private void OnSectionBreakRead(object sender, RoutedEventArgs e) => SetSectionMemBp(MemAccess.Read);
    private void OnSectionBreakWrite(object sender, RoutedEventArgs e) => SetSectionMemBp(MemAccess.Write);
    private void OnSectionBreakAccess(object sender, RoutedEventArgs e) => SetSectionMemBp(MemAccess.ReadWrite);
    private void OnSectionBreakExecute(object sender, RoutedEventArgs e) => SetSectionMemBp(MemAccess.Execute);

    /// <summary>A filename-safe form of a section name for the dump's suggested filename (e.g. ".text" → "text").</summary>
    private static string SanitizeSectionName(string name)
    {
        var cleaned = new string(name.Where(c => !Path.GetInvalidFileNameChars().Contains(c)).ToArray()).TrimStart('.');
        return cleaned.Length > 0 ? cleaned : "section";
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
        RefreshFormatChips();
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
                    RefreshFormatChips();
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

    // ---- Objective-C (Mach-O) path ----

    /// <summary>If the freshly-analyzed Mach-O carries Objective-C metadata, populate and reveal the Obj-C tab
    /// (a class → method tree; double-click a method to jump to its IMP in the listing).</summary>
    private void ProbeObjC(IBinaryImage image)
    {
        if (image is not MachOImage { ObjC: { Classes.Count: > 0 } objc })
        {
            ObjCTab.Visibility = Visibility.Collapsed;
            ObjCTree.ItemsSource = null;
            RefreshFormatChips();
            return;
        }
        ObjCTree.ItemsSource = objc.Classes.OrderBy(c => c.Name).Select(c => new ObjCClassVm(c)).ToList();
        ObjCTab.Visibility = Visibility.Visible;
        RefreshFormatChips();
        StatusText.Text = $"Objective-C: {objc.Classes.Count} class(es), {objc.MethodSymbols.Count} method(s) — see the Obj-C tab.";
    }

    private void OnObjCActivate(object sender, MouseButtonEventArgs e)
    {
        if (ObjCTree.SelectedItem is ObjCMethodVm m) { CenterTabs.SelectedIndex = 0; _nav.Navigate(m.Va); }
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

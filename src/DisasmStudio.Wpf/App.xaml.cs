using System.Runtime.InteropServices;
using System.Windows;
using DisasmStudio.Wpf.Diagnostics;

namespace DisasmStudio.Wpf;

public partial class App : Application
{
    [DllImport("kernel32.dll")] private static extern bool AttachConsole(int dwProcessId);
    private const int ATTACH_PARENT_PROCESS = -1;

    protected override void OnStartup(StartupEventArgs e)
    {
        // Headless (no-GUI) mode — Ghidra analyzeHeadless-style. When the first arg is a headless verb, run the
        // Core-only command-line front end (attach to the launching terminal, print, exit) and never show a window.
        if (e.Args.Length > 0 && Headless.IsHeadlessVerb(e.Args[0]))
        {
            bool hasConsole = AttachConsole(ATTACH_PARENT_PROCESS);
            int rc = Headless.Run(e.Args, hasConsole);
            Shutdown(rc);
            return;
        }
        // Hidden self-test for the condition evaluator: print to the launching terminal and exit, no UI.
        if (e.Args.Length > 0 && e.Args[0] == "--smoke-cond")
        {
            AttachConsole(ATTACH_PARENT_PROCESS);
            int rc = ConditionSmoke.Run();
            Shutdown(rc);
            return;
        }
        // Hidden self-test for .dsproj persistence: round-trip a v8 project (breakpoints / trace / patches /
        // jump what-ifs / markup) plus a legacy v6 file, print to the launching terminal, and exit — no UI.
        if (e.Args.Length > 0 && e.Args[0] == "--smoke-project")
        {
            AttachConsole(ATTACH_PARENT_PROCESS);
            int rc = ProjectSmoke.Run();
            Shutdown(rc);
            return;
        }
        // Hidden self-test for the .NET managed path (decompiler view / SetAssembly tree build). Runs inside the
        // live App so theme resources exist, prints to the launching terminal, and exits — no window.
        if (e.Args.Length > 0 && e.Args[0] == "--smoke-managed")
        {
            AttachConsole(ATTACH_PARENT_PROCESS);
            string file = e.Args.Length > 1 ? e.Args[1] : @"C:\tmp\891SAFPLUSPCDriveUpdater.exe";
            int rc = ManagedSmoke.Run(file);
            Shutdown(rc);
            return;
        }
        // Hidden self-test for the Mach-O loader + Objective-C metadata parser: load a thin/fat Mach-O, dump its
        // sections/symbols/Obj-C classes, analyse, and assert sections/symbols/functions were produced — no UI.
        if (e.Args.Length > 0 && e.Args[0] == "--smoke-objc")
        {
            AttachConsole(ATTACH_PARENT_PROCESS);
            int rc = e.Args.Length > 1 ? ObjCSmoke.Run(e.Args[1]) : 2;
            Shutdown(rc);
            return;
        }
        // Hidden self-test for the managed source-level debugger: drive the real ManagedDebugClient against a
        // .NET assembly (locate host → launch → entry breakpoint → hit → exit), print to the terminal, exit.
        if (e.Args.Length > 0 && e.Args[0] == "--smoke-mdbg")
        {
            AttachConsole(ATTACH_PARENT_PROCESS);
            int rc = e.Args.Length > 1 ? Diagnostics.ManagedDebugSmoke.Run(e.Args[1]) : 2;
            Shutdown(rc);
            return;
        }
        // Hidden self-test for the anti-anti-debug (Hide from debugger) layer: launch a protected target under
        // the native debugger with Hide off then on, and confirm the NtClose invalid-handle trick (0xC0000008)
        // stops us only with Hide off. Reproduces the "run the .NET Framework app natively" offer path headlessly.
        if (e.Args.Length > 0 && e.Args[0] == "--smoke-hidedbg")
        {
            AttachConsole(ATTACH_PARENT_PROCESS);
            int rc = e.Args.Length > 1 ? Diagnostics.HideDebugSmoke.Run(e.Args[1]) : 2;
            Shutdown(rc);
            return;
        }

        // Hidden self-test for the whole-section EXECUTE software memory breakpoint (Memory Map → "Break on
        // execute"): launch a target, arm an execute mem-bp on the entry page, continue, and assert the fetch
        // faults through as StopReason.MemoryBreakpoint with access = execute (8). Prints to the terminal, exits.
        if (e.Args.Length > 0 && e.Args[0] == "--smoke-secbp")
        {
            AttachConsole(ATTACH_PARENT_PROCESS);
            int rc = Diagnostics.SectionBpSmoke.Run(e.Args.Length > 1 ? e.Args[1] : null);
            Shutdown(rc);
            return;
        }
        // Hidden self-test for the Entropy tab's math (EntropyData.Build): build the per-block / per-section
        // entropy profile of a synthetic zero/uniform/constant blob and assert min≈0, max≈8, overall in between.
        if (e.Args.Length > 0 && e.Args[0] == "--smoke-entropy")
        {
            AttachConsole(ATTACH_PARENT_PROCESS);
            int rc = EntropySmoke.Run(e.Args.Length > 1 ? e.Args[1] : null);
            Shutdown(rc);
            return;
        }
        // Hidden self-test for the "changed since last step" memory highlight (HexView.DiffChangedVas + the live
        // control path): assert exact changed-VA sets over in-place/scroll cases, then drive a real HexView over a
        // RawImage — baseline, mutate a byte, confirm exactly that VA flags and it renders. Prints, exits — no UI.
        if (e.Args.Length > 0 && e.Args[0] == "--smoke-memdiff")
        {
            AttachConsole(ATTACH_PARENT_PROCESS);
            int rc = MemDiffSmoke.Run();
            Shutdown(rc);
            return;
        }
        // Hidden self-test for the "follow writes" resolver (WriteTarget.TryResolve): decode a few x64 stores /
        // reads / a push and assert the resolved memory-write effective address + width. Prints, exits — no UI.
        if (e.Args.Length > 0 && e.Args[0] == "--smoke-followwrite")
        {
            AttachConsole(ATTACH_PARENT_PROCESS);
            int rc = FollowWriteSmoke.Run();
            Shutdown(rc);
            return;
        }
        // Hidden self-test for editing strings in their existing allocation: ASCII/UTF-16LE encoding,
        // NUL-padding, scanner refresh, invalid-input rejection, and static patch undo.
        if (e.Args.Length > 0 && e.Args[0] == "--smoke-string-edit")
        {
            AttachConsole(ATTACH_PARENT_PROCESS);
            int rc = StringEditSmoke.Run();
            Shutdown(rc);
            return;
        }
        base.OnStartup(e);   // StartupUri creates MainWindow
    }
}

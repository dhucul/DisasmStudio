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
        base.OnStartup(e);   // StartupUri creates MainWindow
    }
}

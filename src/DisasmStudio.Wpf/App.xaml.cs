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
        base.OnStartup(e);   // StartupUri creates MainWindow
    }
}

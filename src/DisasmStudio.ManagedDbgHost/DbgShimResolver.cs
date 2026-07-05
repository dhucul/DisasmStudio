using System.IO;
using System.Runtime.InteropServices;

namespace DisasmStudio.ManagedDbgHost;

/// <summary>Locates the dbgshim.dll shipped by the Microsoft.Diagnostics.DbgShim.win-{arch} package,
/// which the SDK copies to <c>runtimes/win-{arch}/native/</c> beside the host. Windows-only. Adapted from
/// the ClrDebug NetCore sample's resolver.</summary>
internal static class DbgShimResolver
{
    public static string Resolve()
    {
        string root = AppContext.BaseDirectory;
        string direct = Path.Combine(root, "dbgshim.dll");
        if (File.Exists(direct)) return direct;

        string arch = RuntimeInformation.ProcessArchitecture.ToString().ToLowerInvariant();   // x64 / x86 / arm64
        foreach (var rid in new[] { $"win-{arch}", RuntimeInformation.RuntimeIdentifier })
        {
            if (string.IsNullOrEmpty(rid)) continue;
            string p = Path.Combine(root, "runtimes", rid, "native", "dbgshim.dll");
            if (File.Exists(p)) return p;
            string p2 = Path.Combine(root, "runtimes", rid, "dbgshim.dll");
            if (File.Exists(p2)) return p2;
        }
        throw new FileNotFoundException($"dbgshim.dll not found under '{root}' (expected runtimes/win-{arch}/native/).");
    }
}

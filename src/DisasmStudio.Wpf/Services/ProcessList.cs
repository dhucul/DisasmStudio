using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

namespace DisasmStudio.Wpf.Services;

/// <summary>One running process, as shown in the attach picker. <see cref="Arch"/>/<see cref="Path"/> are
/// best-effort — a protected or higher-integrity process may refuse even limited-info queries, leaving them
/// blank ("?" / "").</summary>
internal sealed record ProcessEntry(uint Pid, string Name, string Title, string Arch, string Path);

/// <summary>Enumerates running processes for the attach dialog. Uses <see cref="Process"/> for the cheap
/// fields (id, name, window title) and a best-effort limited-info handle for architecture and full image
/// path — limited-info works cross-bitness and without elevation for most user processes.</summary>
internal static class ProcessList
{
    private const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint access, bool inherit, uint pid);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr h);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool IsWow64Process(IntPtr h, out bool wow64);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool QueryFullProcessImageNameW(IntPtr h, uint flags, StringBuilder buf, ref uint size);

    /// <summary>Snapshot of the current user-visible processes, sorted by name then pid. The host is 64-bit
    /// (the app requires x64), so a WOW64 process is x86 and everything else is x64.</summary>
    public static List<ProcessEntry> Enumerate()
    {
        var list = new List<ProcessEntry>();
        uint self = (uint)Environment.ProcessId;
        foreach (var p in Process.GetProcesses())
        {
            try
            {
                uint pid = (uint)p.Id;
                if (pid == 0 || pid == self) continue;   // System Idle, and our own process (self-attach deadlocks)

                string title = "";
                try { title = p.MainWindowTitle ?? ""; } catch { /* access denied on the title */ }

                string arch = "?";
                string path = "";
                IntPtr h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
                if (h != IntPtr.Zero)
                {
                    try
                    {
                        if (IsWow64Process(h, out bool wow)) arch = wow ? "x86" : "x64";
                        var sb = new StringBuilder(1024);
                        uint sz = (uint)sb.Capacity;
                        if (QueryFullProcessImageNameW(h, 0, sb, ref sz)) path = sb.ToString();
                    }
                    finally { CloseHandle(h); }
                }

                list.Add(new ProcessEntry(pid, p.ProcessName, title, arch, path));
            }
            catch { /* the process exited mid-enumeration */ }
            finally { p.Dispose(); }
        }
        return list.OrderBy(e => e.Name, StringComparer.OrdinalIgnoreCase).ThenBy(e => e.Pid).ToList();
    }
}

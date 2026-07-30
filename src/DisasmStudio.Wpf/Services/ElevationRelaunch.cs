using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Security.Principal;
using DisasmStudio.Debug;

namespace DisasmStudio.Wpf.Services;

internal enum ElevationRelaunchResult
{
    Started,
    Cancelled,
    Failed,
}

/// <summary>Starts a second copy through the Windows UAC broker; the caller owns its current-window lifecycle.</summary>
internal static class ElevationRelaunch
{
    private const int ErrorCancelled = 1223;

    public static bool IsCurrentProcessElevated()
    {
        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
        }
        catch
        {
            return false;
        }
    }

    public static ElevationRelaunchResult TryStart(
        DebugElevationRequest request,
        out Process? process,
        out string? error)
    {
        process = null;
        error = null;
        try
        {
            string executable = Environment.ProcessPath
                ?? throw new InvalidOperationException("The DisasmStudio executable path is unavailable.");
            string workingDirectory = !string.IsNullOrWhiteSpace(request.WorkingDirectory)
                && Directory.Exists(request.WorkingDirectory)
                ? request.WorkingDirectory
                : AppContext.BaseDirectory;
            var psi = new ProcessStartInfo(executable)
            {
                UseShellExecute = true,
                Verb = "runas",
                WorkingDirectory = workingDirectory,
            };
            foreach (string arg in request.ToArguments()) psi.ArgumentList.Add(arg);

            process = Process.Start(psi);
            if (process is null)
            {
                error = "Windows did not start the elevated process.";
                return ElevationRelaunchResult.Failed;
            }
            return ElevationRelaunchResult.Started;
        }
        catch (Win32Exception ex) when (ex.NativeErrorCode == ErrorCancelled)
        {
            return ElevationRelaunchResult.Cancelled;
        }
        catch (Exception ex)
        {
            error = ex.Message;
            return ElevationRelaunchResult.Failed;
        }
    }
}

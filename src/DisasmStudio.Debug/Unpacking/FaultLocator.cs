using System.Text;
using System.Threading;

namespace DisasmStudio.Debug.Unpacking;

/// <summary>The outcome of a fault-localization run.</summary>
/// <param name="Launched">True if the target was started under the debugger.</param>
/// <param name="Crashed">True if it died by a fault (captured) or an NTSTATUS-shaped exit code.</param>
/// <param name="ExitCode">The process exit code (0 if it didn't exit before the timeout).</param>
/// <param name="Fault">The first fatal fault, or null if none was captured.</param>
/// <param name="FirstChanceExceptions">Count of non-fatal first-chance exceptions seen before the kill.</param>
public sealed record FaultLocateResult(
    bool Launched, bool Crashed, uint ExitCode, FaultSnapshot? Fault, int FirstChanceExceptions, string Log);

/// <summary>
/// Diagnostic: launch a (rebuilt / suspect) executable under the debugger, run it to its first fatal fault, and
/// report exactly where it dies — module+offset, the faulting instruction, registers, and (for an access
/// violation) the inaccessible address and its page state. Answers "why won't this dump run?" with a concrete
/// fault site instead of a guess. It reuses the debugger's own fault localization
/// (<see cref="DebuggerEngine.CaptureFault"/>); first-chance exceptions are passed to the target (so its own SEH
/// runs) and only the fatal one is captured. The hide layer is OFF by default, so the target runs unmodified —
/// the closest approximation to a standalone launch (turn it on only to see how anti-debug changes the outcome).
/// </summary>
public static class FaultLocator
{
    /// <summary>Launch <paramref name="path"/> and report where it first dies. Blocks until the target faults,
    /// exits, or <paramref name="timeoutMs"/> elapses, then terminates it.</summary>
    public static FaultLocateResult Run(string path, bool hideFromDebugger = false, int timeoutMs = 25000,
        Action<string>? report = null)
    {
        var sb = new StringBuilder();
        void Log(string m) { sb.AppendLine(m); report?.Invoke(m); }

        var eng = new DebuggerEngine
        {
            PassFirstChanceExceptions = true,                 // let the target's own SEH run; only the kill matters
            HideFromDebugger = hideFromDebugger,
            HideInterceptRdtsc = hideFromDebugger,
            HideUseApiHooks = hideFromDebugger,
        };
        FaultSnapshot? fatal = null;
        int firstChance = 0;
        uint exitCode = 0;
        bool exited = false;
        using var done = new ManualResetEventSlim(false);

        eng.ExceptionObserved += e =>
        {
            bool isFatal = (e.Code & 0xF000_0000) == 0xC000_0000 || !e.FirstChance;
            if (!isFatal) { firstChance++; return; }
            fatal ??= eng.CaptureFault(e);                    // keep the first fatal fault — the death site
        };
        eng.Stopped += stop =>
        {
            if (stop.Reason == StopReason.Exception) { done.Set(); return; }
            try { eng.Go(); } catch { /* race with teardown */ }
        };
        eng.Exited += code => { exitCode = (uint)code; exited = true; done.Set(); };

        Log($"Launching {Path.GetFileName(path)} under the debugger (hide layer {(hideFromDebugger ? "on" : "off")})…");
        try { eng.Launch(path); }
        catch (Exception ex) { Log("Launch failed: " + ex.Message); return new FaultLocateResult(false, false, 0, null, 0, sb.ToString()); }

        done.Wait(timeoutMs);
        try { eng.Stop(); } catch { }

        if (fatal is { } f)
        {
            Log($"Fault: {f.CodeName} at {f.Address:X} in {f.Module}+{f.ModuleOffset:X} ({(f.FirstChance ? "first-chance" : "second-chance")}).");
            if (f.AccessDesc.Length > 0) Log($"  {f.AccessDesc} (target page: {f.MemState}).");
            if (f.Instruction.Length > 0) Log($"  faulting instruction: {f.Instruction}");
            if (f.Registers.Length > 0) Log($"  registers: {f.Registers}");
        }
        else if (exited) Log($"No fault captured; the target exited with code 0x{exitCode:X8}.");
        else Log("No fault captured — the target hung or kept running; stopped at the timeout.");

        bool crashed = fatal is not null || (exited && (exitCode & 0xF000_0000) == 0xC000_0000);
        return new FaultLocateResult(true, crashed, exitCode, fatal, firstChance, sb.ToString());
    }
}

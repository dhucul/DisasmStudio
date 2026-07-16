using System;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Threading;
using DisasmStudio.Debug;

namespace DisasmStudio.Wpf.Diagnostics;

/// <summary>
/// Hidden self-test for the whole-section EXECUTE software memory breakpoint (the Memory Map tab's
/// "Break on execute (section)" action → <see cref="MemAccess.Execute"/>). Launches a target under the native
/// <see cref="DebuggerEngine"/>, and at the first stop arms an execute memory breakpoint on the page covering the
/// (rebased) entry point, then continues. The engine strips the execute bit from those pages, so the first
/// instruction fetch there faults (ACCESS_VIOLATION, access-type 8) and must surface
/// <see cref="StopReason.MemoryBreakpoint"/> with <see cref="DebuggerEngine.LastMemoryHitAccess"/> == 8 inside the
/// watched range — proving <see cref="MemAccess.Execute"/> works end-to-end. Read/Write/ReadWrite are unchanged
/// code paths (the engine change is additive and gated on <c>needExec</c>), so this focuses on the new path.
/// Logs to the launching terminal and %TEMP%\ds_smoke_secbp.txt.
/// Usage: DisasmStudio.exe --smoke-secbp [exe] [seconds]
/// </summary>
internal static class SectionBpSmoke
{
    public static int Run(string? exe = null, int seconds = 8)
    {
        exe ??= Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "where.exe");
        var log = new StringBuilder();
        void Log(string s) { log.AppendLine(s); Console.WriteLine(s); }

        Log($"=== section execute-breakpoint smoke: {exe} ===");
        if (!File.Exists(exe)) { Log($"target not found: {exe}"); return 2; }

        bool pass = RunOnce(exe, seconds, Log);
        Log(pass ? "RESULT: PASS (execute mem-bp fired at the entry point, access=execute)"
                 : "RESULT: FAIL (no execute mem-bp hit — see timeline)");
        try { File.WriteAllText(Path.Combine(Path.GetTempPath(), "ds_smoke_secbp.txt"), log.ToString()); } catch { }
        return pass ? 0 : 1;
    }

    private static bool RunOnce(string exe, int seconds, Action<string> log)
    {
        var sw = Stopwatch.StartNew();
        string T() => $"[{sw.ElapsedMilliseconds,6}ms]";

        var eng = new DebuggerEngine();
        var done = new ManualResetEventSlim(false);
        bool armed = false, hit = false;
        ulong rangeLo = 0, rangeHi = 0, hitVa = 0;
        int hitAccess = -1;
        int resumeCount = 0;

        eng.Stopped += si =>
        {
            // First stop with the main image mapped: arm an execute watch on the entry page, then continue.
            if (!armed && eng.EntryPoint != 0)
            {
                ulong ep = eng.EntryPoint;
                rangeLo = ep; rangeHi = ep + 0x1000;
                eng.SetMemoryBreakpoint(ep, 0x1000, MemAccess.Execute);
                armed = true;
                log($"  {T()} armed EXECUTE mem-bp [{rangeLo:X}..{rangeHi:X}) at entry; first stop was {si.Reason} @ {si.Address:X}");
                eng.Go();
                return;
            }
            // The entry-point fetch should fault through as a MemoryBreakpoint.
            if (armed && si.Reason == StopReason.MemoryBreakpoint)
            {
                hit = true; hitVa = eng.LastMemoryHitVa; hitAccess = eng.LastMemoryHitAccess;
                log($"  {T()} HIT MemoryBreakpoint @ {si.Address:X}  dataVa={hitVa:X}  access={hitAccess}");
                eng.Stop();
                done.Set();
                return;
            }
            log($"  {T()} stop {si.Reason} @ {si.Address:X} (continuing)");
            if (resumeCount++ < 20000) eng.Go(); else { eng.Stop(); done.Set(); }
        };
        eng.Exited += code => { log($"  {T()} EXITED 0x{(uint)code:X8} (before the execute hit)"); done.Set(); };

        eng.Launch(exe);
        done.Wait(seconds * 1000);
        if (!done.IsSet) { log($"  {T()} timeout"); eng.Stop(); }
        Thread.Sleep(200);

        bool inRange = hitVa >= rangeLo && hitVa < rangeHi;
        log($"  => armed={armed} hit={hit} access={hitAccess} (want 8) hitVa={hitVa:X} inRange={inRange}");
        return hit && hitAccess == 8 && inRange;
    }
}

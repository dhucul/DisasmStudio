using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using DisasmStudio.Debug;

namespace DisasmStudio.Wpf.Diagnostics;

/// <summary>
/// Hidden self-test / diagnostic for the anti-anti-debug ("Hide from debugger") layer against a real
/// protected target, reproducing headlessly the "run the .NET Framework app under the native debugger" offer
/// path (<c>MainWindow.OfferNativeForFrameworkStartupCrash</c>). Launches the target under the native
/// <see cref="DebuggerEngine"/> twice — once with Hide OFF and once with Hide ON — and logs a timeline
/// (module loads, first/second-chance exceptions, stops, liveness, exit) so the effect of the hide layer on a
/// protected app's own anti-debug (the NtClose "bad handle" tricks: STATUS_INVALID_HANDLE 0xC0000008 and
/// STATUS_HANDLE_NOT_CLOSABLE 0xC0000235, and any detect-and-exit) is visible.
///   • Hide OFF should surface the anti-debug exception(s); the app cannot run past them.
///   • Hide ON should swallow them and let the app reach its message loop (still alive at the timeout).
/// Logs to the launching terminal and %TEMP%\ds_smoke_hidedbg.txt.
/// Usage: DisasmStudio.exe --smoke-hidedbg &lt;exe&gt; [seconds]
/// </summary>
internal static class HideDebugSmoke
{
    public static int Run(string exe, int seconds = 6)
    {
        var log = new StringBuilder();
        void Log(string s) { log.AppendLine(s); Console.WriteLine(s); }

        Log($"=== hide-from-debugger smoke: {exe}  (watch {seconds}s) ===");
        if (!File.Exists(exe)) { Log($"target not found: {exe}"); return 2; }

        var off = RunOnce(exe, hide: false, seconds, Log);
        var on = RunOnce(exe, hide: true, seconds, Log);

        // "Ran" = reached the message loop: still alive at the timeout with no fatal (second-chance) exception.
        bool offBlocked = off.AntiDebugExceptions.Count > 0 || !off.AliveAtTimeout;
        bool onRan = on.AliveAtTimeout && off.AntiDebugExceptions.Count >= 0; // ran to timeout
        Log("");
        Log($"hide OFF: anti-debug exceptions={string.Join(",", off.AntiDebugExceptions.Select(c => $"0x{c:X8}"))} " +
            $"exit=0x{(uint)off.ExitCode:X8} alive@timeout={off.AliveAtTimeout}");
        Log($"hide ON : anti-debug exceptions={string.Join(",", on.AntiDebugExceptions.Select(c => $"0x{c:X8}"))} " +
            $"exit=0x{(uint)on.ExitCode:X8} alive@timeout={on.AliveAtTimeout}");
        bool pass = offBlocked && onRan;
        Log(pass ? "RESULT: PASS (hide OFF blocked, hide ON ran to the message loop)"
                 : "RESULT: FAIL (hide ON did not reach a running message loop — see timeline)");
        try { File.WriteAllText(Path.Combine(Path.GetTempPath(), "ds_smoke_hidedbg.txt"), log.ToString()); } catch { }
        return pass ? 0 : 1;
    }

    private sealed class Outcome
    {
        public System.Collections.Generic.List<uint> AntiDebugExceptions = new();
        public bool AliveAtTimeout;
        public int ExitCode = int.MinValue;
    }

    private static Outcome RunOnce(string exe, bool hide, int seconds, Action<string> log)
    {
        log($"--- launch (hide={hide}) ---");
        var sw = Stopwatch.StartNew();
        string T() => $"[{sw.ElapsedMilliseconds,6}ms]";

        var eng = new DebuggerEngine { HideFromDebugger = hide };
        var outcome = new Outcome();
        var exited = new ManualResetEventSlim(false);
        int resumeCount = 0;

        eng.ExceptionObserved += ee =>
        {
            log($"  {T()} exception 0x{ee.Code:X8} @ 0x{ee.Address:X} firstChance={ee.FirstChance}");
            if (ee.Code is 0xC0000008 or 0xC0000235) outcome.AntiDebugExceptions.Add(ee.Code);
        };
        eng.Stopped += si =>
        {
            log($"  {T()} STOP {si.Reason} @ 0x{si.Address:X} code=0x{si.ExceptionCode:X8}");
            if (resumeCount++ < 20000) eng.Go(); else eng.Stop();   // keep the target moving past benign/passed events
        };
        eng.Exited += code => { outcome.ExitCode = code; log($"  {T()} EXITED code=0x{(uint)code:X8}"); exited.Set(); };

        eng.Launch(exe);

        // Heartbeat: watch module count climb (init progress) and note when the app is running (no outstanding stop).
        int lastMods = -1;
        while (sw.ElapsedMilliseconds < seconds * 1000 && !exited.IsSet)
        {
            Thread.Sleep(400);
            int mods; try { mods = eng.Modules.Count; } catch { mods = lastMods; }
            if (mods != lastMods) { log($"  {T()} modules={mods} stopped={eng.IsStopped}"); lastMods = mods; }
        }

        outcome.AliveAtTimeout = !exited.IsSet;
        log($"  {T()} => alive@timeout={outcome.AliveAtTimeout} modules={SafeMods(eng)} antiDebug={outcome.AntiDebugExceptions.Count}");
        eng.Stop();
        exited.Wait(3000);
        return outcome;
    }

    private static int SafeMods(DebuggerEngine e) { try { return e.Modules.Count; } catch { return -1; } }
}

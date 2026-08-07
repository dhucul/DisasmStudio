using System;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Windows.Threading;
using DisasmStudio.Debug;
using DisasmStudio.Debug.Unpacking;
using DisasmStudio.Wpf.Services;

namespace DisasmStudio.Wpf.Diagnostics;

/// <summary>
/// Hidden self-test for the "run to OEP" hunt as the application actually drives it — through
/// <see cref="DebugSession"/> on a real WPF <see cref="Dispatcher"/>, rather than by poking
/// <see cref="OepFinder"/> directly the way <see cref="OepHuntSmoke"/> does.
/// <para>
/// The two differ in exactly the places a hunt can silently disappear: the engine-thread stop routing, the
/// UI-thread <c>StartOepHunt</c> entry, the resume-ownership flag, and the outcome being stashed on one thread
/// and raised on another. This asserts the property that matters to the user — <b>a hunt always terminates with
/// exactly one OepHuntFinished</b>, whether it finds the OEP, fails, or the target exits underneath it.
/// </para>
/// Usage: DisasmStudio.exe --smoke-oep-session &lt;exe&gt; [seconds]
/// </summary>
internal static class OepSessionSmoke
{
    /// <param name="orphan">Arm the hunt on an address that is never executed, so it can never fire and the
    /// target runs to completion underneath it — the "it just ran and said nothing" report. The hunt must still
    /// report exactly one outcome when the process exits.</param>
    public static int Run(string? exe = null, int seconds = 25, bool orphan = false)
    {
        var log = new StringBuilder();
        void Log(string s) { log.AppendLine(s); Console.WriteLine(s); }

        Log($"=== run-to-OEP session smoke{(orphan ? " [orphan: hunt can never fire]" : "")}: {exe ?? "(no target)"} ===");
        if (exe is null || !File.Exists(exe)) { Log("usage: DisasmStudio.exe --smoke-oep-session <exe> [seconds]"); return 2; }

        var sw = Stopwatch.StartNew();
        string T() => $"[{sw.ElapsedMilliseconds,6}ms]";

        var ui = Dispatcher.CurrentDispatcher;
        var session = new DebugSession(ui, null);
        var frame = new DispatcherFrame();

        int outcomes = 0, stops = 0;
        bool huntStarted = false, exited = false;
        DebugSession.OepHuntResult? outcome = null;

        // UI-callback traffic while the hunt runs. Every engine resume raises Running, which DebugSession
        // marshals to the Dispatcher and MainWindow turns into a status-bar write plus three button updates.
        // The hunt resumes programmatically, so an unbounded stop rate becomes an unbounded flood of UI work —
        // the window stops responding until the hunt ends, then recovers.
        int engineRunning = 0, uiRunning = 0;
        session.Engine.Running += () => Interlocked.Increment(ref engineRunning);
        session.Running += () => uiRunning++;

        session.Stopped += () =>
        {
            stops++;
            Log($"  {T()} UI stop #{stops}: {session.LastReason} @ {session.CurrentIp:X}  hunting={session.IsHuntingOep}");
            if (!huntStarted && session.LastReason == StopReason.EntryPoint)
            {
                huntStarted = true;
                // Orphan mode breaks at a PE-header byte, which is committed and patchable but never executed.
                ulong? manual = orphan ? session.Engine.ImageBase + 2 : null;
                string? err = session.StartOepHunt(orphan ? OepMethod.Manual : OepMethod.Auto, manual, 0);
                Log($"  {T()} StartOepHunt → {(err is null ? "armed" : "REFUSED: " + err)}");
                if (err is not null) frame.Continue = false;
            }
        };
        session.OepHuntFinished += r =>
        {
            outcomes++;
            outcome = r;
            Log($"  {T()} OepHuntFinished #{outcomes}: found={r.Found} oep={r.Oep:X} method={r.Method} " +
                $"skipped={r.SkippedBreakpoints} error={r.Error ?? "(none)"}");
            frame.Continue = false;
        };
        session.Exited += code =>
        {
            exited = true;
            Log($"  {T()} session Exited 0x{(uint)code:X8} (outcomes so far: {outcomes})");
            frame.Continue = false;
        };

        var timeout = new DispatcherTimer(TimeSpan.FromSeconds(seconds), DispatcherPriority.Normal,
            (_, _) => { Log($"  {T()} TIMEOUT"); frame.Continue = false; }, ui);
        timeout.Start();

        session.Launch(exe);
        Dispatcher.PushFrame(frame);
        timeout.Stop();

        // Let a trailing Exited/outcome callback land before judging.
        var drain = new DispatcherFrame();
        new DispatcherTimer(TimeSpan.FromMilliseconds(600), DispatcherPriority.Normal,
            (_, _) => drain.Continue = false, ui).Start();
        Dispatcher.PushFrame(drain);

        Log($"  UI traffic: {engineRunning:N0} engine resumes → {uiRunning:N0} Running callbacks dispatched to the UI " +
            $"({sw.ElapsedMilliseconds:N0} ms, {(sw.ElapsedMilliseconds > 0 ? engineRunning * 1000L / sw.ElapsedMilliseconds : 0):N0}/s)");
        Log($"  timeline:\n{session.OepTimeline}");

        // A finished hunt must leave no trace on the session. Leaking PassFirstChanceExceptions=true would
        // silently disable the user's exception filter for the rest of the session; leaving guards armed would
        // strand the target with sections we made non-executable.
        bool pfcRestored = session.Engine.PassFirstChanceExceptions == false;
        bool guardsClear = !session.Engine.HasGuards;
        bool huntCleared = !session.IsHuntingOep;
        Log($"  => state after the hunt: PassFirstChanceExceptions restored={pfcRestored} " +
            $"guardsClear={guardsClear} huntCleared={huntCleared}");
        try { session.Stop(); } catch { }

        // The invariant: an armed hunt must always report exactly once and leave the session clean. Silence, or
        // a hunt that stays armed with nothing able to disarm it, are the bugs this smoke exists for.
        bool pass = huntStarted && outcomes == 1 && pfcRestored && guardsClear && huntCleared;
        Log($"  => huntStarted={huntStarted} outcomes={outcomes} exited={exited} " +
            $"outcome={(outcome is null ? "(none)" : outcome.Found ? $"OEP {outcome.Oep:X}" : outcome.Error)}");
        Log(pass ? "RESULT: PASS (the hunt reported exactly one outcome)"
                 : outcomes == 0 ? "RESULT: FAIL (the hunt vanished — no outcome was ever raised)"
                                 : $"RESULT: FAIL ({outcomes} outcomes)");
        try { File.WriteAllText(Path.Combine(Path.GetTempPath(), "ds_smoke_oep_session.txt"), log.ToString()); } catch { }
        return pass ? 0 : 1;
    }
}

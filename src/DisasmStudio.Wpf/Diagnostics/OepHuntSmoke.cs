using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using DisasmStudio.Core.Analysis;
using DisasmStudio.Core.Formats;
using DisasmStudio.Core.Unpacking;
using DisasmStudio.Debug;
using DisasmStudio.Debug.Unpacking;

namespace DisasmStudio.Wpf.Diagnostics;

/// <summary>
/// Hidden self-test for the interactive "▶◎ To OEP" hunt: launch a packed EXE, stop at the packer stub entry,
/// then drive <see cref="OepFinder"/> through the real <see cref="OepStopRouting"/> policy until it reports the
/// original entry point.
/// <para>
/// This covers what <c>UnpackSession</c> deliberately does not. That path dumps to a file and terminates the
/// target, so nothing else proves the properties the interactive feature depends on: the OEP lands in a section
/// the stub does not live in, the process is <b>still alive and steppable</b> afterwards, re-analysing the dump
/// with <see cref="AnalysisOptions.AssumeUnpacked"/> recovers the real program (rather than being narrowed back
/// onto the dead stub), and <see cref="OepFinder.Abort"/> leaves no guards behind.
/// </para>
/// Logs to the launching terminal and %TEMP%\ds_smoke_oep.txt.
/// Usage: DisasmStudio.exe --smoke-oep &lt;packed.exe&gt; [seconds]
/// </summary>
internal static class OepHuntSmoke
{
    public static int Run(string? exe = null, int seconds = 25)
    {
        var log = new StringBuilder();
        void Log(string s) { log.AppendLine(s); Console.WriteLine(s); }

        Log($"=== run-to-OEP smoke: {exe ?? "(no target)"} ===");
        if (exe is null)
        {
            Log("usage: DisasmStudio.exe --smoke-oep <packed.exe> [seconds]");
            Log("  Pack a small unsigned EXE first (a signed system binary fails UPX's own checks):");
            Log(@"    copy C:\Windows\System32\where.exe C:\tmp\where.exe && upx C:\tmp\where.exe");
            return 2;
        }
        if (!File.Exists(exe)) { Log($"target not found: {exe}"); return 2; }

        bool pass = RunOnce(exe, seconds, Log);
        Log(pass ? "RESULT: PASS (OEP reached outside the stub section; process still live and steppable; unpacked re-analysis recovered the program)"
                 : "RESULT: FAIL (see timeline)");
        try { File.WriteAllText(Path.Combine(Path.GetTempPath(), "ds_smoke_oep.txt"), log.ToString()); } catch { }
        return pass ? 0 : 1;
    }

    private static bool RunOnce(string exe, int seconds, Action<string> log)
    {
        var sw = Stopwatch.StartNew();
        string T() => $"[{sw.ElapsedMilliseconds,6}ms]";

        var eng = new DebuggerEngine
        {
            // The same pre-run configuration the interactive session applies for a packed target.
            PassFirstChanceExceptions = true,
            HideFromDebugger = true,
        };
        var finder = new OepFinder(OepMethod.Auto, null, 0);
        var done = new ManualResetEventSlim(false);

        bool started = false, huntResume = false;
        ulong oep = 0, stubEntry = 0;
        int skippedBps = 0, surfaced = 0;

        // Phase 2 of the test: once the OEP is reached, single-step to prove the process is still live.
        bool wantStep = false, stepped = false;
        ulong steppedIp = 0;

        eng.Stopped += si =>
        {
            if (!started)
            {
                if (si.Reason != StopReason.EntryPoint)
                {
                    log($"  {T()} pre-entry stop {si.Reason} @ {si.Address:X} (continuing)");
                    eng.Go();
                    return;
                }
                started = true;
                stubEntry = eng.EntryPoint;
                log($"  {T()} stub entry stop @ {si.Address:X} (EntryPoint {stubEntry:X}) — beginning hunt");
                try
                {
                    huntResume = true;
                    if (finder.Begin(eng) is { } immediate) { oep = immediate; done.Set(); }
                }
                catch (Exception ex) { log($"  {T()} hunt could not be armed: {ex.Message}"); done.Set(); }
                return;
            }

            if (wantStep)
            {
                stepped = true;
                steppedIp = eng.GetRegisters()?.Ip ?? si.Address;
                log($"  {T()} post-OEP step stop {si.Reason} @ {steppedIp:X}");
                done.Set();
                return;
            }

            // Route through the real policy, so the smoke exercises the shipped decision table rather than a copy.
            bool owns;
            try { owns = finder.Owns(eng, si); } catch { owns = false; }
            var route = OepStopRouting.Decide(true, huntResume, owns, si.Reason);
            log($"  {T()} stop {si.Reason} @ {si.Address:X}  owns={owns} → {route}");

            switch (route)
            {
                case OepRoute.Resume:
                    skippedBps++;
                    huntResume = true;
                    eng.Go();
                    return;
                case OepRoute.Forward:
                    try
                    {
                        if (finder.OnStop(eng, si) is { } found) { oep = found; done.Set(); }
                        else huntResume = true;
                    }
                    catch (Exception ex) { log($"  {T()} finder threw: {ex.Message}"); done.Set(); }
                    return;
                default:
                    surfaced++;
                    huntResume = false;
                    if (si.Reason == StopReason.ProcessExited) { done.Set(); return; }
                    // Nothing is driving this run interactively, so keep going rather than stalling.
                    eng.Go();
                    return;
            }
        };
        eng.Exited += code =>
        {
            log(oep == 0 ? $"  {T()} EXITED 0x{(uint)code:X8} before the OEP was reached"
                         : $"  {T()} EXITED 0x{(uint)code:X8} (teardown)");
            done.Set();
        };

        eng.Launch(exe);
        done.Wait(seconds * 1000);
        if (oep == 0)
        {
            log($"  {T()} no OEP (timeout or early exit). finder log:\n{finder.Log}");
            eng.Stop();
            Thread.Sleep(200);
            return false;
        }

        log($"  {T()} OEP {oep:X} via {finder.ActiveMethod} ({skippedBps} breakpoint hit(s) skipped, {surfaced} surfaced)");
        log(finder.Log.TrimEnd());

        // 1. The OEP must be outside the section the stub lives in — otherwise the guard fired on the stub itself.
        bool outsideStub = SectionOf(eng, oep) is { } oepSec && SectionOf(eng, stubEntry) is { } stubSec
                           && oepSec != stubSec;
        log($"  => OEP section {SectionOf(eng, oep) ?? 0:X}, stub section {SectionOf(eng, stubEntry) ?? 0:X}, distinct={outsideStub}");

        // 2. The bytes there should look like a function prologue.
        // On a target that isn't actually packed there is no OEP to find: the guard simply catches the first
        // cross-section transfer (typically an import thunk), which is not a prologue. Failing here is the
        // correct answer for such a target — it is the signal that this smoke needs a genuinely packed EXE.
        bool prologue = false;
        try { prologue = OepValidator.LooksLikeOep(eng.ReadMemory(oep, 32), eng.Is32); } catch { }
        log($"  => prologue recognised: {prologue}"
            + (prologue ? "" : "  (expected on a target that isn't packed — the guard caught an ordinary cross-section jump)"));

        // 3. Re-analysis from the unpacked image must recover the real program, seeded at the OEP, and must NOT
        //    be narrowed back onto the loader stub.
        bool reanalyzed = false;
        int functions = 0;
        string? entryName = null;
        bool restricted = true;
        try
        {
            var dump = eng.DumpImage(eng.ImageBase, out _);
            if (PeMemoryImage.TryLoadFromBytes(dump, eng.ImageBase, exe, out var img, entryVaOverride: oep))
            {
                var res = AnalysisEngine.Analyze(img, new AnalysisOptions { AssumeUnpacked = true });
                restricted = res.PackedAnalysisRestricted;
                functions = res.Functions.Count;
                res.Names.TryGetValue(oep, out entryName);
                reanalyzed = !restricted && functions > 0 && entryName == "start";
            }
        }
        catch (Exception ex) { log($"  => re-analysis threw: {ex.Message}"); }
        log($"  => re-analysis: restricted={restricted} functions={functions:N0} name@OEP={entryName ?? "(none)"} ok={reanalyzed}");

        // 4. The process must still be live and steppable — the whole point of the interactive hunt.
        done.Reset();
        wantStep = true;
        eng.StepInto();
        done.Wait(5000);
        bool live = stepped && steppedIp != 0;
        log($"  => still steppable: {live} (IP after step {steppedIp:X})");

        // 5. Aborting must leave no guards behind.
        try { finder.Abort(eng); } catch (Exception ex) { log($"  => abort threw: {ex.Message}"); }
        bool guardsCleared = !eng.HasGuards;
        log($"  => guards cleared after Abort: {guardsCleared}");

        eng.Stop();
        Thread.Sleep(200);
        return outsideStub && prologue && reanalyzed && live && guardsCleared;
    }

    /// <summary>The base VA of the mapped section containing <paramref name="va"/>, or null.</summary>
    private static ulong? SectionOf(DebuggerEngine eng, ulong va)
    {
        try
        {
            if (!PeView.TryParse(eng.ReadMemory(eng.ImageBase, 0x1000), out var view)) return null;
            foreach (var s in view.Sections)
            {
                ulong lo = eng.ImageBase + s.VirtualAddress;
                ulong hi = lo + Math.Max(s.VirtualSize, s.SizeOfRawData);
                if (va >= lo && va < hi) return lo;
            }
        }
        catch { }
        return null;
    }
}

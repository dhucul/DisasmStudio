using System.Runtime.InteropServices;
using DisasmStudio.Core.Unpacking;

namespace DisasmStudio.Debug.Unpacking;

/// <summary>Tuning for the auto-timing watch (<see cref="NonInvasiveDumper.DumpWhenSettled"/>).</summary>
/// <param name="PollIntervalMs">How often to sample the watched code region.</param>
/// <param name="MaxWaitMs">Overall ceiling; dump the current state when reached.</param>
/// <param name="StablePolls">Consecutive unchanged samples before the image counts as settled (and 2× this as
/// fully quiescent, which dumps even if the body stays high-entropy — e.g. a virtualizer).</param>
/// <param name="EntropyThreshold">Code entropy below this reads as decrypted.</param>
/// <param name="UseInputIdle">Also accept a GUI's input-idle as a settle signal (best-effort).</param>
public sealed record AutoTimingOptions(
    int PollIntervalMs = 500,
    int MaxWaitMs = 30000,
    int StablePolls = 4,
    double EntropyThreshold = 7.0,
    bool UseInputIdle = true);

/// <summary>Where to launch a target for launch-and-watch (<see cref="NonInvasiveDumper.LaunchAndDump"/>).</summary>
public sealed record LaunchWatchOptions(
    string TargetPath,
    string? Arguments = null,
    string? WorkingDirectory = null,
    bool Sandbox = true);

/// <summary>Outcome of a non-invasive dump. <see cref="RawOutputPath"/> is set when the in-memory header had to
/// be reconstructed (a protector wiped it): the raw VA-indexed memory image, openable at the image base, is a
/// reliable artifact even if the rebuilt PE is imperfect.</summary>
public sealed record NonInvasiveDumpResult(
    bool Ok, ulong ImageBase, int Bitness, uint SizeOfImage,
    int ModuleCount, int ExportCount, int ImportsResolved, int ImportsUnresolved,
    double HottestExecEntropy, string? HottestExecSection,
    string? OutputPath, string? Error, string Log, string? RawOutputPath = null, string? SnapshotOutputPath = null);

/// <summary>
/// Dumps a running process's main image to a clean, re-analyzable PE <b>without debugging it</b>. Where the
/// generic unpacker drives the target under a debugger (which a hardened protector can detect and sabotage
/// before it ever decrypts), this attaches no debugger at all: the user runs the protected target normally —
/// so every <c>IsDebuggerPresent</c> / debug-port / debug-object check passes and the program decrypts itself —
/// then this opens it read-only via <see cref="Native.OpenProcess"/> with <c>PROCESS_VM_READ</c> and snapshots
/// it from the outside. A passive cross-process reader is not "being debugged", so the protector's anti-debug
/// cannot see it.
///
/// <para>The cost is timing: there is no OEP trace, so the caller decides <i>when</i> the image is decrypted
/// (typically once the app's window is up or it has gone idle) and dumps then. The snapshot reuses the same
/// dump → IAT-rebuild → PE-writer pipeline as the debugger-driven unpacker, with the PE header's entry as a
/// best-effort OEP. For a <i>virtualized</i> function the recovered code stays virtualized — feed the dump to
/// the devirtualizer — but for merely packed/encrypted code this recovers the real bytes.</para>
/// </summary>
public static class NonInvasiveDumper
{
    private const uint PROCESS_QUERY_INFORMATION = 0x0400;
    private const uint PROCESS_VM_READ = 0x0010;
    private const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
    private const uint PROCESS_SUSPEND_RESUME = 0x0800;

    /// <summary>Dump the main image of process <paramref name="pid"/> to <paramref name="outputPath"/>.</summary>
    /// <param name="suspend">Freeze the target's threads for a consistent snapshot, then thaw them (best-effort).</param>
    /// <param name="preferredImageBase">The file's preferred image base (for the rebuilt PE / relocation choice).</param>
    public static NonInvasiveDumpResult Dump(int pid, string outputPath, bool suspend,
        ulong preferredImageBase, Action<string>? report = null, string? snapshotPath = null)
    {
        var sb = new System.Text.StringBuilder();
        string? rawPath = null, snapPath = null;
        void Log(string m) { sb.AppendLine(m); report?.Invoke(m); }
        NonInvasiveDumpResult Fail(string error) { Log("FAILED: " + error); return new NonInvasiveDumpResult(false, 0, 0, 0, 0, 0, 0, 0, 0, null, null, error, sb.ToString(), rawPath, snapPath); }

        // Request suspend rights too; fall back to read-only if that's denied (e.g. cross-integrity).
        IntPtr h = Native.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SUSPEND_RESUME, false, (uint)pid);
        bool canSuspend = h != IntPtr.Zero;
        if (h == IntPtr.Zero)
            h = Native.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFORMATION, false, (uint)pid);
        if (h == IntPtr.Zero)
            return Fail($"OpenProcess(pid {pid}) failed (Win32 error {Marshal.GetLastWin32Error()}). The process may have exited, or be higher-integrity — try running DisasmStudio as administrator.");

        bool suspended = false;
        try
        {
            var modules = EnumerateModules(h, pid, out string? mainPath, out ulong mainBase);
            if (mainBase == 0 || modules.Count == 0)
                return Fail("Could not enumerate the target's modules (EnumProcessModules failed). A 32-bit DisasmStudio cannot read a 64-bit target; this build is x64, so check the PID and access rights.");
            Log($"PID {pid}: {modules.Count} module(s); main image '{Path.GetFileName(mainPath ?? "?")}' @ {mainBase:X}.");

            if (suspend)
            {
                if (!canSuspend)
                    Log("Suspend requested but PROCESS_SUSPEND_RESUME was denied; dumping live (a moving target may be slightly inconsistent).");
                else
                {
                    int st = Native.NtSuspendProcess(h);
                    suspended = st >= 0;
                    Log(suspended ? "Froze the target's threads for a consistent snapshot."
                                  : $"NtSuspendProcess failed (status 0x{st:X8}); dumping live.");
                }
            }

            MemReader read = MakeReader(h);

            var image = MemoryImageDump.Dump(h, mainBase, read, out uint sizeOfImage, out var regions);
            if (image.Length == 0 || !PeView.TryParse(image, out var view))
                return Fail("Could not read or parse the target image. If it is a protector that decrypts lazily, let it run further (open its UI / let it idle) before dumping.");
            int bitness = view.Is64 ? 64 : 32;
            Log($"Dumped {sizeOfImage:X} bytes from base {mainBase:X} ({bitness}-bit).");

            // A protector (Themida/WinLicense-class) may wipe its own section table in memory as an anti-dump
            // measure, leaving an image PeBuilder can't lay out. Detect that, drop a raw copy of the decrypted
            // image as a reliable fallback (openable at the image base), then reconstruct the section table from
            // the committed-memory region map so the rebuilt PE can re-parse.
            if (DumpRepair.NeedsReconstruction(view, sizeOfImage))
            {
                Log("In-memory PE header has no usable section table (a protector anti-dump measure).");
                rawPath = WriteRaw(outputPath, image, Log);
                if (DumpRepair.TryReconstruct(image, view, sizeOfImage, regions, Log, out var repaired))
                    view = repaired;
            }

            // Decryption indicator: a still-encrypted body reads as near-maximal entropy.
            var hot = view.Sections.Where(s => s.IsExecutable)
                                   .OrderByDescending(s => Math.Max(s.VirtualSize, s.SizeOfRawData))
                                   .FirstOrDefault();
            double hotEnt = 0; string? hotName = null;
            if (hot is not null)
            {
                int len = (int)Math.Min(Math.Max(hot.VirtualSize, hot.SizeOfRawData), 1u << 20);
                if (len > 0 && (ulong)hot.VirtualAddress + (ulong)len <= sizeOfImage)
                {
                    var bytes = new byte[len];
                    Array.Copy(image, hot.VirtualAddress, bytes, 0, len);
                    hotEnt = Entropy.Shannon(bytes);
                    hotName = hot.Name;
                    Log($"Largest exec section '{hot.Name}' entropy {hotEnt:F2} — {(hotEnt > 7.0 ? "still packed/encrypted (dump again after it has decrypted)" : "looks decrypted")}.");
                }
            }

            var resolver = new ModuleExportResolver(modules, read);
            Log($"Indexed {resolver.ModuleCount} module(s), {resolver.ExportCount} export(s).");

            // Recover the real OEP. The PE header entry is the packer/protector STUB; a dump run from the stub
            // re-runs it over already-unpacked bytes and crashes, so a runnable rebuild needs the original entry.
            // OepScanner finds the stub's tail jump to it. Falls back to the header entry (analysis-only) if not
            // found. The recovered OEP also anchors the IAT code-scan at the real code, improving import location.
            uint oepRva = view.EntryRva;
            ulong recovered = OepScanner.FindOep(read, view, mainBase, view.Is64);
            if (recovered > mainBase && recovered < mainBase + sizeOfImage)
            {
                oepRva = (uint)(recovered - mainBase);
                Log($"Recovered OEP at {recovered:X} (RVA {oepRva:X}); header/stub entry was {mainBase + view.EntryRva:X}.");
            }
            else
                Log("Using the header entry as the OEP (it already looks like a valid entry, or no packer-stub tail " +
                    "was found). If the target is packed, the rebuilt PE may re-run the stub rather than the original.");

            ulong oepVa = mainBase + oepRva;
            var iat = ImportRebuilder.Rebuild(read, resolver, view, mainBase, oepVa);
            foreach (var line in iat.Log.Split('\n', StringSplitOptions.RemoveEmptyEntries)) Log(line);

            var outBytes = PeBuilder.Build(image, view, oepRva, iat.Ok ? iat : null, mainBase, preferredImageBase, out var buildLog);
            foreach (var line in buildLog.Split('\n', StringSplitOptions.RemoveEmptyEntries)) Log(line);

            try { File.WriteAllBytes(outputPath, outBytes); }
            catch (Exception ex) { return Fail("Failed to write output file: " + ex.Message); }
            Log($"Wrote {outputPath}.");

            // Optional full process snapshot: capture the private (heap/VM) regions too — while the process is
            // still open and frozen — so a protector's separately-allocated VM context is included.
            if (snapshotPath is not null && ProcessSnapshot.CaptureToFile(h, mainBase, bitness, snapshotPath, Log) > 0)
                snapPath = snapshotPath;

            return new NonInvasiveDumpResult(true, mainBase, bitness, sizeOfImage, resolver.ModuleCount,
                resolver.ExportCount, iat.Resolved, iat.Unresolved, hotEnt, hotName, outputPath, null, sb.ToString(), rawPath, snapPath);
        }
        catch (Exception ex)
        {
            return Fail("Unexpected error: " + ex.Message);
        }
        finally
        {
            if (suspended) Native.NtResumeProcess(h);
            Native.CloseHandle(h);
        }
    }

    /// <summary>Watch a running target until its main image <i>settles</i> — its largest code section stops
    /// changing (the unpack/decrypt stub has finished writing it) and either looks decrypted or the app has gone
    /// input-idle — then take the <see cref="Dump"/>. This removes the guesswork of "when has it decrypted": you
    /// just launch the target and the dumper picks the moment. Falls back to dumping the current state on a
    /// timeout, if the target exits, or if no code section can be watched. <paramref name="cancelled"/> lets the
    /// UI abort the wait.</summary>
    public static NonInvasiveDumpResult DumpWhenSettled(int pid, string outputPath, bool suspend,
        ulong preferredImageBase, AutoTimingOptions opt, Action<string>? report = null, Func<bool>? cancelled = null,
        string? snapshotPath = null)
    {
        void Log(string m) => report?.Invoke(m);

        // A read-only handle just for watching; the final Dump opens its own (and may add suspend rights).
        IntPtr h = Native.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFORMATION, false, (uint)pid);
        if (h == IntPtr.Zero)
            return Dump(pid, outputPath, suspend, preferredImageBase, report, snapshotPath);   // surface the real OpenProcess error via the normal path

        bool wasCancelled = false, exited = false;
        try
        {
            var read = MakeReader(h);
            // A just-launched / just-resumed target may not have its module list populated yet — retry briefly so
            // launch-and-watch can begin from t=0 without giving up before the main image is even mapped.
            (ulong Va, int Len)? section = null;
            long bootStart = Environment.TickCount64;
            long bootDeadline = bootStart + Math.Min(opt.MaxWaitMs, 5000);
            while (true)
            {
                if (cancelled?.Invoke() == true) { Log("Auto-timing: cancelled by user."); wasCancelled = true; break; }
                EnumerateModules(h, pid, out _, out ulong mainBase);
                section = mainBase != 0 ? HottestExecSection(read, mainBase) : null;
                if (section is not null) break;
                if (ProcessGone(h)) { Log("Auto-timing: the target exited before its image mapped."); exited = true; break; }
                if (Environment.TickCount64 >= bootDeadline) break;
                Thread.Sleep(Math.Min(opt.PollIntervalMs, 100));
            }

            if (!wasCancelled && section is null && !exited)
            {
                // No executable section to time against — typically a protector that has wiped its in-memory PE
                // header (the section table / exec flags) as an anti-dump measure, so "settled" can't be detected.
                // Don't snapshot at ~t0: wait out the rest of the max-wait budget blind so the unpack/decrypt stub
                // has time to run, then dump. (The normal "module not mapped yet" case finds a section in <1s and
                // never reaches here.)
                long elapsed = Environment.TickCount64 - bootStart;
                int blind = (int)Math.Max(0, opt.MaxWaitMs - elapsed);
                if (blind > 0)
                {
                    Log($"Auto-timing: no watchable code section (the protector likely wiped the PE header) — waiting " +
                        $"{blind / 1000.0:F0}s blind for it to decrypt, then dumping.");
                    long until = Environment.TickCount64 + blind;
                    while (Environment.TickCount64 < until)
                    {
                        if (cancelled?.Invoke() == true) { Log("Auto-timing: cancelled by user."); wasCancelled = true; break; }
                        if (ProcessGone(h)) { Log("Auto-timing: the target exited during the blind wait."); exited = true; break; }
                        Thread.Sleep(Math.Min(opt.PollIntervalMs, 250));
                    }
                }
                if (!wasCancelled && !exited) Log("Auto-timing: blind wait elapsed; dumping the current state.");
            }
            else if (!wasCancelled && section is null)
            {
                Log("Auto-timing: no readable code section to watch; dumping the current state.");
            }
            else if (!wasCancelled)
            {
                (ulong secVa, int secLen) = section!.Value;
                Log($"Auto-timing: watching {secLen:X}-byte code region @ {secVa:X} (poll {opt.PollIntervalMs} ms, max {opt.MaxWaitMs / 1000.0:F0} s, settle after {opt.StablePolls} stable polls)…");
                long start = Environment.TickCount64;
                int stable = 0, polls = 0; ulong lastHash = 0; bool haveLast = false;
                while (true)
                {
                    if (cancelled?.Invoke() == true) { Log("Auto-timing: cancelled by user."); wasCancelled = true; break; }
                    if (Environment.TickCount64 - start > opt.MaxWaitMs)
                    {
                        Log($"Auto-timing: reached the {opt.MaxWaitMs / 1000.0:F0}s limit after {polls} poll(s); dumping the current state (it may not be fully decrypted).");
                        break;
                    }
                    if (!ProbeSection(read, secVa, secLen, out double ent, out ulong hash))
                    {
                        if (ProcessGone(h)) { Log("Auto-timing: the target exited before it settled."); exited = true; break; }
                        Thread.Sleep(opt.PollIntervalMs);
                        continue;
                    }
                    polls++;
                    bool same = haveLast && hash == lastHash;
                    stable = same ? stable + 1 : 0;
                    lastHash = hash; haveLast = true;
                    bool idle = opt.UseInputIdle && InputIdle(h);
                    bool decrypted = ent < opt.EntropyThreshold;

                    // Settle when the code has stopped changing AND looks decrypted (or the app is idle); also
                    // settle on a fully-quiescent image even if it stays high-entropy (a virtualizer's body never
                    // drops) so we don't always wait out the whole timeout for VM-protected targets.
                    if (stable >= opt.StablePolls && (decrypted || idle))
                    {
                        Log($"Auto-timing: settled after {polls} poll(s) — {(decrypted ? $"code entropy {ent:F2} < {opt.EntropyThreshold:F1}" : $"input-idle (entropy {ent:F2})")}, stable for {stable} poll(s).");
                        break;
                    }
                    if (stable >= opt.StablePolls * 2)
                    {
                        Log($"Auto-timing: image fully quiescent after {polls} poll(s) (entropy {ent:F2}, stable for {stable} poll(s)); dumping{(decrypted ? "" : " — still high-entropy, likely virtualized")}.");
                        break;
                    }
                    Log($"  poll {polls}: entropy {ent:F2}{(same ? $" (stable x{stable})" : " (changed)")}{(idle ? " idle" : "")}");
                    Thread.Sleep(opt.PollIntervalMs);
                }
            }
        }
        catch (Exception ex)
        {
            Log("Auto-timing watch error: " + ex.Message + " — dumping the current state.");
        }
        finally
        {
            Native.CloseHandle(h);
        }

        if (wasCancelled)
            return new NonInvasiveDumpResult(false, 0, 0, 0, 0, 0, 0, 0, 0, null, null, "Cancelled before dumping.", "");
        if (exited)
            return new NonInvasiveDumpResult(false, 0, 0, 0, 0, 0, 0, 0, 0, null, null,
                "The target exited before its image settled — nothing to dump. If it ran entirely inside a VM (a pure virtualizer) there is no decrypted native image to capture.", "");
        return Dump(pid, outputPath, suspend, preferredImageBase, report, snapshotPath);
    }

    /// <summary>Launch the target ourselves (NO debugger), watch it from the very first instruction, and
    /// <see cref="DumpWhenSettled"/> when its image settles — then terminate it. This is the turnkey form: the
    /// user points at an EXE instead of pre-launching it and picking a PID. The target is created
    /// <c>CREATE_SUSPENDED</c> so the watch is armed before any of its code (incl. the unpack/decrypt stub) runs,
    /// optionally placed in a kill-on-close job sandbox, then resumed. Because we are not its debugger, its
    /// anti-debug passes exactly as in a normal run.</summary>
    public static NonInvasiveDumpResult LaunchAndDump(LaunchWatchOptions launch, string outputPath, bool suspend,
        ulong preferredImageBase, AutoTimingOptions opt, Action<string>? report = null, Func<bool>? cancelled = null,
        string? snapshotPath = null)
    {
        var sb = new System.Text.StringBuilder();
        void Log(string m) { sb.AppendLine(m); report?.Invoke(m); }
        NonInvasiveDumpResult Err(string e) { Log("FAILED: " + e); return new NonInvasiveDumpResult(false, 0, 0, 0, 0, 0, 0, 0, 0, null, null, e, sb.ToString()); }

        if (string.IsNullOrWhiteSpace(launch.TargetPath) || !File.Exists(launch.TargetPath))
            return Err($"Target executable not found: {launch.TargetPath}");

        if (preferredImageBase == 0) preferredImageBase = TryReadPreferredBase(launch.TargetPath);

        // argv0 must be quoted; CreateProcessW writes into lpCommandLine, so hand it a fresh string.
        string cmdline = "\"" + launch.TargetPath + "\""
                       + (string.IsNullOrWhiteSpace(launch.Arguments) ? "" : " " + launch.Arguments);
        // null (not "") lets CreateProcessW inherit the parent's current directory; "" is an invalid directory.
        string? workDir = !string.IsNullOrWhiteSpace(launch.WorkingDirectory)
            ? launch.WorkingDirectory
            : Path.GetDirectoryName(launch.TargetPath);
        if (string.IsNullOrEmpty(workDir)) workDir = null;

        var si = new Native.STARTUPINFO();
        si.cb = (uint)Marshal.SizeOf<Native.STARTUPINFO>();

        // CREATE_SUSPENDED → arm the watch at t=0; CREATE_NEW_CONSOLE → a console target doesn't write into ours;
        // CREATE_BREAKAWAY_FROM_JOB → we can job-contain it even when the host (Terminal/VS) is itself in a job.
        // Retry without breakaway if the host's job forbids it.
        Log($"Launching {Path.GetFileName(launch.TargetPath)} suspended (no debugger)…");
        uint flags = Native.CREATE_SUSPENDED | Native.CREATE_NEW_CONSOLE | Native.CREATE_BREAKAWAY_FROM_JOB;
        if (!Native.CreateProcessW(null, cmdline, IntPtr.Zero, IntPtr.Zero, false, flags, IntPtr.Zero, workDir, ref si, out var pi))
        {
            int err1 = Marshal.GetLastWin32Error();
            flags = Native.CREATE_SUSPENDED | Native.CREATE_NEW_CONSOLE;
            if (!Native.CreateProcessW(null, cmdline, IntPtr.Zero, IntPtr.Zero, false, flags, IntPtr.Zero, workDir, ref si, out pi))
            {
                int err2 = Marshal.GetLastWin32Error();
                return Err(err1 == 740 || err2 == 740
                    ? "the target requests elevation. Run DisasmStudio as administrator, or start the target yourself and use 'Attach to running process'."
                    : $"CreateProcess failed (Win32 error {err2}).");
            }
        }

        IntPtr job = IntPtr.Zero;
        try
        {
            if (launch.Sandbox)
            {
                job = TrySetupJob(pi, Log);
                if (job == IntPtr.Zero)
                    return Err("sandbox containment could not be established; the target was not resumed. Disable Sandbox explicitly to run without containment.");
            }
            Native.ResumeThread(pi.hThread);   // the target now starts running; we already hold its PID to watch
            Log($"Launched pid {pi.dwProcessId}; watching from start.");
            return DumpWhenSettled((int)pi.dwProcessId, outputPath, suspend, preferredImageBase, opt, report, cancelled, snapshotPath);
        }
        catch (Exception ex) { return Err("Unexpected error: " + ex.Message); }
        finally
        {
            try { Native.TerminateProcess(pi.hProcess, 0); } catch { }
            if (job != IntPtr.Zero) Native.CloseHandle(job);   // kill-on-close reaps any survivor
            Native.CloseHandle(pi.hThread);
            Native.CloseHandle(pi.hProcess);
        }
    }

    /// <summary>Create a kill-on-close, one-process job and assign the freshly-launched target to it (mirrors the
    /// unpacker's containment). Returns the job handle to keep alive, or IntPtr.Zero when containment could not
    /// be established. Process-level only — use a VM for truly untrusted samples.</summary>
    private static IntPtr TrySetupJob(Native.PROCESS_INFORMATION pi, Action<string> log)
    {
        IntPtr job = Native.CreateJobObjectW(IntPtr.Zero, null);
        if (job == IntPtr.Zero) { log("Sandbox: CreateJobObject failed."); return IntPtr.Zero; }
        var info = new Native.JOBOBJECT_EXTENDED_LIMIT_INFORMATION();
        info.BasicLimitInformation.LimitFlags = Native.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | Native.JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
        info.BasicLimitInformation.ActiveProcessLimit = 1;   // block child-process spawning
        uint sz = (uint)Marshal.SizeOf<Native.JOBOBJECT_EXTENDED_LIMIT_INFORMATION>();
        if (!Native.SetInformationJobObject(job, Native.JobObjectExtendedLimitInformation, ref info, sz))
        {
            log($"Sandbox: SetInformationJobObject failed (err {Marshal.GetLastWin32Error()}).");
            Native.CloseHandle(job);
            return IntPtr.Zero;
        }
        if (Native.AssignProcessToJobObject(job, pi.hProcess))
        {
            log("Sandbox: job containment active (kill-on-close, child processes blocked).");
            return job;
        }
        int err = Marshal.GetLastWin32Error();
        log($"Sandbox: AssignProcessToJobObject failed (err {err}).");
        Native.CloseHandle(job);
        return IntPtr.Zero;
    }

    /// <summary>Read a PE's preferred ImageBase from its on-disk header, for the rebuilt PE's relocation choice
    /// when launch-and-watch doesn't have the matching binary open. 0 if it can't be read.</summary>
    private static ulong TryReadPreferredBase(string path)
    {
        try
        {
            using var fs = File.OpenRead(path);
            var buf = new byte[0x1000];
            int n = fs.Read(buf, 0, buf.Length);
            if (n < 0x200) return 0;
            if (n < buf.Length) Array.Resize(ref buf, n);
            return PeView.TryParse(buf, out var v) ? v.ImageBase : 0;
        }
        catch { return 0; }
    }

    /// <summary>Write the raw VA-indexed memory image beside the rebuilt PE (a reliable artifact when the header
    /// had to be reconstructed). The user opens it as a raw binary at the image base. Returns the path or null.</summary>
    private static string? WriteRaw(string outputPath, byte[] image, Action<string> log)
    {
        try
        {
            string dir = Path.GetDirectoryName(outputPath) ?? ".";
            string raw = Path.Combine(dir, Path.GetFileNameWithoutExtension(outputPath) + "_raw.bin");
            File.WriteAllBytes(raw, image);
            log($"Wrote raw decrypted memory image to {raw} ({image.Length} bytes) — open it as a raw binary at the " +
                "image base to inspect the decrypted bytes even if the rebuilt PE is imperfect.");
            return raw;
        }
        catch (Exception ex) { log("Raw dump write failed: " + ex.Message); return null; }
    }

    /// <summary>A page-tolerant cross-process reader over <paramref name="h"/>: a single ReadProcessMemory, and
    /// on failure a page-by-page recovery so a request that straddles an unreadable gap still returns its
    /// readable prefix (matching the debugger's ReadMemory semantics).</summary>
    private static MemReader MakeReader(IntPtr h) => (va, count) =>
    {
        if (count <= 0) return [];
        var buf = new byte[count];
        if (Native.ReadProcessMemory(h, va, buf, (nuint)count, out var got))
        {
            if ((int)got != count) Array.Resize(ref buf, (int)got);
            return buf;
        }
        return ReadPaged(h, va, count);
    };

    /// <summary>The absolute VA + sample length of the largest executable section of the image at
    /// <paramref name="mainBase"/> (the region most likely to be rewritten by an unpack/decrypt stub), or null
    /// if the header can't be read/parsed yet. Section VAs are fixed at runtime, so this is found once.</summary>
    private static (ulong Va, int Len)? HottestExecSection(MemReader read, ulong mainBase)
    {
        var hdr = read(mainBase, 0x1000);
        if (hdr.Length < 0x200 || !PeView.TryParse(hdr, out var view)) return null;
        var hot = view.Sections.Where(s => s.IsExecutable)
                               .OrderByDescending(s => Math.Max(s.VirtualSize, s.SizeOfRawData))
                               .FirstOrDefault();
        if (hot is null) return null;
        int len = (int)Math.Min(Math.Max(hot.VirtualSize, hot.SizeOfRawData), 1u << 20);
        return len > 0 ? (mainBase + hot.VirtualAddress, len) : null;
    }

    /// <summary>Read the watched region and report its Shannon entropy and a cheap change-detection hash.
    /// Returns false if the region can't currently be read (process mid-teardown or not yet committed).</summary>
    private static bool ProbeSection(MemReader read, ulong va, int len, out double entropy, out ulong hash)
    {
        entropy = 0; hash = 0;
        var bytes = read(va, len);
        if (bytes.Length == 0) return false;
        entropy = Entropy.Shannon(bytes);
        hash = Fnv1a(bytes);
        return true;
    }

    private static ulong Fnv1a(byte[] data)
    {
        ulong h = 1469598103934665603UL;
        foreach (byte b in data) { h ^= b; h *= 1099511628211UL; }
        return h;
    }

    private static bool ProcessGone(IntPtr h) =>
        Native.GetExitCodeProcess(h, out uint code) && code != Native.STILL_ACTIVE;

    private static bool InputIdle(IntPtr h) => Native.WaitForInputIdle(h, 0) == 0;

    /// <summary>Enumerate the target's modules into (base, path) pairs. The first HMODULE is the main image;
    /// an HMODULE <i>is</i> the module's load base, so no extra query is needed for the address.</summary>
    private static List<ModuleInfo> EnumerateModules(IntPtr h, int pid, out string? mainPath, out ulong mainBase)
    {
        mainPath = null; mainBase = 0;

        // A 32-bit (WOW64) target: EnumProcessModules from this x64 process returns the 64-bit module view,
        // whose kernel32/ntdll bases differ from the 32-bit ones the target actually imports through — so the
        // IAT can't resolve. Enumerate the target's *32-bit* modules via a Toolhelp snapshot instead.
        if (Native.IsWow64Process(h, out bool isWow) && isWow)
        {
            var wow = EnumerateModulesToolhelp(pid, out mainPath, out mainBase);
            if (wow.Count > 0) return wow;   // else fall through to the EnumProcessModules path
        }

        var list = new List<ModuleInfo>();
        var hmods = new IntPtr[1024];
        if (!Native.EnumProcessModules(h, hmods, (uint)(hmods.Length * IntPtr.Size), out uint needed))
            return list;
        int count = Math.Min((int)(needed / (uint)IntPtr.Size), hmods.Length);
        var nameBuf = new char[260];
        for (int i = 0; i < count; i++)
        {
            ulong baseVa = (ulong)hmods[i];
            uint len = Native.GetModuleFileNameEx(h, baseVa, nameBuf, (uint)nameBuf.Length);
            string path = len > 0 ? new string(nameBuf, 0, (int)len) : $"module_{baseVa:X}";
            list.Add(new ModuleInfo(baseVa, path));
            if (i == 0) { mainBase = baseVa; mainPath = path; }
        }
        return list;
    }

    /// <summary>Enumerate a 32-bit (WOW64) target's 32-bit modules via a Toolhelp snapshot (the first entry is
    /// the main image; modBaseAddr is the 32-bit load base). Empty list if the snapshot couldn't be taken.</summary>
    private static List<ModuleInfo> EnumerateModulesToolhelp(int pid, out string? mainPath, out ulong mainBase)
    {
        mainPath = null; mainBase = 0;
        var list = new List<ModuleInfo>();
        IntPtr snap = Native.CreateToolhelp32Snapshot(Native.TH32CS_SNAPMODULE | Native.TH32CS_SNAPMODULE32, (uint)pid);
        if (snap == Native.INVALID_HANDLE_VALUE) return list;
        try
        {
            var me = new Native.MODULEENTRY32W { dwSize = (uint)Marshal.SizeOf<Native.MODULEENTRY32W>() };
            if (!Native.Module32FirstW(snap, ref me)) return list;
            do
            {
                ulong baseVa = (ulong)me.modBaseAddr.ToInt64() & 0xFFFF_FFFFUL;
                string path = !string.IsNullOrEmpty(me.szExePath) ? me.szExePath
                            : !string.IsNullOrEmpty(me.szModule) ? me.szModule
                            : $"module_{baseVa:X}";
                list.Add(new ModuleInfo(baseVa, path));
                if (list.Count == 1) { mainBase = baseVa; mainPath = path; }
                me.dwSize = (uint)Marshal.SizeOf<Native.MODULEENTRY32W>();
            }
            while (Native.Module32NextW(snap, ref me));
        }
        finally { Native.CloseHandle(snap); }
        return list;
    }

    /// <summary>Read <paramref name="count"/> bytes one page at a time, stopping at the first unreadable page,
    /// so a request that straddles a decommitted/guard gap still returns the readable prefix (as ReadMemory does).</summary>
    private static byte[] ReadPaged(IntPtr h, ulong va, int count)
    {
        var outBuf = new byte[count];
        int done = 0;
        while (done < count)
        {
            ulong cur = va + (ulong)done;
            int chunk = Math.Min(0x1000 - (int)(cur & 0xFFF), count - done);
            var tmp = new byte[chunk];
            if (!Native.ReadProcessMemory(h, cur, tmp, (nuint)chunk, out var got) || got == 0) break;
            Array.Copy(tmp, 0, outBuf, done, (int)got);
            done += (int)got;
            if ((int)got != chunk) break;
        }
        if (done != count) Array.Resize(ref outBuf, done);
        return outBuf;
    }
}

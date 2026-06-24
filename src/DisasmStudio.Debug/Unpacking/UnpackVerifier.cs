using System.Runtime.InteropServices;
using System.Threading;
using DisasmStudio.Core.Unpacking;

namespace DisasmStudio.Debug.Unpacking;

/// <summary>The classified outcome of running a rebuilt/unpacked PE.</summary>
public enum UnpackVerdict
{
    /// <summary>It executed without an unhandled crash — the unpack looks good.</summary>
    Runs,
    /// <summary>Transferred to runtime-only memory (virtualized / self-modifying / a pointer captured mid-run);
    /// not recoverable by static unpacking.</summary>
    RuntimeDependent,
    /// <summary>Executed into a non-executable section — the OEP is wrong or the exec-extent cap clipped code.</summary>
    ExecutedData,
    /// <summary>Faulted touching the IAT/import area — imports weren't bound.</summary>
    ImportBinding,
    /// <summary>Exited with an NTSTATUS and no localizable fault — the loader rejected/failed the image.</summary>
    LoaderRejected,
    /// <summary>Faulted inside a system module called from the image — likely a wrong IAT slot / bad args.</summary>
    ApiMisuse,
    /// <summary>Crashed, but the cause doesn't match a known pattern.</summary>
    UnknownCrash,
    /// <summary>The image couldn't be launched at all.</summary>
    LaunchFailed,
}

/// <summary>The verdict plus a human summary and the captured fault (if any).</summary>
public sealed record VerifyResult(UnpackVerdict Verdict, string Summary, FaultSnapshot? Fault);

/// <summary>
/// Post-unpack self-test: does a rebuilt PE run, and if not, WHICH stage of the unpack failed?
/// <para>
/// The run/crash verdict comes from a <b>standalone</b> launch (no debugger) — its exit code is the ground
/// truth, because attaching a debugger and passing first-chance exceptions can change the target's behavior
/// (a protector's SEH may "handle" an access violation under a debugger yet the same image crashes standalone).
/// Only when the standalone run actually crashes do we re-launch it under <see cref="FaultLocator"/> to
/// <i>localize</i> the fault, and classify by its shape: an execute fault into unmapped / out-of-image memory is
/// a transfer to runtime-only state (virtualized / self-modifying — not statically recoverable); an execute
/// fault into a non-executable section means the OEP is wrong or the exec-extent cap clipped real code; a
/// read/write fault in the IAT/import area means imports weren't bound; an NTSTATUS exit with no localizable
/// fault means the loader rejected the image.
/// </para>
/// NOTE: this executes the unpacked target — only call it on output you intend to run.
/// </summary>
public static class UnpackVerifier
{
    private const uint STILL_ACTIVE = 259;

    public static VerifyResult Verify(string rebuiltPath, bool sandbox = true, Action<string>? report = null, int settleMs = 6000)
    {
        // 1) Ground truth: run it standalone (no debugger) and read the exit code.
        report?.Invoke($"Running {System.IO.Path.GetFileName(rebuiltPath)} standalone{(sandbox ? " (sandboxed)" : "")} for up to {settleMs / 1000}s…");
        var (launched, ranClean, exited, exitCode) = RunStandalone(rebuiltPath, sandbox, settleMs, report);
        if (!launched)
            return Done(UnpackVerdict.LaunchFailed, "Could not launch the rebuilt image.", null, report);
        if (ranClean)
            return Done(UnpackVerdict.Runs,
                $"RUNS — {(exited ? $"exited cleanly (code 0x{exitCode:X8})" : "still alive")} after {settleMs / 1000}s " +
                "standalone with no unhandled crash. A clean survival of the watch window, not a proof of full correctness.", null, report);

        // 2) It crashed standalone. Re-launch under the debugger only to localize the fault.
        report?.Invoke($"Crashed standalone (exit 0x{exitCode:X8}); localizing the fault under the debugger…");
        var r = FaultLocator.Run(rebuiltPath, hideFromDebugger: false, timeoutMs: settleMs, report, sandbox);

        if (r.Fault is null)
            return Done(UnpackVerdict.LoaderRejected,
                $"CRASHED — exited 0x{exitCode:X8}" +
                (exitCode == 0xC000007B ? " (STATUS_INVALID_IMAGE_FORMAT — import directory, CFG, or relocations are wrong)" : "") +
                ", and no fault site reproduced under the debugger: most likely a load/init failure.", null, report);

        var f = r.Fault;
        TryParse(rebuiltPath, out var view);
        ulong baseVa = r.ImageBase != 0 ? r.ImageBase : view?.ImageBase ?? 0;
        ulong size = view?.SizeOfImage ?? 0;
        ulong fa = f.FaultAddress;

        if (f.AccessType == 8)   // execute fault: control reached fa and the CPU couldn't fetch from it
        {
            bool inImage = view is not null && baseVa != 0 && fa >= baseVa && fa < baseVa + size;
            bool dead = Unmapped(f.MemState);
            if (!inImage || dead)
                return Done(UnpackVerdict.RuntimeDependent,
                    $"NOT RECOVERABLE — executed into {(dead ? "unmapped" : "out-of-image")} memory at {fa:X}. The code " +
                    "transfers to runtime-only memory (virtualized / self-modifying, or a pointer captured mid-run); a " +
                    "static dump can't carry that. Not a fixable unpack.", f, report);

            var sec = SectionContaining(view!, baseVa, fa);
            if (sec is { IsExecutable: false })
                return Done(UnpackVerdict.ExecutedData,
                    $"OEP / EXEC-MARKING — executed into the non-executable section '{sec.Name}' at {fa:X}. The entry/OEP " +
                    "is wrong, or the executable-extent cap marked real code as data. Widen the exec window or re-find the OEP.", f, report);

            return Done(UnpackVerdict.UnknownCrash, $"Execute fault at {fa:X} inside an executable region ({f.CodeName}).", f, report);
        }

        if (view is not null && baseVa != 0)
        {
            var (iatRva, iatSize) = view.DataDir(PeConstants.DirIat);
            var (impRva, impSize) = view.DataDir(PeConstants.DirImport);
            if (InRange(fa, baseVa + iatRva, iatSize) || InRange(fa, baseVa + impRva, impSize))
                return Done(UnpackVerdict.ImportBinding,
                    $"IMPORTS — faulted touching the import area at {fa:X}: an IAT slot wasn't bound (import directory / " +
                    "FirstThunk mismatch). Check the rebuilt import table.", f, report);
        }

        string tgt = System.IO.Path.GetFileName(rebuiltPath);
        if (f.Module is { Length: > 0 } m && !m.Equals(tgt, StringComparison.OrdinalIgnoreCase))
            return Done(UnpackVerdict.ApiMisuse,
                $"BAD IMPORT? — faulted inside {m}+{f.ModuleOffset:X} (reached from the rebuilt image): likely a wrong IAT " +
                $"slot resolving to the wrong export, or bad arguments ({f.AccessDesc}).", f, report);

        return Done(UnpackVerdict.UnknownCrash, $"{f.CodeName} at {f.Address:X} in {f.Module}+{f.ModuleOffset:X} ({f.AccessDesc}).", f, report);
    }

    /// <summary>Launch the image with no debugger (optionally job-sandboxed), watch up to <paramref name="waitMs"/>,
    /// then terminate it. ranClean = it survived the window or exited with a non-NTSTATUS code.</summary>
    private static (bool launched, bool ranClean, bool exited, uint exitCode) RunStandalone(string path, bool sandbox, int waitMs, Action<string>? report)
    {
        if (!System.IO.File.Exists(path)) { report?.Invoke($"Target not found: {path}"); return (false, false, false, 0); }

        var si = new Native.STARTUPINFO();
        si.cb = (uint)Marshal.SizeOf<Native.STARTUPINFO>();
        string? dir = System.IO.Path.GetDirectoryName(path);
        if (string.IsNullOrEmpty(dir)) dir = null;

        // lpApplicationName = path, lpCommandLine = null: CreateProcessW uses the app path as argv0 (mirrors the
        // debugger's launch). Run from the exe's own directory so it can find adjacent files.
        uint flags = Native.CREATE_SUSPENDED | Native.CREATE_NEW_CONSOLE | Native.CREATE_BREAKAWAY_FROM_JOB;
        if (!Native.CreateProcessW(path, null, IntPtr.Zero, IntPtr.Zero, false, flags, IntPtr.Zero, dir, ref si, out var pi))
        {
            int err1 = Marshal.GetLastWin32Error();
            flags = Native.CREATE_SUSPENDED | Native.CREATE_NEW_CONSOLE;
            if (!Native.CreateProcessW(path, null, IntPtr.Zero, IntPtr.Zero, false, flags, IntPtr.Zero, dir, ref si, out pi))
            {
                report?.Invoke($"CreateProcess failed (err {err1} with breakaway, err {Marshal.GetLastWin32Error()} without).");
                return (false, false, false, 0);
            }
        }

        IntPtr job = IntPtr.Zero;
        try
        {
            if (sandbox) job = TrySetupJob(pi.hProcess);
            Native.ResumeThread(pi.hThread);

            uint code = STILL_ACTIVE;
            long deadline = Environment.TickCount64 + waitMs;
            while (Environment.TickCount64 < deadline)
            {
                if (Native.GetExitCodeProcess(pi.hProcess, out code) && code != STILL_ACTIVE) break;
                Thread.Sleep(80);
            }
            bool exited = code != STILL_ACTIVE;
            bool ranClean = !exited || (code & 0xF000_0000) != 0xC000_0000;
            return (true, ranClean, exited, exited ? code : 0);
        }
        finally
        {
            try { Native.TerminateProcess(pi.hProcess, 0); } catch { }
            if (job != IntPtr.Zero) Native.CloseHandle(job);
            Native.CloseHandle(pi.hThread);
            Native.CloseHandle(pi.hProcess);
        }
    }

    private static IntPtr TrySetupJob(IntPtr hProcess)
    {
        if (Native.IsProcessInJob(hProcess, IntPtr.Zero, out bool already) && already) return IntPtr.Zero;
        IntPtr job = Native.CreateJobObjectW(IntPtr.Zero, null);
        if (job == IntPtr.Zero) return IntPtr.Zero;
        var info = new Native.JOBOBJECT_EXTENDED_LIMIT_INFORMATION();
        info.BasicLimitInformation.LimitFlags = Native.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | Native.JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
        info.BasicLimitInformation.ActiveProcessLimit = 1;
        uint sz = (uint)Marshal.SizeOf<Native.JOBOBJECT_EXTENDED_LIMIT_INFORMATION>();
        Native.SetInformationJobObject(job, Native.JobObjectExtendedLimitInformation, ref info, sz);
        if (Native.AssignProcessToJobObject(job, hProcess)) return job;
        Native.CloseHandle(job);
        return IntPtr.Zero;
    }

    private static VerifyResult Done(UnpackVerdict v, string s, FaultSnapshot? f, Action<string>? report)
    {
        report?.Invoke("Verdict: " + s);
        return new VerifyResult(v, s, f);
    }

    private static bool Unmapped(string memState) =>
        memState.Contains("free", StringComparison.OrdinalIgnoreCase) ||
        memState.Contains("unmapped", StringComparison.OrdinalIgnoreCase) ||
        memState.Contains("reserved", StringComparison.OrdinalIgnoreCase);

    private static bool InRange(ulong va, ulong start, uint len) => len != 0 && va >= start && va < start + len;

    private static void TryParse(string path, out PeView? view)
    {
        view = null;
        try { if (PeView.TryParse(System.IO.File.ReadAllBytes(path), out var v)) view = v; } catch { }
    }

    private static SectionHeader? SectionContaining(PeView view, ulong baseVa, ulong va)
    {
        if (va < baseVa) return null;
        uint rva = (uint)(va - baseVa);
        foreach (var s in view.Sections)
        {
            uint sz = Math.Max(s.VirtualSize, s.SizeOfRawData);
            if (rva >= s.VirtualAddress && rva < s.VirtualAddress + sz) return s;
        }
        return null;
    }
}

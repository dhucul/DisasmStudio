using System.IO;
using System.Reflection.PortableExecutable;
using DisasmStudio.ManagedDebug;
using DisasmStudio.Wpf.Services;

namespace DisasmStudio.Wpf.Diagnostics;

/// <summary>Hidden self-test for the managed (.NET) source-level debug path: drives the REAL
/// <see cref="ManagedDebugClient"/> (the same code the Run button uses) against a .NET assembly — locate the
/// host, launch, arm a breakpoint at the entry method, hit it, report the frame/locals, continue to exit.
/// Prints to the launching terminal and exits. Reproduces the GUI Run flow without a window.</summary>
internal static class ManagedDebugSmoke
{
    public static int Run(string path)
    {
        // A GUI-subsystem exe's attached-console output is unreliable — also tee to a temp file we can read.
        try { Console.SetOut(new StreamWriter(Path.Combine(Path.GetTempPath(), "ds_smoke_mdbg.txt"), append: false) { AutoFlush = true }); } catch { }

        // Accept either the managed .dll or the apphost .exe; the managed module is the .dll.
        string dll = path.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) && File.Exists(Path.ChangeExtension(path, ".dll"))
            ? Path.ChangeExtension(path, ".dll")! : path;
        if (!File.Exists(dll)) { Console.WriteLine($"not found: {dll}"); return 2; }

        int epToken;
        try
        {
            using var fs = File.OpenRead(dll);
            using var pe = new PEReader(fs);
            var cor = pe.PEHeaders.CorHeader;
            if (cor is null) { Console.WriteLine($"{Path.GetFileName(dll)} is not a managed assembly (no COR header)."); return 2; }
            epToken = cor.EntryPointTokenOrRelativeVirtualAddress;
        }
        catch (Exception ex) { Console.WriteLine("PE read failed: " + ex.Message); return 2; }

        string module = Path.GetFileName(dll);
        Console.WriteLine($"entry method token = 0x{epToken:X8} in {module}");
        if ((epToken & 0xFF000000) != 0x06000000)   // table byte must be 0x06 (MethodDef)
            Console.WriteLine($"WARNING: entry token 0x{epToken:X8} is not a MethodDef (0x06……) — a library with no entry point can't be launched.");

        // Same target/bitness/host selection as MainWindow.StartManagedDebug.
        string exe = Path.ChangeExtension(dll, ".exe");
        string target; string? args = null; int bitness;
        if (File.Exists(exe)) { target = exe; bitness = PeBitness(exe) ?? 64; }
        else { target = "dotnet"; args = $"\"{dll}\""; bitness = 64; }
        bool framework = !File.Exists(Path.ChangeExtension(dll, ".runtimeconfig.json"));   // no runtimeconfig ⇒ .NET Framework
        if (framework && target == "dotnet") { Console.WriteLine("refusing: a .NET Framework library (no .exe) can't be launched (mirrors StartManagedDebug)."); return 2; }
        string? host = ManagedDebugHostLocator.Find(bitness);
        Console.WriteLine($"launch target = {target}{(args is null ? "" : " " + args)}");
        Console.WriteLine($"bitness = {bitness}  framework = {framework}  host = {host ?? "<NOT FOUND>"}");
        if (host is null)
        {
            Console.WriteLine("FAIL: managed-debug host exe not found for this bitness (build/publish DisasmStudio.ManagedDbgHost).");
            return 3;
        }

        var sw = System.Diagnostics.Stopwatch.StartNew();
        void Log(string m) => Console.WriteLine($"  [{sw.ElapsedMilliseconds,6}ms] {m}");

        var client = new ManagedDebugClient(host, showConsole: false);
        var done = new ManualResetEventSlim(false);
        int stops = 0, modules = 0, pid = 0; bool exited = false; string? err = null;
        client.EventReceived += ev =>
        {
            switch (ev.Ev)
            {
                case Mdbg.Launched: pid = ev.Pid; Log($"launched pid={pid}"); break;
                case Mdbg.ModuleLoaded: modules++; if (modules <= 6) Log($"module {ev.Module}"); break;
                case Mdbg.Stopped:
                    stops++;
                    var top = ev.Frames is { Length: > 0 } fr ? fr[0] : null;
                    string detail = string.IsNullOrEmpty(ev.Message) ? "" : $"  «{ev.Message}»";
                    Log($"STOPPED {ev.Reason} top={(top is null ? "-" : $"{top.Module}!0x{top.Token:X8}+IL{top.IlOffset}")} locals={ev.Locals?.Length}{detail}");
                    client.Go();
                    break;
                case Mdbg.Exited: Log($"EXITED code={ev.Code}"); exited = true; done.Set(); break;
                case Mdbg.Error: err = ev.Message; Log($"ERROR {ev.Message}"); done.Set(); break;
            }
        };

        client.Start();
        client.Launch(target, args, Path.GetDirectoryName(dll), [new BpLoc(module, epToken, 0, 1)], framework);

        // Watchdog: if the target is still running after 3s (a long-running target we'll Go past its breakpoint),
        // kill it — simulating the user closing the program — so we can time the teardown.
        _ = Task.Run(async () =>
        {
            await Task.Delay(3000);
            if (!done.IsSet && pid != 0)
            {
                try { Log($"killing debuggee pid={pid} (simulate the user closing the program)"); System.Diagnostics.Process.GetProcessById(pid).Kill(); }
                catch (Exception ex) { Log("kill failed: " + ex.Message); }
            }
        });

        if (!done.Wait(TimeSpan.FromSeconds(90)))
            Log("TIMEOUT: no exit within 90s");

        Log("disposing client…");
        var dsw = System.Diagnostics.Stopwatch.StartNew();
        client.Dispose();
        Log($"client.Dispose() returned after {dsw.ElapsedMilliseconds}ms");

        Console.WriteLine($"\nstops={stops} exited={exited} error={err ?? "(none)"}  total={sw.ElapsedMilliseconds}ms");
        return exited ? 0 : 1;
    }

    private static int? PeBitness(string path)
    {
        try
        {
            using var fs = File.OpenRead(path);
            using var pe = new PEReader(fs);
            return pe.PEHeaders.PEHeader?.Magic == PEMagic.PE32Plus ? 64 : 32;
        }
        catch { return null; }
    }
}

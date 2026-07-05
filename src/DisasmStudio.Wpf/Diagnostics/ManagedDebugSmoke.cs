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
        if ((epToken & 0x06000000) != 0x06000000)
            Console.WriteLine($"WARNING: entry token 0x{epToken:X8} is not a MethodDef (0x06……) — a library with no entry point can't be launched.");

        // Same target/bitness/host selection as MainWindow.StartManagedDebug.
        string exe = Path.ChangeExtension(dll, ".exe");
        string target; string? args = null; int bitness;
        if (File.Exists(exe)) { target = exe; bitness = PeBitness(exe) ?? 64; }
        else { target = "dotnet"; args = $"\"{dll}\""; bitness = 64; }
        string? host = ManagedDebugHostLocator.Find(bitness);
        Console.WriteLine($"launch target = {target}{(args is null ? "" : " " + args)}");
        Console.WriteLine($"bitness = {bitness}  host = {host ?? "<NOT FOUND>"}");
        if (host is null)
        {
            Console.WriteLine("FAIL: managed-debug host exe not found for this bitness (build/publish DisasmStudio.ManagedDbgHost).");
            return 3;
        }

        var client = new ManagedDebugClient(host);
        var done = new ManualResetEventSlim(false);
        int stops = 0, modules = 0; bool exited = false; string? err = null;
        client.EventReceived += ev =>
        {
            switch (ev.Ev)
            {
                case Mdbg.Launched: Console.WriteLine($"  ev launched pid={ev.Pid}"); break;
                case Mdbg.ModuleLoaded: modules++; if (modules <= 6) Console.WriteLine($"  ev module {ev.Module}"); break;
                case Mdbg.Stopped:
                    stops++;
                    var top = ev.Frames is { Length: > 0 } fr ? fr[0] : null;
                    Console.WriteLine($"  ev STOPPED {ev.Reason} frames={ev.Frames?.Length} " +
                                      $"top={(top is null ? "-" : $"{top.Module}!0x{top.Token:X8}+IL{top.IlOffset}")} locals={ev.Locals?.Length}");
                    if (ev.Locals is not null)
                        foreach (var l in ev.Locals) Console.WriteLine($"      {(l.IsArg ? "(arg) " : "")}{l.Name} : {l.Type} = {l.Value}");
                    client.Go();
                    break;
                case Mdbg.Exited: Console.WriteLine($"  ev EXITED code={ev.Code}"); exited = true; done.Set(); break;
                case Mdbg.Error: err = ev.Message; Console.WriteLine($"  ev ERROR {ev.Message}"); break;
            }
        };

        client.Start();
        client.Launch(target, args, Path.GetDirectoryName(dll), [new BpLoc(module, epToken, 0, 1)]);

        if (!done.Wait(TimeSpan.FromSeconds(40)))
        {
            Console.WriteLine("TIMEOUT: no exit within 40s (stops so far = " + stops + ")");
            client.Dispose();
            return 4;
        }
        client.Dispose();

        Console.WriteLine($"\nstops={stops} exited={exited} error={err ?? "(none)"}");
        bool pass = stops >= 1 && exited && err is null;
        Console.WriteLine(pass ? "PASS: managed debug launched, hit the entry breakpoint, and exited" : "FAIL");
        return pass ? 0 : 1;
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

using System.IO;
using System.IO.Pipes;
using DisasmStudio.ManagedDebug;
using DisasmStudio.ManagedDbgHost;

// Out-of-process managed-debug host. The app spawns this (bitness matched to the target), passing a named
// pipe it already created; we connect back and exchange newline-delimited JSON (MdbgCommand in, MdbgEvent out).
// All ICorDebug / dbgshim usage is confined to this process, isolating the app from the debuggee's runtime.

string? pipeName = null;
for (int i = 0; i < args.Length - 1; i++)
    if (args[i] == "--pipe") pipeName = args[i + 1];
if (pipeName is null) { Console.Error.WriteLine("usage: DisasmStudio.ManagedDbgHost --pipe <name>"); return 2; }

using var pipe = new NamedPipeClientStream(".", pipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
try { pipe.Connect(15000); }
catch (Exception ex) { Console.Error.WriteLine("pipe connect failed: " + ex.Message); return 2; }

using var reader = new StreamReader(pipe);
var writer = new StreamWriter(pipe) { AutoFlush = true };
var writeLock = new object();

void Emit(MdbgEvent ev)
{
    lock (writeLock)
    {
        try { writer.WriteLine(MdbgJson.ToLine(ev)); } catch { /* pipe gone */ }
    }
}

ManagedDebugEngine engine;
try { engine = new ManagedDebugEngine(Emit); }
catch (Exception ex) { Emit(new MdbgEvent { Ev = Mdbg.Error, Message = "engine init failed: " + ex.Message }); return 1; }

string? line;
while ((line = reader.ReadLine()) is not null)
{
    MdbgCommand? cmd;
    try { cmd = MdbgJson.FromLine<MdbgCommand>(line); } catch { continue; }
    if (cmd is null) continue;
    try
    {
        switch (cmd.Cmd)
        {
            case Mdbg.Launch:
                // Launch (register-for-startup + wait + attach) can take seconds; run it off the command-reader
                // thread so Stop/Quit stay responsive if the target's runtime never starts (e.g. a wrong-runtime target).
                var lc = cmd;
                _ = Task.Run(() =>
                {
                    try { engine.Launch(lc.Target!, lc.Args, lc.Cwd, lc.Breakpoints, lc.Framework); }
                    catch (Exception ex)
                    {
                        Emit(new MdbgEvent { Ev = Mdbg.Error, Message = ex.Message });
                        Emit(new MdbgEvent { Ev = Mdbg.Exited, Code = Mdbg.LaunchFailedExitCode });
                    }
                });
                break;
            case Mdbg.SetBreakpoint: if (cmd.Bp is not null) engine.SetBreakpoint(cmd.Bp); break;
            case Mdbg.RemoveBreakpoint: engine.RemoveBreakpoint(cmd.Id); break;
            case Mdbg.Go: engine.Go(); break;
            case Mdbg.StepInto: engine.Step(Mdbg.StepInto, cmd.Range); break;
            case Mdbg.StepOver: engine.Step(Mdbg.StepOver, cmd.Range); break;
            case Mdbg.StepOut: engine.Step(Mdbg.StepOut, cmd.Range); break;
            case Mdbg.Pause: engine.Pause(); break;
            case Mdbg.Stop: engine.Stop(); break;
            case Mdbg.Detach: engine.Detach(); break;
            case Mdbg.Quit: engine.Stop(); return 0;   // terminate the debuggee, then exit
        }
    }
    catch (Exception ex) { Emit(new MdbgEvent { Ev = Mdbg.Error, Message = ex.Message }); }
}
// Pipe closed (the app went away) — terminate the debuggee so it isn't orphaned. A prior Detach makes this a no-op.
engine.Stop();
return 0;

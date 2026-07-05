using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using DisasmStudio.ManagedDebug;

namespace DisasmStudio.Wpf.Services;

/// <summary>Locates the out-of-process managed-debug host exe matching the target's bitness. In a deployed
/// layout the per-RID hosts live under <c>mdbghost/win-{x86,x64}/</c>; in a dev build the x64 host is the
/// sibling project's build output (an x86 target needs a win-x86 publish — see Phase 5).</summary>
internal static class ManagedDebugHostLocator
{
    private const string HostExe = "DisasmStudio.ManagedDbgHost.exe";

    public static string? Find(int bitness)
    {
        string rid = bitness == 32 ? "win-x86" : "win-x64";
        string baseDir = AppContext.BaseDirectory;
        foreach (var c in Candidates(baseDir, rid))
            if (File.Exists(c)) return c;
        return null;
    }

    private static IEnumerable<string> Candidates(string baseDir, string rid)
    {
        yield return Path.Combine(baseDir, "mdbghost", rid, HostExe);   // deploy: per-RID
        yield return Path.Combine(baseDir, HostExe);                    // flat (single bitness)
        // Dev: sibling project output (base = src/DisasmStudio.Wpf/bin/<cfg>/net10.0).
        foreach (var cfg in new[] { "Debug", "Release" })
        {
            string hostBin = Path.GetFullPath(Path.Combine(baseDir, "..", "..", "..", "..", "DisasmStudio.ManagedDbgHost", "bin", cfg, "net10.0"));
            if (rid == "win-x64") yield return Path.Combine(hostBin, HostExe);   // plain dev build is x64
            yield return Path.Combine(hostBin, rid, "publish", HostExe);         // per-RID publish
        }
    }
}

/// <summary>Owns the named-pipe connection to one managed-debug host process: spawns it, exchanges
/// newline-delimited JSON (<see cref="MdbgCommand"/> out, <see cref="MdbgEvent"/> in), and raises
/// <see cref="EventReceived"/> on a background thread (the session marshals to the UI).</summary>
internal sealed class ManagedDebugClient : IDisposable
{
    private readonly string _hostPath;
    private readonly bool _showConsole;   // give the host (and thus the debuggee) a console — only for console targets
    private NamedPipeServerStream? _pipe;
    private Process? _host;
    private StreamReader? _reader;
    private StreamWriter? _writer;
    private readonly object _writeLock = new();
    private readonly Queue<string> _sendQueue = new();   // buffers commands issued before the pipe connects
    private volatile bool _disposed;
    private volatile bool _sawExit;                       // a real "exited" event arrived (suppress the synthetic one)

    public event Action<MdbgEvent>? EventReceived;

    public ManagedDebugClient(string hostPath, bool showConsole)
    {
        _hostPath = hostPath;
        _showConsole = showConsole;
    }

    public void Start()
    {
        string pipeName = "disasmstudio-mdbg-" + Guid.NewGuid().ToString("N");
        _pipe = new NamedPipeServerStream(pipeName, PipeDirection.InOut, 1, PipeTransmissionMode.Byte, PipeOptions.Asynchronous);

        // The debuggee inherits the host's console (dbgshim's CreateProcessForLaunch can't request its own), so
        // give the host a console ONLY for a console target — otherwise a GUI target gets a stray blank window.
        var psi = new ProcessStartInfo(_hostPath) { UseShellExecute = false, CreateNoWindow = !_showConsole };
        psi.ArgumentList.Add("--pipe");
        psi.ArgumentList.Add(pipeName);
        _host = Process.Start(psi) ?? throw new InvalidOperationException("failed to start the managed-debug host");

        Task.Run(async () =>
        {
            try
            {
                await _pipe.WaitForConnectionAsync().ConfigureAwait(false);
                var reader = new StreamReader(_pipe);
                var writer = new StreamWriter(_pipe) { AutoFlush = true };
                lock (_writeLock)
                {
                    _reader = reader;
                    _writer = writer;
                    // Flush anything queued before the host connected (crucially, the launch command + initial breakpoints).
                    while (_sendQueue.Count > 0)
                        try { _writer.WriteLine(_sendQueue.Dequeue()); } catch { }
                }
                ReadLoop();
            }
            catch (Exception ex) { Raise(new MdbgEvent { Ev = Mdbg.Error, Message = "host connect failed: " + ex.Message }); }
        });
    }

    private void ReadLoop()
    {
        try
        {
            string? line;
            while (!_disposed && (line = _reader!.ReadLine()) is not null)
            {
                MdbgEvent? ev;
                try { ev = MdbgJson.FromLine<MdbgEvent>(line); } catch { continue; }
                if (ev is null) continue;
                if (ev.Ev == Mdbg.Exited) _sawExit = true;
                Raise(ev);
            }
        }
        catch { /* pipe closed */ }
        if (!_disposed && !_sawExit) Raise(new MdbgEvent { Ev = Mdbg.Exited, Code = -1 });   // host/pipe died before a real exit
    }

    private void Raise(MdbgEvent ev) => EventReceived?.Invoke(ev);

    private void Send(MdbgCommand cmd)
    {
        string line = MdbgJson.ToLine(cmd);
        lock (_writeLock)
        {
            if (_writer is not null) { try { _writer.WriteLine(line); } catch { } }
            else if (!_disposed) _sendQueue.Enqueue(line);   // not connected yet — buffer; flushed on connect
        }
    }

    public void Launch(string target, string? args, string? cwd, IReadOnlyList<BpLoc>? bps)
        => Send(new MdbgCommand { Cmd = Mdbg.Launch, Target = target, Args = args, Cwd = cwd, Breakpoints = bps?.ToArray() });
    public void SetBreakpoint(BpLoc bp) => Send(new MdbgCommand { Cmd = Mdbg.SetBreakpoint, Bp = bp });
    public void RemoveBreakpoint(int id) => Send(new MdbgCommand { Cmd = Mdbg.RemoveBreakpoint, Id = id });
    public void Go() => Send(new MdbgCommand { Cmd = Mdbg.Go });
    public void StepInto(int[]? range) => Send(new MdbgCommand { Cmd = Mdbg.StepInto, Range = range });
    public void StepOver(int[]? range) => Send(new MdbgCommand { Cmd = Mdbg.StepOver, Range = range });
    public void StepOut() => Send(new MdbgCommand { Cmd = Mdbg.StepOut });
    public void Pause() => Send(new MdbgCommand { Cmd = Mdbg.Pause });
    public void StopTarget() => Send(new MdbgCommand { Cmd = Mdbg.Stop });
    public void Detach() => Send(new MdbgCommand { Cmd = Mdbg.Detach });

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        try { Send(new MdbgCommand { Cmd = Mdbg.Quit }); } catch { }
        try { _pipe?.Dispose(); } catch { }
        try { if (_host is { HasExited: false }) { if (!_host.WaitForExit(1500)) _host.Kill(entireProcessTree: true); } } catch { }
        try { _host?.Dispose(); } catch { }
    }
}

using System.Windows.Threading;
using DisasmStudio.ManagedDebug;

namespace DisasmStudio.Wpf.Services;

/// <summary>UI-facing wrapper around a <see cref="ManagedDebugClient"/>: marshals host events onto the WPF
/// dispatcher and tracks stop state. The managed counterpart to <see cref="DebugSession"/> — but source-level
/// (C# line / IL offset) rather than native (address / register), driven by the out-of-process ICorDebug host.</summary>
internal sealed class ManagedDebugSession : IDisposable
{
    private readonly Dispatcher _dispatcher;
    private readonly ManagedDebugClient _client;

    public event Action? Launched;
    public event Action<string>? ModuleLoaded;   // module file name
    public event Action<MdbgEvent>? Stopped;      // full stop (reason, thread, frames, locals)
    public event Action<int>? Exited;             // exit code
    public event Action<string>? Error;
    public event Action<string>? Output;

    public bool IsRunning { get; private set; }
    public bool IsStopped { get; private set; }
    public MdbgEvent? LastStop { get; private set; }

    public ManagedDebugSession(Dispatcher dispatcher, string hostPath, bool showConsole)
    {
        _dispatcher = dispatcher;
        _client = new ManagedDebugClient(hostPath, showConsole);
        _client.EventReceived += OnEvent;
    }

    public void Launch(string target, string? args, string? cwd, IReadOnlyList<BpLoc>? bps, bool framework = false)
    {
        IsRunning = true;
        _client.Start();
        _client.Launch(target, args, cwd, bps, framework);
    }

    public void SetBreakpoint(BpLoc bp) => _client.SetBreakpoint(bp);
    public void RemoveBreakpoint(int id) => _client.RemoveBreakpoint(id);

    public void Go() { IsStopped = false; _client.Go(); }
    public void StepInto(int[]? range = null) { IsStopped = false; _client.StepInto(range); }
    public void StepOver(int[]? range = null) { IsStopped = false; _client.StepOver(range); }
    public void StepOut() { IsStopped = false; _client.StepOut(); }
    public void Pause() => _client.Pause();
    public void Stop() => _client.StopTarget();
    public void Detach() => _client.Detach();

    private void OnEvent(MdbgEvent ev)
    {
        _dispatcher.BeginInvoke(() =>
        {
            switch (ev.Ev)
            {
                case Mdbg.Launched: Launched?.Invoke(); break;
                case Mdbg.ModuleLoaded: ModuleLoaded?.Invoke(ev.Module ?? ""); break;
                case Mdbg.Stopped: IsStopped = true; LastStop = ev; Stopped?.Invoke(ev); break;
                case Mdbg.Exited: IsRunning = false; IsStopped = false; Exited?.Invoke(ev.Code); break;
                case Mdbg.Error: Error?.Invoke(ev.Message ?? ""); break;
                case Mdbg.Output: Output?.Invoke(ev.Text ?? ""); break;
            }
        });
    }

    public void Dispose() => _client.Dispose();
}

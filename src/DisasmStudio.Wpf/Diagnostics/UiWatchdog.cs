using System;
using System.Diagnostics;
using System.IO;
using System.Threading;
using System.Windows.Threading;

namespace DisasmStudio.Wpf.Diagnostics;

/// <summary>
/// Detects the UI thread going unresponsive and records what it was doing at the time.
/// <para>
/// A background timer posts a heartbeat to the dispatcher; if one is not serviced within
/// <see cref="StallSeconds"/> the UI thread is blocked (or its queue is saturated), which is what Windows
/// eventually reports by ghosting the window white and offering to close it. Heavy UI operations mark
/// themselves with <see cref="Scope"/>, so the report names the culprit instead of leaving it to guesswork.
/// </para>
/// Findings are appended to <c>%TEMP%\ds_ui_stall.txt</c>.
/// </summary>
internal static class UiWatchdog
{
    private const int StallSeconds = 3;

    private static Dispatcher? _ui;
    private static Timer? _timer;
    private static readonly Stopwatch Clock = Stopwatch.StartNew();

    /// <summary>Name of the innermost marked UI operation, or null when the UI thread is idle/unmarked.</summary>
    private static volatile string? _current;
    private static long _currentStartedMs;

    /// <summary>Heartbeat state: when the outstanding beat was posted, and whether it has come back.</summary>
    private static long _beatPostedMs;
    private static volatile bool _beatPending;
    private static bool _stallReported;

    public static string LogPath { get; } = Path.Combine(Path.GetTempPath(), "ds_ui_stall.txt");

    public static void Start(Dispatcher ui)
    {
        if (_timer is not null) return;
        _ui = ui;
        _timer = new Timer(Tick, null, 1000, 1000);
    }

    /// <summary>Mark a UI operation so a stall can be attributed to it. Nest freely.</summary>
    public static IDisposable Scope(string name) => new Op(name);

    /// <summary>Mark a modal dialog. A modal loop stops servicing the heartbeat exactly like a blocked thread,
    /// so without this a dialog quietly waiting for the user is indistinguishable in the log from a hang — and
    /// it looks the same on screen too if the dialog opens behind its owner.</summary>
    public static IDisposable ModalScope(string name)
    {
        Report($"MODAL OPENED: {name} — the UI thread is now waiting for the user, not blocked");
        var op = new Op($"modal dialog: {name}");
        _modalDepth++;
        return new Modal(op, name);
    }

    /// <summary>Nesting depth of open modal dialogs. Written on the UI thread and read on the timer thread, so
    /// volatile like every other cross-thread field here — a stale read would report a dialog quietly waiting
    /// for the user as a hang, which is the one distinction this field exists to make.</summary>
    private static volatile int _modalDepth;

    private sealed class Modal(Op op, string name) : IDisposable
    {
        public void Dispose()
        {
            _modalDepth--;
            op.Dispose();
            Report($"MODAL CLOSED: {name}");
        }
    }

    private sealed class Op : IDisposable
    {
        private readonly string? _prev;
        private readonly long _prevStart;

        public Op(string name)
        {
            _prev = _current; _prevStart = _currentStartedMs;
            _current = name; _currentStartedMs = Clock.ElapsedMilliseconds;
        }

        public void Dispose() { _current = _prev; _currentStartedMs = _prevStart; }
    }

    private static void Tick(object? _)
    {
        var ui = _ui;
        if (ui is null) return;

        if (_beatPending)
        {
            long blockedMs = Clock.ElapsedMilliseconds - _beatPostedMs;
            if (blockedMs >= StallSeconds * 1000 && !_stallReported)
            {
                _stallReported = true;
                string what = _current is { } c
                    ? $"inside \"{c}\" for {Clock.ElapsedMilliseconds - _currentStartedMs:N0} ms"
                    : "outside any marked operation (blocked in un-instrumented code, or the dispatcher queue is saturated)";
                Report(_modalDepth > 0
                    ? $"WAITING ON A MODAL DIALOG for {blockedMs:N0} ms — {what}. Not a hang: the dialog needs an answer (check behind the main window)."
                    : $"UI STALL: no heartbeat for {blockedMs:N0} ms — {what}");
            }
            return;   // still blocked; don't queue more beats behind it
        }

        _beatPending = true;
        _beatPostedMs = Clock.ElapsedMilliseconds;
        try
        {
            ui.BeginInvoke(DispatcherPriority.Background, () =>
            {
                long waited = Clock.ElapsedMilliseconds - _beatPostedMs;
                _beatPending = false;
                if (_stallReported)
                {
                    _stallReported = false;
                    Report($"UI recovered after {waited:N0} ms");
                }
            });
        }
        catch { _beatPending = false; }
    }

    private static void Report(string line)
    {
        try { File.AppendAllText(LogPath, $"[{DateTime.Now:HH:mm:ss.fff}] {line}{Environment.NewLine}"); }
        catch { /* diagnostics must never throw into the app */ }
    }
}

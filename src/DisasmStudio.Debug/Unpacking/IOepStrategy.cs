namespace DisasmStudio.Debug.Unpacking;

/// <summary>
/// A single OEP-finding strategy. Each strategy is a state machine that drives the debugger toward the
/// Original Entry Point. <see cref="OepFinder"/> delegates to the active strategy, and
/// <see cref="MultiPassStrategy"/> chains several together.
/// </summary>
public interface IOepStrategy
{
    /// <summary>The method this strategy implements (for reporting).</summary>
    OepMethod Method { get; }

    /// <summary>Human-readable log of what the strategy has done so far.</summary>
    string Log { get; }

    /// <summary>True once the strategy has finished (found OEP, failed, or was aborted).</summary>
    bool IsDone { get; }

    /// <summary>
    /// Arm the strategy and issue the first resume. Called on the entry-point stop.
    /// Returns a non-null OEP if it is already reached; otherwise null.
    /// </summary>
    ulong? Begin(DebuggerEngine eng);

    /// <summary>
    /// Process a stop. Returns the OEP VA once found, or null when the strategy has issued the next resume.
    /// </summary>
    ulong? OnStop(DebuggerEngine eng, StopInfo stop);

    /// <summary>
    /// Whether <paramref name="stop"/> is one this strategy produced itself (as opposed to a user
    /// breakpoint or unrelated event). Used by <see cref="OepStopRouting"/>.
    /// </summary>
    bool Owns(DebuggerEngine eng, StopInfo stop);

    /// <summary>
    /// Disarm everything this strategy planted. Called on cancellation or when the strategy is exhausted
    /// and the next one in a MultiPass chain is about to start. Idempotent.
    /// </summary>
    void Abort(DebuggerEngine eng);
}
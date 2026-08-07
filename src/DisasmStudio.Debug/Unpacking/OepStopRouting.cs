namespace DisasmStudio.Debug.Unpacking;

/// <summary>What an interactive debug session should do with a stop that arrives while an
/// <see cref="OepFinder"/> hunt is in flight.</summary>
public enum OepRoute
{
    /// <summary>No hunt is running — handle the stop normally.</summary>
    NotHunting,
    /// <summary>The finder produced this stop; hand it to <see cref="OepFinder.OnStop"/>, which either
    /// resumes again or returns the OEP.</summary>
    Forward,
    /// <summary>Not the finder's stop, but the hunt takes priority over it: resume silently and count it.
    /// Only user breakpoints/watchpoints qualify.</summary>
    Resume,
    /// <summary>Present the stop to the user. The hunt stays armed unless the caller tears it down, so a
    /// later Continue still reaches the OEP.</summary>
    Surface,
}

/// <summary>
/// The decision table for stops that arrive during a "run to OEP" hunt, kept as a pure function so the
/// policy can be tested without launching a process.
/// <para>
/// The hunt runs the target at full speed through the packer stub, which commonly re-executes instrumented
/// code many times. Letting every user breakpoint stop the run would make the OEP unreachable in practice,
/// so breakpoint-class stops are resumed and counted (the total is reported when the OEP is reached) — but
/// <see cref="StopReason.Paused"/> stays the user's escape hatch and a real exception is never hidden.
/// </para>
/// <para>
/// Stops the user asked for are never swallowed: whenever the last resume came from a user command
/// (Continue / Step / Run-to-cursor) rather than from the finder, the stop surfaces regardless of reason.
/// </para>
/// </summary>
public static class OepStopRouting
{
    /// <param name="huntActive">A finder is armed and has not yet reported an OEP.</param>
    /// <param name="huntIssuedLastResume">The resume that produced this stop came from the finder, not
    /// from a user command.</param>
    /// <param name="finderOwns">The finder recognises this stop as its own — see <see cref="OepFinder.Owns"/>.
    /// Required because <see cref="StopReason"/> alone is ambiguous: a section execute-breakpoint and a user
    /// memory breakpoint both report <see cref="StopReason.MemoryBreakpoint"/>, and the ESP-trick watch and a
    /// user hardware watchpoint both report <see cref="StopReason.Watchpoint"/>.</param>
    public static OepRoute Decide(bool huntActive, bool huntIssuedLastResume, bool finderOwns, StopReason reason)
    {
        if (!huntActive) return OepRoute.NotHunting;

        // The target is gone: there is nothing left to hunt and nothing left to disarm.
        if (reason == StopReason.ProcessExited) return OepRoute.Surface;

        // Checked before the resume-ownership gate below, because a stop the finder recognises is its own
        // signal no matter who pressed what. This is what makes the hunt survive a Pause: after the user
        // pauses and later continues, the section guard still resolves as the OEP instead of surfacing as a
        // bare, uninterpreted guard-exec stop that nothing explains.
        if (finderOwns) return OepRoute.Forward;

        // The user drove this resume, so the resulting stop is theirs.
        if (!huntIssuedLastResume) return OepRoute.Surface;

        return reason switch
        {
            // The hunt outranks the user's own breakpoints while it is running; each skipped hit is counted.
            StopReason.Breakpoint or StopReason.Watchpoint or StopReason.MemoryBreakpoint => OepRoute.Resume,
            // Pause (the escape hatch), a genuine fault, and anything unexpected go to the user untouched.
            _ => OepRoute.Surface,
        };
    }
}

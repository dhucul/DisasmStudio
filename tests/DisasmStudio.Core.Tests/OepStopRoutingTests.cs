using DisasmStudio.Debug;
using DisasmStudio.Debug.Unpacking;
using Xunit;

namespace DisasmStudio.Core.Tests;

/// <summary>
/// The "run to OEP" stop-routing policy. No process is launched — the point of extracting the decision out of
/// <c>DebugSession</c> is that the invariant that matters ("a stop the user asked for is never swallowed") can
/// be pinned exhaustively here rather than only observed in a live debug session.
/// </summary>
public sealed class OepStopRoutingTests
{
    private static readonly StopReason[] AllReasons = Enum.GetValues<StopReason>();

    [Fact]
    public void NoHuntLeavesEveryStopAlone()
    {
        foreach (var reason in AllReasons)
            foreach (bool pending in new[] { true, false })
                foreach (bool owns in new[] { true, false })
                    Assert.Equal(OepRoute.NotHunting,
                        OepStopRouting.Decide(huntActive: false, pending, owns, reason));
    }

    [Fact]
    public void AStopTheUserResumedIntoSurfacesUnlessItIsTheFindersOwnSignal()
    {
        // The user pressed Continue / Step / Run-to-cursor, so the resulting stop is theirs — the hunt must not
        // eat a step the user explicitly asked for.
        foreach (var reason in AllReasons)
            Assert.Equal(OepRoute.Surface,
                OepStopRouting.Decide(huntActive: true, huntIssuedLastResume: false, finderOwns: false, reason));
    }

    [Fact]
    public void TheFindersOwnSignalIsClaimedEvenAfterTheUserResumed()
    {
        // Pause, then Continue: the section guard is still armed, so its guard-exec IS the OEP and must be
        // reported as one. Gating it on "who resumed" would surface a bare, unexplained stop instead and strand
        // the hunt armed forever.
        Assert.Equal(OepRoute.Forward,
            OepStopRouting.Decide(huntActive: true, huntIssuedLastResume: false, finderOwns: true, StopReason.GuardExec));
        Assert.Equal(OepRoute.Forward,
            OepStopRouting.Decide(huntActive: true, huntIssuedLastResume: false, finderOwns: true, StopReason.Breakpoint));
    }

    [Theory]
    [InlineData(StopReason.Step)]            // the finder's own single-step (ESP-trick)
    [InlineData(StopReason.Watchpoint)]      // the popad watch
    [InlineData(StopReason.GuardExec)]       // a section guard fired
    [InlineData(StopReason.MemoryBreakpoint)]// a section execute breakpoint fired
    [InlineData(StopReason.Breakpoint)]      // the manual OEP breakpoint
    public void StopsTheFinderOwnsAreForwardedToIt(StopReason reason)
        => Assert.Equal(OepRoute.Forward,
            OepStopRouting.Decide(huntActive: true, huntIssuedLastResume: true, finderOwns: true, reason));

    [Theory]
    [InlineData(StopReason.Breakpoint)]
    [InlineData(StopReason.Watchpoint)]
    [InlineData(StopReason.MemoryBreakpoint)]
    public void UserBreakpointsAreResumedPastWhileHunting(StopReason reason)
        // The hunt outranks the user's breakpoints: a stub that loops through instrumented code would otherwise
        // never reach the OEP. Each skipped hit is counted and reported when it does.
        => Assert.Equal(OepRoute.Resume,
            OepStopRouting.Decide(huntActive: true, huntIssuedLastResume: true, finderOwns: false, reason));

    [Fact]
    public void PauseIsTheEscapeHatch()
        => Assert.Equal(OepRoute.Surface,
            OepStopRouting.Decide(huntActive: true, huntIssuedLastResume: true, finderOwns: false, StopReason.Paused));

    [Fact]
    public void ExceptionsAreNeverHidden()
        => Assert.Equal(OepRoute.Surface,
            OepStopRouting.Decide(huntActive: true, huntIssuedLastResume: true, finderOwns: false, StopReason.Exception));

    [Fact]
    public void ProcessExitSurfacesEvenWhenTheFinderWouldClaimIt()
        => Assert.Equal(OepRoute.Surface,
            OepStopRouting.Decide(huntActive: true, huntIssuedLastResume: true, finderOwns: true, StopReason.ProcessExited));

    [Fact]
    public void OnlyBreakpointClassStopsAreEverSwallowed()
    {
        // The safety property, stated once over the whole reason space: nothing except a user breakpoint,
        // watchpoint or memory breakpoint is ever silently resumed past.
        foreach (var reason in AllReasons)
        {
            var route = OepStopRouting.Decide(huntActive: true, huntIssuedLastResume: true, finderOwns: false, reason);
            if (route == OepRoute.Resume)
                Assert.Contains(reason, new[] { StopReason.Breakpoint, StopReason.Watchpoint, StopReason.MemoryBreakpoint });
        }
    }
}

using DisasmStudio.Debug;
using Xunit;

namespace DisasmStudio.Core.Tests;

public sealed class DebugElevationRequestTests
{
    [Fact]
    public void HandoffRoundTripsPathAndDebugOptions()
    {
        var expected = new DebugElevationRequest(
            @"C:\Program Files\Example App\target.exe",
            ElevatedDebugMode.Native,
            HideFromDebugger: true,
            StopAtLoaderBreakpoint: true,
            WorkingDirectory: @"C:\Program Files\Example App",
            SessionPath: @"C:\Users\tester\AppData\Local\DisasmStudio\ElevationHandoffs\abc.dsproj",
            SessionSha256: new string('A', 64),
            ReadyEventName: @"Local\DisasmStudio.ElevationReady.0123456789abcdef0123456789abcdef");

        Assert.True(DebugElevationRequest.TryParse(expected.ToArguments(), out var actual));
        Assert.Equal(expected, actual);
    }

    [Fact]
    public void HandoffDefaultsOptionalDebugSettingsOff()
    {
        string[] args = [DebugElevationRequest.Switch, "AUTO", @"C:\target.exe"];

        Assert.True(DebugElevationRequest.TryParse(args, out var request));
        Assert.NotNull(request);
        Assert.Equal(ElevatedDebugMode.Auto, request.Mode);
        Assert.False(request.HideFromDebugger);
        Assert.False(request.StopAtLoaderBreakpoint);
    }

    [Theory]
    [InlineData()]
    [InlineData("--elevated-debug")]
    [InlineData("--elevated-debug", "native")]
    [InlineData("--elevated-debug", "invalid", @"C:\target.exe")]
    [InlineData("--elevated-debug", "native", " ")]
    [InlineData("--elevated-debug", "native", @"C:\target.exe", "--unknown")]
    [InlineData("--elevated-debug", "native", @"C:\target.exe", "--working-directory")]
    [InlineData("--elevated-debug", "native", @"C:\target.exe", "--session", " ")]
    [InlineData("--elevated-debug", "native", @"C:\target.exe", "--session", "a", "--session", "b")]
    [InlineData("--elevated-debug", "native", @"C:\target.exe", "--session", "a")]
    [InlineData("--elevated-debug", "native", @"C:\target.exe", "--session-sha256", "ABC")]
    [InlineData("--elevated-debug", "native", @"C:\target.exe", "--session-sha256", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")]
    [InlineData("--elevated-debug", "native", @"C:\target.exe", "--ready-event")]
    [InlineData("--elevated-debug", "native", @"C:\target.exe", "--ready-event", "Global\\Other.Event")]
    [InlineData("--elevated-debug", "native", @"C:\target.exe", "--ready-event", "Local\\DisasmStudio.ElevationReady.not-a-guid")]
    public void HandoffRejectsMalformedOrAmbiguousArguments(params string[] args)
        => Assert.False(DebugElevationRequest.TryParse(args, out _));

    [Fact]
    public void HandoffRejectsInvalidRecordStateBeforeLaunching()
    {
        var missingTarget = new DebugElevationRequest("", ElevatedDebugMode.Native, false, false);
        var invalidMode = new DebugElevationRequest(@"C:\target.exe", (ElevatedDebugMode)99, false, false);
        var unsignedSession = new DebugElevationRequest(
            @"C:\target.exe", ElevatedDebugMode.Native, false, false, SessionPath: @"C:\session.dsproj");
        var invalidReadyEvent = new DebugElevationRequest(
            @"C:\target.exe", ElevatedDebugMode.Native, false, false, ReadyEventName: "invalid");

        Assert.Throws<InvalidOperationException>(missingTarget.ToArguments);
        Assert.Throws<InvalidOperationException>(invalidMode.ToArguments);
        Assert.Throws<InvalidOperationException>(unsignedSession.ToArguments);
        Assert.Throws<InvalidOperationException>(invalidReadyEvent.ToArguments);
    }

    [Theory]
    [InlineData(DebugStartFailure.AccessDenied, true)]
    [InlineData(DebugStartFailure.ElevationRequired, true)]
    [InlineData(2, false)]
    [InlineData(87, false)]
    public void OnlyElevationRelevantStartErrorsRequestAnElevatedRetry(int error, bool expected)
        => Assert.Equal(expected, new DebugStartFailure(DebugStartOperation.Launch, error).MayRequireElevation);
}

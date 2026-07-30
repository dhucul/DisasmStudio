namespace DisasmStudio.Debug;

/// <summary>The debug path an elevated DisasmStudio instance should resume after startup.</summary>
public enum ElevatedDebugMode
{
    Auto,
    Native,
}

/// <summary>
/// Command-line handoff used when a standard-rights DisasmStudio instance cannot launch an elevated target.
/// Keeping this as a small, strict value object prevents ordinary file-open arguments from accidentally
/// triggering a debug launch and makes paths containing spaces safe through <c>ProcessStartInfo.ArgumentList</c>.
/// </summary>
public sealed record DebugElevationRequest(
    string TargetPath,
    ElevatedDebugMode Mode,
    bool HideFromDebugger,
    bool StopAtLoaderBreakpoint,
    string? WorkingDirectory = null,
    string? SessionPath = null,
    string? SessionSha256 = null)
{
    public const string Switch = "--elevated-debug";
    private const string HideSwitch = "--hide-from-debugger";
    private const string LoaderSwitch = "--stop-at-loader";
    private const string WorkingDirectorySwitch = "--working-directory";
    private const string SessionSwitch = "--session";
    private const string SessionSha256Switch = "--session-sha256";

    public string[] ToArguments()
    {
        if (string.IsNullOrWhiteSpace(TargetPath))
            throw new InvalidOperationException("An elevated debug target path is required.");
        string mode = Mode switch
        {
            ElevatedDebugMode.Auto => "auto",
            ElevatedDebugMode.Native => "native",
            _ => throw new InvalidOperationException($"Unsupported elevated debug mode: {Mode}."),
        };
        var args = new List<string>
        {
            Switch,
            mode,
            TargetPath,
        };
        if (HideFromDebugger) args.Add(HideSwitch);
        if (StopAtLoaderBreakpoint) args.Add(LoaderSwitch);
        if (!string.IsNullOrWhiteSpace(WorkingDirectory))
        {
            args.Add(WorkingDirectorySwitch);
            args.Add(WorkingDirectory);
        }
        if (!string.IsNullOrWhiteSpace(SessionPath))
        {
            if (!IsSha256(SessionSha256))
                throw new InvalidOperationException("A valid SHA-256 digest is required for the elevation session.");
            args.Add(SessionSwitch);
            args.Add(SessionPath);
            args.Add(SessionSha256Switch);
            args.Add(SessionSha256!);
        }
        else if (SessionSha256 is not null)
            throw new InvalidOperationException("A session digest cannot be supplied without a session path.");
        return [.. args];
    }

    public static bool TryParse(IReadOnlyList<string>? args, out DebugElevationRequest? request)
    {
        request = null;
        if (args is null || args.Count < 3
            || !string.Equals(args[0], Switch, StringComparison.OrdinalIgnoreCase)
            || string.IsNullOrWhiteSpace(args[2]))
            return false;

        ElevatedDebugMode mode;
        if (string.Equals(args[1], "auto", StringComparison.OrdinalIgnoreCase))
            mode = ElevatedDebugMode.Auto;
        else if (string.Equals(args[1], "native", StringComparison.OrdinalIgnoreCase))
            mode = ElevatedDebugMode.Native;
        else
            return false;

        bool hide = false;
        bool loader = false;
        string? workingDirectory = null;
        string? sessionPath = null;
        string? sessionSha256 = null;
        for (int i = 3; i < args.Count; i++)
        {
            if (string.Equals(args[i], HideSwitch, StringComparison.OrdinalIgnoreCase))
                hide = true;
            else if (string.Equals(args[i], LoaderSwitch, StringComparison.OrdinalIgnoreCase))
                loader = true;
            else if (string.Equals(args[i], WorkingDirectorySwitch, StringComparison.OrdinalIgnoreCase))
            {
                if (workingDirectory is not null || ++i >= args.Count || string.IsNullOrWhiteSpace(args[i]))
                    return false;
                workingDirectory = args[i];
            }
            else if (string.Equals(args[i], SessionSwitch, StringComparison.OrdinalIgnoreCase))
            {
                if (sessionPath is not null || ++i >= args.Count || string.IsNullOrWhiteSpace(args[i]))
                    return false;
                sessionPath = args[i];
            }
            else if (string.Equals(args[i], SessionSha256Switch, StringComparison.OrdinalIgnoreCase))
            {
                if (sessionSha256 is not null || ++i >= args.Count || !IsSha256(args[i]))
                    return false;
                sessionSha256 = args[i];
            }
            else
                return false;
        }

        if ((sessionPath is null) != (sessionSha256 is null)) return false;
        request = new DebugElevationRequest(
            args[2], mode, hide, loader, workingDirectory, sessionPath, sessionSha256);
        return true;
    }

    private static bool IsSha256(string? value)
        => value is { Length: 64 } && value.All(Uri.IsHexDigit);
}

public enum DebugStartOperation
{
    Launch,
    Attach,
}

/// <summary>A Win32 failure that occurred before a native debug loop could start.</summary>
public readonly record struct DebugStartFailure(DebugStartOperation Operation, int Win32Error)
{
    public const int AccessDenied = 5;
    public const int ElevationRequired = 740;

    /// <summary>Error codes for which a retry by an elevated debugger is useful.</summary>
    public bool MayRequireElevation => Win32Error is AccessDenied or ElevationRequired;
}

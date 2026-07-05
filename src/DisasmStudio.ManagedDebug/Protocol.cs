using System.Text.Json;
using System.Text.Json.Serialization;

namespace DisasmStudio.ManagedDebug;

/// <summary>A source-level breakpoint target: a method (metadata token) + IL offset within a module.
/// <see cref="Id"/> is the app-assigned handle used to remove it later.</summary>
public sealed record BpLoc(string Module, int Token, int IlOffset, int Id = 0);

/// <summary>One managed stack frame at a stop: the method (module + token) and the IL offset of its
/// instruction pointer, plus a human label. The app maps (Module, Token, IlOffset) back to a decompiled C# line.</summary>
public sealed record MdbgFrame(string Module, int Token, int IlOffset, string Method);

/// <summary>A local variable / argument value at a stop.</summary>
public sealed record MdbgLocal(string Name, string Value, string Type, bool IsArg);

/// <summary>Command from the app to the host (one JSON object per line over the pipe).</summary>
public sealed record MdbgCommand
{
    public string Cmd { get; init; } = "";     // launch, setBreakpoint, removeBreakpoint, go, stepInto, stepOver, stepOut, pause, stop, detach, quit
    public string? Target { get; init; }
    public string? Args { get; init; }
    public string? Cwd { get; init; }
    public BpLoc? Bp { get; init; }
    public int Id { get; init; }
    public int Frame { get; init; }
    public BpLoc[]? Breakpoints { get; init; }  // pending breakpoints to arm as their modules load
    public int[]? Range { get; init; }          // [ilStart, ilEnd) of the current C# statement — for line-level step
    public bool Framework { get; init; }         // target is .NET Framework (desktop CLR) — use the legacy ICorDebug launch
}

/// <summary>Event from the host to the app (one JSON object per line over the pipe).</summary>
public sealed record MdbgEvent
{
    public string Ev { get; init; } = "";       // launched, moduleLoaded, stopped, output, exited, error, ack
    public int Pid { get; init; }
    public string? Module { get; init; }
    public string? Path { get; init; }
    public string? Reason { get; init; }        // entry, breakpoint, step, exception, pause
    public int Thread { get; init; }
    public MdbgFrame[]? Frames { get; init; }
    public MdbgLocal[]? Locals { get; init; }
    public string? Text { get; init; }
    public int Code { get; init; }
    public string? Message { get; init; }
}

/// <summary>Command / event name constants (avoid stringly-typed drift across the two processes).</summary>
public static class Mdbg
{
    // commands
    public const string Launch = "launch", SetBreakpoint = "setBreakpoint", RemoveBreakpoint = "removeBreakpoint",
        Go = "go", StepInto = "stepInto", StepOver = "stepOver", StepOut = "stepOut",
        Pause = "pause", Stop = "stop", Detach = "detach", Quit = "quit";
    // events
    public const string Launched = "launched", ModuleLoaded = "moduleLoaded", Stopped = "stopped",
        Output = "output", Exited = "exited", Error = "error", Ack = "ack";
    // stop reasons
    public const string ReasonEntry = "entry", ReasonBreakpoint = "breakpoint", ReasonStep = "step",
        ReasonException = "exception", ReasonPause = "pause";
}

/// <summary>Newline-delimited JSON framing used on the pipe.</summary>
public static class MdbgJson
{
    private static readonly JsonSerializerOptions Opts = new() { DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull };
    public static string ToLine<T>(T msg) => JsonSerializer.Serialize(msg, Opts);
    public static T? FromLine<T>(string line) => JsonSerializer.Deserialize<T>(line, Opts);
}

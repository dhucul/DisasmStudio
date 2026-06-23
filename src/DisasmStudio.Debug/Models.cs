namespace DisasmStudio.Debug;

/// <summary>Why the debuggee stopped.</summary>
public enum StopReason { EntryPoint, Attached, Breakpoint, Step, Watchpoint, Paused, Exception, ProcessExited, GuardExec }

/// <summary>Kind of a hardware breakpoint / watchpoint.</summary>
public enum HwKind { Execute, Write, ReadWrite }

/// <summary>What to do when resuming the debuggee.</summary>
public enum ResumeMode { Go, StepInto, StepOver, StepOut, RunToCursor, Stop }

/// <summary>Details of a stop event, raised to the UI.</summary>
public readonly record struct StopInfo(StopReason Reason, uint ThreadId, ulong Address, uint ExceptionCode);

/// <summary>A loaded module in the debuggee.</summary>
public sealed record ModuleInfo(ulong Base, string Path)
{
    public string Name => System.IO.Path.GetFileName(Path);
}

/// <summary>An observed exception, raised so a caller can localize a fault. For an access violation,
/// <see cref="AccessType"/> is 0/1/8 (read/write/execute) and <see cref="FaultAddress"/> is the inaccessible
/// address; for other exceptions <see cref="AccessType"/> is -1.</summary>
public readonly record struct ExceptionEvent(uint Code, ulong Address, bool FirstChance, uint ThreadId,
    int AccessType, ulong FaultAddress);

/// <summary>A captured fault: the exception, where it happened (module + offset), the faulting instruction,
/// a register snapshot, and — for an access violation — what address it tried to touch (read/write/execute)
/// and the page state there. Localizes an anti-debug self-crash instead of reporting only the exit code.</summary>
public sealed record FaultSnapshot(uint Code, ulong Address, bool FirstChance,
    string Module, ulong ModuleOffset, string Instruction, string Registers,
    int AccessType, ulong FaultAddress, string MemState)
{
    public string CodeName => Code switch
    {
        0xC0000005 => "ACCESS_VIOLATION",
        0xC000001D => "ILLEGAL_INSTRUCTION",
        0xC0000096 => "PRIVILEGED_INSTRUCTION",
        0x80000003 => "BREAKPOINT",
        0xC0000094 => "INTEGER_DIVIDE_BY_ZERO",
        0xC0000409 => "STACK_BUFFER_OVERRUN",
        0xC0000025 => "NONCONTINUABLE_EXCEPTION",
        0xC0000420 => "ASSERTION_FAILURE",
        _ => $"0x{Code:X8}",
    };

    public string Access => AccessType switch { 0 => "read", 1 => "write", 8 => "execute", _ => "" };

    /// <summary>e.g. "tried to execute 401D2A" — empty when not an access violation.</summary>
    public string AccessDesc => AccessType < 0 ? "" : $"tried to {Access} {FaultAddress:X}";
}

/// <summary>A thread in the debuggee.</summary>
public sealed record ThreadInfo(uint Id, ulong StartAddress);

/// <summary>A breakpoint (software int3, or a hardware execute/access watchpoint).</summary>
public sealed class Breakpoint
{
    public required ulong Address { get; init; }
    public bool Hardware { get; init; }
    public HwKind Kind { get; init; }
    public int Size { get; init; } = 1;     // hardware watch length: 1/2/4/8
    public bool Enabled { get; set; } = true;

    // software-bp state
    public byte Original { get; set; }
    public bool Armed { get; set; }
    // hardware-bp state
    public int Slot { get; set; } = -1;      // Dr0..Dr3, or -1
}

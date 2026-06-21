namespace DisasmStudio.Core.Analysis;

/// <summary>How control reaches one block from another.</summary>
public enum EdgeKind { FallThrough, Taken, Jump, Switch }

/// <summary>An edge in a function's control-flow graph, identified by target block start VA.</summary>
public readonly record struct CfgEdge(ulong ToBlockStart, EdgeKind Kind);

/// <summary>A straight-line run of instructions ending at a branch/return (or the next leader).</summary>
public sealed class BasicBlock
{
    public required ulong Start { get; init; }
    public ulong End { get; set; }                 // exclusive
    public List<ulong> InstrVas { get; } = [];
    public List<CfgEdge> Out { get; } = [];

    // Layout fields filled by the graph view (kept here so layout is computed once).
    public double X, Y, Width, Height;
}

/// <summary>
/// A discovered function. Its control-flow blocks are built lazily on first request (graph open),
/// so listing thousands of functions stays instant — only the one being viewed pays for its CFG.
/// </summary>
public sealed class Function
{
    public required ulong Va { get; init; }
    public required string Name { get; set; }
    private List<BasicBlock>? _blocks;

    /// <summary>The VA the CFG actually begins at. Equal to <see cref="Va"/> except when the entry was
    /// realigned forward because <see cref="Va"/> landed mid-instruction (e.g. a function recovered from
    /// a code pointer that pointed into the middle of an instruction). Set when the CFG is built.</summary>
    public ulong EntryVa { get; private set; }

    public bool BlocksBuilt => _blocks is not null;
    public IReadOnlyList<BasicBlock> Blocks => _blocks ?? [];
    internal void SetBlocks(List<BasicBlock> b, ulong entryVa) { _blocks = b; EntryVa = entryVa; }

    public override string ToString() => $"{Name} @ {Va:X}";
}

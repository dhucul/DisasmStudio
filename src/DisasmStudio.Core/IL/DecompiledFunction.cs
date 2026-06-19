using DisasmStudio.Core.Disasm;

namespace DisasmStudio.Core.IL;

/// <summary>The four decompiler abstraction levels, low to high.</summary>
public enum ILLevel { LowIL, MediumIL, HighIL, PseudoC }

/// <summary>One rendered line of decompiler output: its coloured token runs, the indent depth, and
/// the source instruction VA it maps to (0 = synthetic line such as a brace) for click-to-sync.</summary>
public readonly record struct DecompLine(ulong Va, IReadOnlyList<AsmToken> Tokens, int Indent);

/// <summary>The decompilation of a single function, rendered at all four levels. Built lazily and
/// cached per function, mirroring how control-flow graphs are built on first view.</summary>
public sealed class DecompiledFunction
{
    public required ulong Va { get; init; }
    public required IReadOnlyList<DecompLine> LowIl { get; init; }
    public required IReadOnlyList<DecompLine> MediumIl { get; init; }
    public required IReadOnlyList<DecompLine> HighIl { get; init; }
    public required IReadOnlyList<DecompLine> PseudoC { get; init; }

    public IReadOnlyList<DecompLine> Lines(ILLevel level) => level switch
    {
        ILLevel.LowIL => LowIl,
        ILLevel.MediumIL => MediumIl,
        ILLevel.HighIL => HighIl,
        _ => PseudoC,
    };
}

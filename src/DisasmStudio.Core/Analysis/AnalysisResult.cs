using DisasmStudio.Core.Formats;

namespace DisasmStudio.Core.Analysis;

/// <summary>An immutable snapshot of everything the analysis discovered, handed to the UI.</summary>
public sealed class AnalysisResult
{
    public required IBinaryImage Image { get; init; }

    /// <summary>Every instruction's VA in image order — the spine of the linear view.
    /// Settable so a local patch repair can splice in a re-decoded region without a full re-analysis.</summary>
    public required LinearIndex Linear { get; set; }

    /// <summary>Discovered functions (entry, exports, call targets), CFG built lazily per function.</summary>
    public required IReadOnlyList<Function> Functions { get; init; }
    public required IReadOnlyDictionary<ulong, Function> FunctionByVa { get; init; }

    public required XrefDatabase Xrefs { get; init; }
    public required IReadOnlyList<FoundString> Strings { get; init; }

    /// <summary>Indirect-jmp VA → recovered switch/jump-table case targets (so the CFG can follow them).</summary>
    public required IReadOnlyDictionary<ulong, ulong[]> JumpTables { get; init; }

    /// <summary>String VA → a data slot pointing at it (a pointer-table entry), for resolving strings
    /// reached only through a pointer. Precomputed so a double-click never scans on the UI thread.</summary>
    public required IReadOnlyDictionary<ulong, ulong> StringPointerSlots { get; init; }

    /// <summary>VA → display name (function / loc_ / import / export) for operand symbolication.</summary>
    public required IReadOnlyDictionary<ulong, string> Names { get; init; }

    /// <summary>Instruction VA → inline comment (e.g. the string it references).</summary>
    public required IReadOnlyDictionary<ulong, string> Comments { get; init; }

    public required IReadOnlyList<string> Warnings { get; init; }

    /// <summary>Best display name for a VA: an exact symbol, else null.</summary>
    public string? NameFor(ulong va) => Names.TryGetValue(va, out var n) ? n : null;
}

namespace DisasmStudio.Core.Formats;

/// <summary>Which container format a file is.</summary>
public enum BinaryFormat { Unknown, Pe, Elf, Raw, Snapshot }

/// <summary>A loaded section/segment, addressed in absolute VAs so the UI is format-agnostic.</summary>
public sealed class Section
{
    public required string Name { get; init; }
    public required ulong StartVa { get; init; }
    public required ulong VirtualSize { get; init; }
    public required int FileOffset { get; init; }
    public required int FileSize { get; init; }
    public bool IsExecutable { get; init; }
    public bool IsReadable { get; init; } = true;
    public bool IsWritable { get; init; }

    /// <summary>End of the section's virtual span (exclusive).</summary>
    public ulong EndVa => StartVa + Math.Max(VirtualSize, (ulong)FileSize);

    public bool ContainsVa(ulong va) => va >= StartVa && va < EndVa;

    public override string ToString() =>
        $"{Name,-10} {StartVa:X8}-{EndVa:X8} {(IsExecutable ? "X" : "-")}{(IsReadable ? "R" : "-")}{(IsWritable ? "W" : "-")}";
}

/// <summary>What a named address represents.</summary>
public enum NamedSymbolKind { Function, Export, Import, Label, Data }

/// <summary>A named address discovered from the file's own metadata (exports, ELF symbols, …).</summary>
public sealed record NamedSymbol(ulong Va, string Name, NamedSymbolKind Kind);

/// <summary>One imported function and the IAT slot that <c>call [slot]</c> targets.</summary>
public sealed record ImportEntry(string Module, string Name, ulong IatVa);

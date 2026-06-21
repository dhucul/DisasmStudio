namespace DisasmStudio.Core.Analysis;

/// <summary>
/// Per-image options chosen at load time: which non-executable sections (and the PE header) to fold
/// into the linear listing as data. Executable sections are always analysed; these are the optional,
/// IDA-style "load this section too" extras. Empty (<see cref="None"/>) reproduces the default — only
/// code in the listing.
/// </summary>
public sealed record AnalysisOptions
{
    /// <summary>Names of non-executable sections to render in the listing as data.</summary>
    public IReadOnlySet<string> IncludedDataSections { get; init; } = new HashSet<string>();

    /// <summary>Render the PE header region (MZ/PE headers) in the listing as data.</summary>
    public bool IncludeHeader { get; init; }

    public static readonly AnalysisOptions None = new();
}

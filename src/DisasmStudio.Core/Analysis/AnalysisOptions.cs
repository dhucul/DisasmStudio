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

    /// <summary>Analyse the image as already-unpacked: still detect the packer (for reporting), but do not
    /// narrow static analysis to the entry-stub window. Set when the bytes came from live process memory after
    /// the original entry point was reached — a UPX memory dump still carries UPX0/UPX1 section names and high
    /// entropy, so the detector would otherwise restrict analysis back onto the (by then dead) loader stub.</summary>
    public bool AssumeUnpacked { get; init; }

    public static readonly AnalysisOptions None = new();
}

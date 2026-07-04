namespace DisasmStudio.Core.Unpacking;

/// <summary>The outcome of a static (no-execution) file→file unpack attempt.</summary>
/// <param name="Applicable">True when this unpacker recognises the format. False ⇒ not my format; try another
/// unpacker or the dynamic path.</param>
/// <param name="Ok">True when a reconstructed image was produced (and, where the format carries a checksum,
/// verified).</param>
/// <param name="Image">The reconstructed image in virtual layout (RVA-indexed), ready to write/open; null on failure.</param>
/// <param name="EntryRva">The recovered entry-point RVA (0 when unknown / still the packer stub).</param>
/// <param name="Blocks">Number of compressed blocks decoded.</param>
public sealed record StaticUnpackResult(
    bool Applicable, bool Ok, byte[]? Image, uint EntryRva, int Blocks, string Log, string? Error)
{
    public static StaticUnpackResult NotApplicable(string why) => new(false, false, null, 0, 0, why, why);
    public static StaticUnpackResult Fail(string log, string error) => new(true, false, null, 0, 0, log, error);
}

/// <summary>
/// A static unpacker: reverses a packer's transform on-disk, with no process launched and no debugger — the
/// route that sidesteps anti-debug entirely, at the cost of being format-specific. Implementations are
/// registered in <see cref="StaticUnpackerRegistry"/> and auto-selected by <see cref="LooksApplicable"/>.
/// Where a static path can't win (virtualized code, or a format this build can't faithfully rebuild), the
/// caller falls back to the dynamic run-to-OEP unpacker / non-invasive dumper.
/// </summary>
public interface IStaticUnpacker
{
    /// <summary>Short human name for the strategy list / log.</summary>
    string Name { get; }

    /// <summary>Cheap, non-throwing probe: does this file look like my format?</summary>
    bool LooksApplicable(byte[] file);

    /// <summary>Attempt the unpack. Returns <see cref="StaticUnpackResult.Applicable"/> = false when the format
    /// isn't actually present.</summary>
    StaticUnpackResult Unpack(byte[] file);
}

/// <summary>Wraps the existing <see cref="VmpStaticUnpacker"/> (VMProtect "Pack the Output File" LZMA layer)
/// behind the <see cref="IStaticUnpacker"/> seam without changing its verified behaviour.</summary>
public sealed class VmpStaticUnpackerAdapter : IStaticUnpacker
{
    public string Name => "VMProtect (packed output / LZMA)";

    public bool LooksApplicable(byte[] file) => VmpStaticUnpacker.LooksApplicable(file);

    public StaticUnpackResult Unpack(byte[] file)
    {
        var r = VmpStaticUnpacker.Unpack(file);
        return new StaticUnpackResult(r.Applicable, r.Ok, r.Image, r.EntryRva, r.Blocks, r.Log, r.Error);
    }
}

/// <summary>The registry of static unpackers, in priority order. <see cref="FindApplicable"/> picks the first
/// whose <see cref="IStaticUnpacker.LooksApplicable"/> matches; the unpacker dialog uses it to auto-select the
/// static strategy and to fall back to the dynamic path when nothing matches.</summary>
public static class StaticUnpackerRegistry
{
    private static readonly IStaticUnpacker[] All =
    [
        new UpxStaticUnpacker(),
        new VmpStaticUnpackerAdapter(),
    ];

    public static IReadOnlyList<IStaticUnpacker> Unpackers => All;

    public static IStaticUnpacker? FindApplicable(byte[] file)
    {
        foreach (var u in All)
        {
            try { if (u.LooksApplicable(file)) return u; }
            catch { /* a probe must never throw the selection */ }
        }
        return null;
    }
}

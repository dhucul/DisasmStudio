using DisasmStudio.Core.Formats;

namespace DisasmStudio.Core.Unpacking;

/// <summary>What a detected packer does — which decides whether generic unpacking can work.</summary>
public enum PackerKind
{
    /// <summary>No packing detected.</summary>
    None,
    /// <summary>Compress-and-restore (UPX, ASPack, FSG, …) — fully unpackable by run-dump-rebuild.</summary>
    Compressor,
    /// <summary>Encrypting/anti-tamper protector — often unpackable, with caveats (anti-debug, redirected IAT).</summary>
    Protector,
    /// <summary>Code-virtualizing protector (VMProtect, Themida, Enigma) — the "OEP" is a bytecode VM; generic
    /// dumping cannot recover native code. Detect-and-warn only.</summary>
    Virtualizer,
    /// <summary>Heuristically packed (high entropy / W+X entry / tiny imports) but no known signature.</summary>
    Unknown,
}

/// <summary>The result of inspecting a PE for packing: a guessed packer name, its behavioural class, the
/// per-section entropy, and human-readable notes.</summary>
public sealed record PackerVerdict(string? Name, PackerKind Kind, IReadOnlyList<(string Section, double Entropy)> SectionEntropy, string Notes)
{
    public bool IsPacked => Kind != PackerKind.None;
    /// <summary>True when generic run-dump-rebuild can plausibly recover the original — i.e. not a virtualizer.</summary>
    public bool IsUnpackable => Kind is PackerKind.Compressor or PackerKind.Protector or PackerKind.Unknown;
}

/// <summary>
/// Heuristic packer detector: section-name signatures (PEiD-style), per-section Shannon entropy, and
/// structural tells (entry point in a writable/high-entropy section, a near-empty import table). Drives the
/// unpacker UI's labelling and the detect-and-warn path for virtualizing protectors.
/// </summary>
public static class PackerDetector
{
    // Section-name → (kind, display name). Matched case-insensitively, exact and prefix.
    private static readonly (string Sig, PackerKind Kind, string Name)[] Signatures =
    [
        ("UPX0", PackerKind.Compressor, "UPX"),
        ("UPX1", PackerKind.Compressor, "UPX"),
        ("UPX2", PackerKind.Compressor, "UPX"),
        (".aspack", PackerKind.Compressor, "ASPack"),
        (".adata", PackerKind.Compressor, "ASPack"),
        ("ASPack", PackerKind.Compressor, "ASPack"),
        (".MPRESS1", PackerKind.Compressor, "MPRESS"),
        (".MPRESS2", PackerKind.Compressor, "MPRESS"),
        ("FSG!", PackerKind.Compressor, "FSG"),
        ("pec1", PackerKind.Compressor, "PECompact"),
        ("pec2", PackerKind.Compressor, "PECompact"),
        ("PEC2", PackerKind.Compressor, "PECompact"),
        (".petite", PackerKind.Compressor, "Petite"),
        ("petite", PackerKind.Compressor, "Petite"),
        (".MEW", PackerKind.Compressor, "MEW"),
        ("MEW", PackerKind.Compressor, "MEW"),
        (".nsp0", PackerKind.Compressor, "NsPack"),
        (".nsp1", PackerKind.Compressor, "NsPack"),
        ("nsp0", PackerKind.Compressor, "NsPack"),
        (".vmp0", PackerKind.Virtualizer, "VMProtect"),
        (".vmp1", PackerKind.Virtualizer, "VMProtect"),
        (".vmp2", PackerKind.Virtualizer, "VMProtect"),
        (".themida", PackerKind.Virtualizer, "Themida"),
        (".winlice", PackerKind.Virtualizer, "Themida/WinLicense"),
        ("Themida", PackerKind.Virtualizer, "Themida"),
        (".enigma1", PackerKind.Protector, "Enigma"),
        (".enigma2", PackerKind.Protector, "Enigma"),
        (".vprotect", PackerKind.Protector, "VProtect"),
        (".yP", PackerKind.Compressor, "Y0da Protector"),
        (".y0da", PackerKind.Protector, "Y0da Protector"),
    ];

    public static PackerVerdict Detect(IBinaryImage img)
    {
        var entropy = new List<(string, double)>();
        foreach (var s in img.Sections)
        {
            int len = Math.Min(s.FileSize, 1 << 20);   // cap per-section sampling at 1 MiB
            var bytes = len > 0 ? img.ReadBytesAtVa(s.StartVa, len) : [];
            entropy.Add((s.Name, Entropy.Shannon(bytes)));
        }

        // 1) Known section-name signature.
        foreach (var s in img.Sections)
            foreach (var (sig, kind, name) in Signatures)
                if (s.Name.Equals(sig, StringComparison.OrdinalIgnoreCase) ||
                    s.Name.StartsWith(sig, StringComparison.OrdinalIgnoreCase))
                {
                    string note = kind == PackerKind.Virtualizer
                        ? $"{name} virtualization detected (section '{s.Name}'). Code is virtualized to bytecode; " +
                          "generic unpacking cannot recover the original — a raw dump is offered for experts only."
                        : $"{name} detected from section '{s.Name}'.";
                    return new PackerVerdict(name, kind, entropy, note);
                }

        // 2) Structural heuristics for unknown packers.
        var entry = img.SectionAt(img.EntryVa);
        double entryEntropy = entry is null ? 0
            : entropy.FirstOrDefault(e => e.Item1 == entry.Name).Item2;
        int moduleCount = img.Imports.Select(i => i.Module).Distinct(StringComparer.OrdinalIgnoreCase).Count();
        int importCount = img.Imports.Count;
        bool entryWritable = entry is { IsWritable: true, IsExecutable: true };
        bool tinyImports = moduleCount <= 2 && importCount <= 12;
        double maxEntropy = entropy.Count > 0 ? entropy.Max(e => e.Item2) : 0;

        var reasons = new List<string>();
        if (entryWritable) reasons.Add($"entry section '{entry!.Name}' is writable+executable (self-modifying)");
        if (entryEntropy > 7.0) reasons.Add($"entry section entropy {entryEntropy:F2} (compressed/encrypted)");
        else if (maxEntropy > 7.2) reasons.Add($"a section has entropy {maxEntropy:F2}");
        if (tinyImports) reasons.Add($"only {importCount} import(s) across {moduleCount} module(s)");

        // Two or more independent tells ⇒ treat as packed-but-unknown.
        if (reasons.Count >= 2)
            return new PackerVerdict(null, PackerKind.Unknown, entropy,
                "Likely packed (unknown packer): " + string.Join("; ", reasons) + ".");

        return new PackerVerdict(null, PackerKind.None, entropy,
            reasons.Count == 1 ? "Possibly packed: " + reasons[0] + "." : "No packing detected.");
    }
}

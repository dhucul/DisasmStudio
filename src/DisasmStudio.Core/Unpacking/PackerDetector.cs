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
/// structural tells (entry point in a writable/high-entropy section, a near-empty import table, odd or
/// duplicated section names). Beyond the name table it carries a structural fingerprint for virtualizing
/// protectors (VMProtect/Themida) whose .vmpN names have been renamed or stripped, so those are still
/// classified as un-dumpable virtualizers rather than generic "unknown" packers. Drives the unpacker UI's
/// labelling and the detect-and-warn path for virtualizing protectors.
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
        (".yP", PackerKind.Protector, "Y0da Protector"),
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

        // 2) Structural heuristics — including a fingerprint for virtualizing protectors (VMProtect /
        //    Themida-class) whose tell-tale .vmpN / .themida section names have been renamed or stripped,
        //    which the name table above cannot catch.
        var entry = img.SectionAt(img.EntryVa);
        // Index into the entropy list by section *position*, not name: protectors routinely emit duplicate
        // section names, so a name lookup would fetch the wrong section's entropy (the entropy list is built
        // in section order above).
        double EntOf(int i) => i >= 0 && i < entropy.Count ? entropy[i].Item2 : 0;
        int idx = -1;
        for (int i = 0; i < img.Sections.Count; i++) if (img.Sections[i].ContainsVa(img.EntryVa)) { idx = i; break; }
        double entryEntropy = EntOf(idx);
        int moduleCount = img.Imports.Select(i => i.Module).Distinct(StringComparer.OrdinalIgnoreCase).Count();
        int importCount = img.Imports.Count;
        bool entryWritable = entry is { IsWritable: true, IsExecutable: true };
        bool emptyImports = importCount == 0;
        bool tinyImports = moduleCount <= 2 && importCount <= 12;
        double maxEntropy = entropy.Count > 0 ? entropy.Max(e => e.Item2) : 0;
        bool entryHighEntropy = entryEntropy > 7.0;

        // A writable+executable section whose contents are high-entropy is a self-decrypting/self-modifying
        // packed body — the protector's runtime lives here. It may be the entry section or, as VMProtect
        // commonly lays it out, a *separate* section the tiny entry stub later jumps into (so we scan all
        // sections, not just the entry's).
        bool rwxHighEntropy = false;
        for (int i = 0; i < img.Sections.Count; i++)
        {
            var s = img.Sections[i];
            if (s.IsWritable && s.IsExecutable && s.FileSize > 0 && EntOf(i) > 7.0) { rwxHighEntropy = true; break; }
        }

        // Imports reduced to the handful of loader primitives a packer stub needs to rebuild the rest of the
        // IAT itself at runtime (LoadLibrary / GetProcAddress / VirtualAlloc / …) — or stripped away entirely.
        bool stubImports = emptyImports
            || (moduleCount <= 2 && importCount <= 16 && LooksLikeLoaderStub(img.Imports));

        // Section-name oddness: protectors emit non-standard and frequently duplicated section names.
        int oddNames = img.Sections.Count(s => !IsConventionalSection(s.Name));
        bool repeatedNames = img.Sections
            .GroupBy(s => s.Name.Trim('\0', ' '), StringComparer.OrdinalIgnoreCase)
            .Any(g => g.Key.Length > 0 && g.Count() > 1);

        var reasons = new List<string>();
        if (rwxHighEntropy) reasons.Add("a writable+executable section is high-entropy (self-decrypting body)");
        else if (entryWritable) reasons.Add($"entry section '{entry!.Name}' is writable+executable (self-modifying)");
        if (entryHighEntropy) reasons.Add($"entry section entropy {entryEntropy:F2} (compressed/encrypted)");
        else if (maxEntropy > 7.2) reasons.Add($"a section has entropy {maxEntropy:F2}");
        if (emptyImports) reasons.Add("import directory empty (imports resolved at runtime)");
        else if (stubImports) reasons.Add($"imports are loader-stub only ({importCount} across {moduleCount} module(s))");
        else if (tinyImports) reasons.Add($"only {importCount} import(s) across {moduleCount} module(s)");
        if (repeatedNames) reasons.Add("repeated section names");
        if (oddNames >= 2) reasons.Add($"{oddNames} non-standard section names");

        // A self-decrypting packed body (RWX + high entropy) plus a loader-stub import set is the core of any
        // run-time packer/protector — including VMProtect/Themida builds whose .vmpN names have been renamed
        // or stripped, which the name table can't catch. Whether such a body merely compresses or fully
        // virtualizes can't be told apart structurally, so split on a VMProtect/Themida tell: these emit twin
        // protector sections (.vmp0/.vmp1, here renamed to identical names) — duplicated section names ⇒ treat
        // as an (un-dumpable) Virtualizer and warn; otherwise an encrypting Protector run-dump-rebuild can try.
        bool packedBody = img.Format == BinaryFormat.Pe && rwxHighEntropy && stubImports;
        if (packedBody && repeatedNames)
            return new PackerVerdict(null, PackerKind.Virtualizer, entropy,
                "Heuristic: virtualizing protector (VMProtect / Themida-class) with renamed or stripped sections — " +
                string.Join("; ", reasons) + ". Code is virtualized to bytecode; generic run-dump-rebuild cannot " +
                "recover the original — a raw dump is offered for experts only.");
        if (packedBody && (oddNames >= 1 || entryWritable))
            return new PackerVerdict(null, PackerKind.Protector, entropy,
                "Likely a protector/crypter: " + string.Join("; ", reasons) +
                ". Often unpackable by run-dump-rebuild, but expect anti-debug and a redirected IAT.");

        // Two or more independent tells ⇒ treat as packed-but-unknown.
        if (reasons.Count >= 2)
            return new PackerVerdict(null, PackerKind.Unknown, entropy,
                "Likely packed (unknown packer): " + string.Join("; ", reasons) + ".");

        return new PackerVerdict(null, PackerKind.None, entropy,
            reasons.Count == 1 ? "Possibly packed: " + reasons[0] + "." : "No packing detected.");
    }

    // Standard, compiler-emitted PE section names — anything outside this set is a mild packer tell.
    private static readonly HashSet<string> ConventionalSections = new(StringComparer.OrdinalIgnoreCase)
    {
        ".text", ".data", ".rdata", ".bss", ".idata", ".edata", ".pdata", ".xdata", ".rsrc", ".reloc",
        ".tls", ".crt", ".gfids", ".giats", ".didat", ".debug", ".00cfg", ".voltbl", ".textbss",
        ".sdata", ".srdata", ".ndata", "init", "page", "pagebgfx", "code", "data", "bss",
    };

    private static bool IsConventionalSection(string name)
    {
        name = name.Trim('\0', ' ');
        return name.Length == 0 || ConventionalSections.Contains(name);
    }

    // The loader primitives a packer/protector stub keeps so it can rebuild the real IAT itself at runtime;
    // everything else it resolves dynamically. An import set dominated by these (and nothing app-specific) is
    // a strong "this is a stub, not the real program" tell.
    private static readonly HashSet<string> LoaderApis = new(StringComparer.OrdinalIgnoreCase)
    {
        "LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "LoadLibraryExW",
        "GetProcAddress", "GetModuleHandleA", "GetModuleHandleW", "GetModuleHandleExA", "GetModuleHandleExW",
        "GetModuleFileNameA", "GetModuleFileNameW", "VirtualAlloc", "VirtualAllocEx", "VirtualProtect",
        "VirtualProtectEx", "VirtualFree", "VirtualQuery", "ExitProcess", "LocalAlloc", "GlobalAlloc",
        "HeapAlloc", "HeapCreate", "GetVersion", "GetVersionExA",
    };

    /// <summary>True when a (small) import set is essentially just the dynamic-loader primitives — the
    /// signature of a packer stub that resolves the real imports itself at runtime.</summary>
    private static bool LooksLikeLoaderStub(IReadOnlyList<ImportEntry> imports)
    {
        if (imports.Count == 0) return true;
        int loader = imports.Count(i => LoaderApis.Contains(i.Name));
        return loader >= Math.Max(2, imports.Count - 1);   // all but at most one import is a loader primitive
    }
}

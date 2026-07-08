using System.Globalization;
using System.IO;
using System.Text;

namespace DisasmStudio.Core.Analysis.Signatures;

/// <summary>
/// A FLIRT/FID-style function signature: a fixed-byte pattern over a function's prologue with wildcards
/// where the bytes vary between builds (relocated addresses, immediates, displacements). Matching is a
/// masked byte compare; <see cref="FixedCount"/> ranks specificity so the most concrete signature wins a
/// collision. Serialized one-per-line as <c>name|bits|pattern</c>, where the pattern is 2-hex-digits per
/// fixed byte and <c>..</c> per wildcard (e.g. <c>4889..24....C3</c>).
/// </summary>
public sealed class Signature
{
    public required string Name { get; init; }
    public required int Bits { get; init; }          // 32 or 64
    public required byte[] Pattern { get; init; }     // fixed bytes (value ignored where masked out)
    public required bool[] Mask { get; init; }        // true = this byte must match; false = wildcard
    public int FixedCount { get; init; }              // count of fixed bytes — specificity for collision ranking

    /// <summary>The first byte when it's fixed (for bucketed lookup), else null (wildcard-first — always checked).</summary>
    public byte? FirstByte => Mask.Length > 0 && Mask[0] ? Pattern[0] : null;

    public bool Matches(ReadOnlySpan<byte> code)
    {
        if (code.Length < Pattern.Length) return false;
        for (int i = 0; i < Pattern.Length; i++)
            if (Mask[i] && code[i] != Pattern[i]) return false;
        return true;
    }

    public string Serialize()
    {
        var sb = new StringBuilder(Name.Length + Pattern.Length * 2 + 8);
        sb.Append(Name).Append('|').Append(Bits).Append('|');
        for (int i = 0; i < Pattern.Length; i++) sb.Append(Mask[i] ? Pattern[i].ToString("X2") : "..");
        return sb.ToString();
    }

    /// <summary>Parse one <c>name|bits|pattern</c> line; null for blank lines, <c>#</c> comments, or malformed input.</summary>
    public static Signature? Parse(string line)
    {
        line = line.Trim();
        if (line.Length == 0 || line[0] == '#') return null;
        var parts = line.Split('|');
        if (parts.Length != 3) return null;
        if (!int.TryParse(parts[1], out int bits) || (bits != 32 && bits != 64)) return null;
        if (ParsePattern(parts[2]) is not var (pat, mask)) return null;
        if (pat.Length == 0) return null;
        int fixedCount = 0;
        foreach (var m in mask) if (m) fixedCount++;
        if (fixedCount == 0) return null;   // an all-wildcard "signature" would match everything
        return new Signature { Name = parts[0], Bits = bits, Pattern = pat, Mask = mask, FixedCount = fixedCount };
    }

    private static (byte[] Pattern, bool[] Mask)? ParsePattern(string p)
    {
        if (p.Length == 0 || p.Length % 2 != 0) return null;
        int n = p.Length / 2;
        var pat = new byte[n];
        var mask = new bool[n];
        for (int i = 0; i < n; i++)
        {
            string h = p.Substring(i * 2, 2);
            if (h == "..") { mask[i] = false; pat[i] = 0; }
            else if (byte.TryParse(h, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var b)) { mask[i] = true; pat[i] = b; }
            else return null;
        }
        return (pat, mask);
    }
}

/// <summary>
/// A collection of <see cref="Signature"/>s indexed by first fixed byte for fast lookup, with a separate
/// bucket for wildcard-first signatures (always checked). <see cref="Shared"/> is the process-wide library
/// loaded from <c>signatures/*.sig</c> beside the executable; <see cref="Reload"/> refreshes it after the
/// user generates new signatures.
/// </summary>
public sealed class SignatureLibrary
{
    private readonly Dictionary<byte, List<Signature>> _byFirst = [];
    private readonly List<Signature> _wildcardFirst = [];
    public int Count { get; private set; }

    public void Add(Signature s)
    {
        if (s.FirstByte is byte b)
        {
            if (!_byFirst.TryGetValue(b, out var list)) _byFirst[b] = list = [];
            list.Add(s);
        }
        else _wildcardFirst.Add(s);
        Count++;
    }

    public void LoadText(string text)
    {
        foreach (var line in text.Split('\n'))
            if (Signature.Parse(line) is { } s) Add(s);
    }

    /// <summary>The most-specific signature (most fixed bytes) matching <paramref name="code"/> for the given
    /// bitness, or null. Ambiguous ties (equal fixed-byte count, different names) are rejected as unreliable.</summary>
    public Signature? Match(ReadOnlySpan<byte> code, int bits)
    {
        Signature? best = null;
        bool tie = false;
        if (code.Length > 0 && _byFirst.TryGetValue(code[0], out var bucket))
            foreach (var s in bucket) Consider(s, code, bits, ref best, ref tie);
        foreach (var s in _wildcardFirst) Consider(s, code, bits, ref best, ref tie);
        return tie ? null : best;
    }

    private static void Consider(Signature s, ReadOnlySpan<byte> code, int bits, ref Signature? best, ref bool tie)
    {
        if (s.Bits != bits || !s.Matches(code)) return;
        if (best is null || s.FixedCount > best.FixedCount) { best = s; tie = false; }
        else if (s.FixedCount == best.FixedCount && s.Name != best.Name) tie = true;
    }

    // ---- shared library loaded from disk ----

    private static SignatureLibrary? _shared;
    private static readonly object Gate = new();

    /// <summary>The directory scanned for user <c>*.sig</c> files: <c>signatures/</c> beside the executable.</summary>
    public static string DefaultDirectory => Path.Combine(AppContext.BaseDirectory, "signatures");

    public static SignatureLibrary Shared
    {
        get { lock (Gate) return _shared ??= LoadFromDirectory(DefaultDirectory); }
    }

    /// <summary>Re-scan the signatures directory (call after generating/importing new <c>.sig</c> files).</summary>
    public static void Reload() { lock (Gate) _shared = LoadFromDirectory(DefaultDirectory); }

    public static SignatureLibrary LoadFromDirectory(string dir)
    {
        var lib = new SignatureLibrary();
        try
        {
            if (Directory.Exists(dir))
                foreach (var file in Directory.EnumerateFiles(dir, "*.sig"))
                    try { lib.LoadText(File.ReadAllText(file)); } catch { /* skip an unreadable file */ }
        }
        catch { /* no directory / access denied → empty library (matching is simply a no-op) */ }
        return lib;
    }
}

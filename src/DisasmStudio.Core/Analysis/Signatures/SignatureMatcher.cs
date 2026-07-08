using DisasmStudio.Core.Formats;
using Iced.Intel;

namespace DisasmStudio.Core.Analysis.Signatures;

/// <summary>
/// Applies a <see cref="SignatureLibrary"/> to a freshly-analysed image — naming the functions whose
/// prologue matches a known library/runtime signature — and generates signatures from a named binary so
/// the library can grow from the user's own corpus (a symboled build, or one they've renamed).
///
/// x86/x64 only (it decodes with Iced to mask relocatable operand bytes); ARM/8051 images are left alone.
/// </summary>
public static class SignatureMatcher
{
    private const int SigBytes = 32;   // prologue window captured/compared (FLIRT-style)

    /// <summary>Rename every still-unnamed (<c>sub_</c>) function whose prologue matches a library signature,
    /// updating <paramref name="names"/> and tagging <paramref name="comments"/>. User renames, symbols,
    /// exports and the entry point are never overwritten. No-op when the library is empty.</summary>
    public static int Apply(IBinaryImage image, IReadOnlyList<Function> functions,
        IDictionary<ulong, string> names, IDictionary<ulong, string> comments, SignatureLibrary library)
    {
        if (library.Count == 0 || image.IsArm || image.Is8051) return 0;
        int bits = image.Bitness;
        int applied = 0;
        foreach (var fn in functions)
        {
            // Only fill in machine placeholders (sub_XXXX). A symbol/export/user rename stays authoritative.
            if (names.TryGetValue(fn.Va, out var cur) && !IsPlaceholder(cur, fn.Va)) continue;
            var code = image.ReadBytesAtVa(fn.Va, SigBytes);
            if (code.Length < 4) continue;
            var match = library.Match(code, bits);
            if (match is null) continue;
            names[fn.Va] = match.Name;
            fn.Name = match.Name;
            comments[fn.Va] = $"library function (sig: {match.Name})";
            applied++;
        }
        return applied;
    }

    private static bool IsPlaceholder(string name, ulong va) =>
        name.Length == 0 || name == $"sub_{va:X}" || name == $"loc_{va:X}";

    /// <summary>Emit signatures for every meaningfully-named function in <paramref name="result"/> (skipping
    /// <c>sub_/loc_</c> placeholders). Each is the function's first <see cref="SigBytes"/> bytes with the
    /// relocatable operand bytes (displacements/immediates) wildcarded, so it matches across builds.</summary>
    public static List<Signature> Generate(AnalysisResult result)
    {
        var sigs = new List<Signature>();
        if (result.Image.IsArm || result.Image.Is8051) return sigs;
        int bits = result.Image.Bitness;
        var seen = new HashSet<string>();   // dedupe identical patterns (thunks share a prologue)
        foreach (var fn in result.Functions)
        {
            string name = result.NameFor(fn.Va) ?? "";
            if (name.Length == 0 || IsPlaceholder(name, fn.Va)) continue;
            if (Build(result.Image, fn.Va, bits, name) is not { } sig) continue;
            if (seen.Add(sig.Serialize())) sigs.Add(sig);
        }
        return sigs;
    }

    /// <summary>Build one signature from the bytes at <paramref name="va"/>: decode instructions across the
    /// window and wildcard each instruction's displacement/immediate byte ranges (via Iced constant offsets),
    /// keeping opcode/prefix/modrm bytes fixed. Trailing wildcards are trimmed so specificity isn't inflated.</summary>
    public static Signature? Build(IBinaryImage image, ulong va, int bits, string name)
    {
        var bytes = image.ReadBytesAtVa(va, SigBytes);
        int n = bytes.Length;
        if (n < 4) return null;

        var mask = new bool[n];
        for (int i = 0; i < n; i++) mask[i] = true;   // fixed by default; operand bytes cleared below

        var decoder = Decoder.Create(bits, new ByteArrayCodeReader(bytes), DecoderOptions.None);
        decoder.IP = va;
        int pos = 0;
        while (pos < n)
        {
            decoder.IP = va + (ulong)pos;
            decoder.Decode(out var instr);
            if (instr.IsInvalid || instr.Length == 0) break;   // stop at the first byte we can't decode
            if (pos + instr.Length > n) break;                 // instruction spills past the window — drop it

            var co = decoder.GetConstantOffsets(instr);
            if (co.HasDisplacement) Wildcard(mask, pos + co.DisplacementOffset, co.DisplacementSize);
            if (co.HasImmediate) Wildcard(mask, pos + co.ImmediateOffset, co.ImmediateSize);
            if (co.HasImmediate2) Wildcard(mask, pos + co.ImmediateOffset2, co.ImmediateSize2);
            pos += instr.Length;
        }
        if (pos < 4) return null;   // couldn't decode a usable prologue

        // Trim to the last decoded byte, then drop trailing wildcards (they add length without specificity).
        int len = pos;
        while (len > 0 && !mask[len - 1]) len--;
        if (len < 4) return null;

        var pat = new byte[len];
        var m = new bool[len];
        int fixedCount = 0;
        for (int i = 0; i < len; i++) { pat[i] = mask[i] ? bytes[i] : (byte)0; m[i] = mask[i]; if (mask[i]) fixedCount++; }
        if (fixedCount < 4) return null;   // too generic to be reliable
        return new Signature { Name = name, Bits = bits, Pattern = pat, Mask = m, FixedCount = fixedCount };
    }

    private static void Wildcard(bool[] mask, int start, int count)
    {
        for (int i = start; i < start + count && i < mask.Length; i++)
            if (i >= 0) mask[i] = false;
    }
}

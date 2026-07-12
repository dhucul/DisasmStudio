using System.Text;
using DisasmStudio.Core.Formats;

namespace DisasmStudio.Core.Analysis;

/// <summary>
/// Byte / hex-pattern / text search over an <see cref="IBinaryImage"/>. A hex pattern (with optional
/// <c>??</c> wildcards) or an ASCII / UTF-16LE string is parsed into a pattern + mask, then the image's
/// VA space is streamed in overlapping windows through <see cref="IBinaryImage.ReadVa"/> — so a match that
/// straddles a window boundary is still found and huge memory-mapped files stay cheap (only touched pages
/// fault in). Unmapped gaps between sections are skipped using <c>ReadVa</c>'s returned contiguous count.
/// </summary>
public static class ByteSearch
{
    private const int ChunkSize = 1 << 16;   // 64 KiB scan window

    /// <summary>Parse "48 8B ?? 05" / "488B05" / "48-8b-05" into bytes + a mask (mask[i]==false ⇒ the byte is
    /// a wildcard). A wildcard byte is written as <c>??</c>. Separators (space, tab, comma, '-', ':') are
    /// ignored. Returns false on an invalid nibble, an odd number of hex digits, or an all-wildcard pattern
    /// (which would match everywhere).</summary>
    public static bool TryParseHex(string text, out byte[] pattern, out bool[] mask)
    {
        pattern = [];
        mask = [];
        if (string.IsNullOrWhiteSpace(text)) return false;

        var sb = new StringBuilder(text.Length);
        foreach (char c in text)
            if (c is not (' ' or '\t' or ',' or '-' or ':')) sb.Append(c);
        string s = sb.ToString();
        if (s.Length == 0 || (s.Length & 1) != 0) return false;   // need whole bytes

        int n = s.Length / 2;
        var p = new byte[n];
        var m = new bool[n];
        bool anyFixed = false;
        for (int i = 0; i < n; i++)
        {
            char a = s[2 * i], b = s[2 * i + 1];
            if (a == '?' && b == '?') { p[i] = 0; m[i] = false; continue; }   // whole-byte wildcard
            int hi = HexVal(a), lo = HexVal(b);
            if (hi < 0 || lo < 0) return false;   // invalid digit or a half-wildcard byte ("4?")
            p[i] = (byte)((hi << 4) | lo);
            m[i] = true;
            anyFixed = true;
        }
        if (!anyFixed) return false;   // all wildcards ⇒ matches everywhere

        pattern = p;
        mask = m;
        return true;
    }

    /// <summary>Encode <paramref name="text"/> as ASCII/Latin-1 bytes (<paramref name="wide"/>=false) or
    /// UTF-16LE bytes (<paramref name="wide"/>=true). The returned pattern has no wildcards.</summary>
    public static byte[] ParseText(string text, bool wide)
    {
        if (string.IsNullOrEmpty(text)) return [];
        if (wide) return Encoding.Unicode.GetBytes(text);   // UTF-16LE, as stored in most Windows binaries
        var b = new byte[text.Length];
        for (int i = 0; i < text.Length; i++) b[i] = (byte)text[i];
        return b;
    }

    /// <summary>Find the first match at/after <paramref name="start"/> (forward) or at/before it (backward),
    /// wrapping around the image once. Returns the match's start VA, or null if the pattern occurs nowhere.
    /// <paramref name="mask"/> may be null (every byte significant).</summary>
    public static ulong? Find(IBinaryImage img, ulong start, byte[] pattern, bool[]? mask,
                              bool forward, CancellationToken token = default)
    {
        if (pattern.Length == 0) return null;
        ulong min = img.MinVa, max = img.MaxVa;
        if (max < min + (ulong)pattern.Length) return null;
        if (start < min) start = min;
        if (start > max - 1) start = max - 1;

        if (forward)
            // Primary pass finds nothing >= start ⇒ the wrap pass (from the start of the image) is
            // guaranteed to return a match < start, so there is no double-report.
            return FindForward(img, start, pattern, mask, token)
                ?? FindForward(img, min, pattern, mask, token);

        return FindBackward(img, start, pattern, mask, token)
            ?? FindBackward(img, max - 1, pattern, mask, token);
    }

    /// <summary>First match whose start VA is >= <paramref name="from"/> (scanning up to MaxVa).</summary>
    private static ulong? FindForward(IBinaryImage img, ulong from, byte[] pat, bool[]? mask, CancellationToken token)
    {
        int len = pat.Length;
        ulong min = img.MinVa, max = img.MaxVa;
        if (from < min) from = min;
        var buf = new byte[ChunkSize + len - 1];

        ulong pos = from;
        while (pos + (ulong)len <= max)
        {
            if (token.IsCancellationRequested) return null;
            int want = (int)Math.Min((ulong)buf.Length, max - pos);
            int read = img.ReadVa(pos, buf.AsSpan(0, want));
            if (read == 0)
            {
                // Whole window unmapped — jump to the next page (mappings are page-granular).
                ulong nextPage = (pos & ~0xFFFUL) + 0x1000;
                pos = nextPage > pos ? nextPage : pos + 1;
                continue;
            }
            if (read < len) { pos += (ulong)read; continue; }   // short mapped tail: no full pattern fits

            int limit = read - len;   // last start index in buf that holds a full pattern
            for (int i = 0; i <= limit; i++)
                if (Matches(buf, i, pat, mask)) return pos + (ulong)i;

            pos += (ulong)(read - (len - 1));   // keep (len-1) overlap so a boundary-straddling match is caught
        }
        return null;
    }

    /// <summary>Last match whose start VA is &lt;= <paramref name="from"/>. Implemented on top of the
    /// gap-robust forward scan (resuming past each hit), so its total work is a single forward sweep of
    /// [MinVa, from].</summary>
    private static ulong? FindBackward(IBinaryImage img, ulong from, byte[] pat, bool[]? mask, CancellationToken token)
    {
        ulong? last = null;
        ulong pos = img.MinVa;
        while (true)
        {
            var hit = FindForward(img, pos, pat, mask, token);
            if (hit is null || hit.Value > from) break;
            last = hit;
            if (hit.Value == ulong.MaxValue) break;   // overflow guard
            pos = hit.Value + 1;
            if (token.IsCancellationRequested) break;
        }
        return last;
    }

    private static bool Matches(byte[] buf, int off, byte[] pat, bool[]? mask)
    {
        for (int i = 0; i < pat.Length; i++)
            if ((mask is null || mask[i]) && buf[off + i] != pat[i]) return false;
        return true;
    }

    private static int HexVal(char c) => c switch
    {
        >= '0' and <= '9' => c - '0',
        >= 'a' and <= 'f' => c - 'a' + 10,
        >= 'A' and <= 'F' => c - 'A' + 10,
        _ => -1,
    };
}

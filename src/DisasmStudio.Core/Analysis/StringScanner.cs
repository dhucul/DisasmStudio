using System.Text;
using DisasmStudio.Core.Formats;

namespace DisasmStudio.Core.Analysis;

/// <summary>A printable string found in the image, with the VA that locates it.</summary>
public sealed record FoundString(ulong Va, int Length, bool Wide, string Text);

/// <summary>
/// Scans for printable ASCII and UTF-16LE runs in one pass over the memory-mapped backing.
/// Non-executable sections are scanned wholesale. Executable sections (where some toolchains place
/// read-only string literals, e.g. when .rdata is merged into .text) are scanned too, but a run is
/// only kept when code actually references into it — otherwise code bytes would flood the list.
/// Capped so a pathological file can't produce unbounded results.
/// </summary>
public static class StringScanner
{
    public static List<FoundString> Scan(IBinaryImage img, IReadOnlySet<ulong>? execRefs = null,
        int minLength = 4, int maxResults = 200_000, CancellationToken token = default)
    {
        var found = new List<FoundString>();
        foreach (var s in img.Sections)
        {
            if (!s.IsReadable || s.FileSize <= 0) continue;
            // Executable section: only mine it for strings code points into (needs the ref set).
            var gate = s.IsExecutable ? execRefs : null;
            if (s.IsExecutable && gate is null) continue;
            ScanSection(img, s, minLength, maxResults, found, gate, token);
            if (found.Count >= maxResults) break;
        }
        return found;
    }

    private static void ScanSection(IBinaryImage img, Section s, int minLength, int maxResults,
        List<FoundString> found, IReadOnlySet<ulong>? gate, CancellationToken token)
    {
        ulong start = s.StartVa;
        int size = s.FileSize;
        var buf = img.ReadBytesAtVa(start, size);

        int i = 0;
        while (i < buf.Length)
        {
            if ((i & 0xFFFF) == 0 && token.IsCancellationRequested) return;
            if (found.Count >= maxResults) return;

            // ASCII run
            int a = i;
            while (a < buf.Length && IsPrintable(buf[a])) a++;
            int asciiLen = a - i;

            // UTF-16LE run (printable, low byte set, high byte zero)
            int w = i, wchars = 0;
            while (w + 1 < buf.Length && buf[w + 1] == 0 && IsPrintable(buf[w])) { w += 2; wchars++; }

            if (wchars >= minLength && wchars * 2 >= asciiLen)
            {
                if (gate is null || Referenced(gate, start + (ulong)i, wchars * 2))
                    found.Add(new FoundString(start + (ulong)i, wchars, true, DecodeAscii(buf, i, wchars * 2, wide: true)));
                i = w;
            }
            else if (asciiLen >= minLength)
            {
                if (gate is null || Referenced(gate, start + (ulong)i, asciiLen))
                    found.Add(new FoundString(start + (ulong)i, asciiLen, false, DecodeAscii(buf, i, asciiLen, wide: false)));
                i = a;
            }
            else i++;
        }
    }

    /// <summary>True if any byte of the run is a recorded data-reference target.</summary>
    private static bool Referenced(IReadOnlySet<ulong> gate, ulong va, int byteLen)
    {
        for (int k = 0; k < byteLen; k++)
            if (gate.Contains(va + (ulong)k)) return true;
        return false;
    }

    private static bool IsPrintable(byte b) => b is >= 0x20 and < 0x7F or 0x09;

    private static string DecodeAscii(byte[] buf, int offset, int byteLen, bool wide)
    {
        var sb = new StringBuilder(byteLen);
        for (int k = 0; k < byteLen; k += wide ? 2 : 1)
            sb.Append((char)buf[offset + k]);
        return sb.ToString();
    }
}

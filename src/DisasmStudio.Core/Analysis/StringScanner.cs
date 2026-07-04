using System.Text;
using DisasmStudio.Core.Formats;

namespace DisasmStudio.Core.Analysis;

/// <summary>A printable string found in the image, with the VA that locates it. <see cref="Referenced"/>
/// marks a string recovered by following a live argument/register pointer at a debugger stop (so it can
/// live on the heap, the stack, or in another module) rather than swept from a data section.</summary>
public sealed record FoundString(ulong Va, int Length, bool Wide, string Text)
{
    public bool Referenced { get; init; }
}

/// <summary>
/// Scans for printable ASCII and UTF-16LE runs in one pass over the memory-mapped backing.
/// Non-executable sections are scanned wholesale. Executable sections (where some toolchains place
/// read-only string literals, e.g. when .rdata is merged into .text) are scanned too, but a run is
/// only kept when code actually references into it — otherwise code bytes would flood the list.
/// Capped so a pathological file can't produce unbounded results.
/// </summary>
public static class StringScanner
{
    /// <summary>Cap on bytes scanned per section when reading live process memory: a section's VirtualSize can
    /// be huge or only partly committed, so this bounds the read + buffer (ReadBytesAtVa returns the committed
    /// prefix anyway).</summary>
    private const int MaxLiveSectionBytes = 32 * 1024 * 1024;

    /// <param name="useVirtualSize">Scan each section's whole virtual extent rather than its on-disk size — used
    /// when scanning live process memory, where decrypted/unpacked strings can live past the raw file size.</param>
    public static List<FoundString> Scan(IBinaryImage img, IReadOnlySet<ulong>? execRefs = null,
        int minLength = 4, int maxResults = 200_000, bool useVirtualSize = false, bool includeExecutable = false,
        CancellationToken token = default)
    {
        var found = new List<FoundString>();
        foreach (var s in img.Sections)
        {
            if (!s.IsReadable) continue;
            int size = useVirtualSize
                ? (int)Math.Min(Math.Max(s.VirtualSize, (ulong)s.FileSize), (ulong)MaxLiveSectionBytes)
                : s.FileSize;
            if (size <= 0) continue;
            // Executable section: only mine it for strings code points into (needs the ref set) — unless the
            // caller opts in to scanning the whole span (a raw firmware blob is one big "executable" section
            // that legitimately holds string tables; ArmAnalyzer opts in, then filters out code-region hits).
            var gate = s.IsExecutable ? execRefs : null;
            if (s.IsExecutable && gate is null && !includeExecutable) continue;
            ScanSection(img, s.StartVa, size, minLength, maxResults, found, gate, token);
            if (found.Count >= maxResults) break;
        }
        return found;
    }

    private static void ScanSection(IBinaryImage img, ulong start, int size, int minLength, int maxResults,
        List<FoundString> found, IReadOnlySet<ulong>? gate, CancellationToken token)
    {
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

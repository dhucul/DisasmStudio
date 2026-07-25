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
    private const int ScanReadChunkBytes = 1024 * 1024;
    private const int MaxStringCharacters = 1024 * 1024;

    private sealed record Candidate(FoundString Value, int ByteLength);

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
        if (minLength < 1) throw new ArgumentOutOfRangeException(nameof(minLength));
        if (maxResults < 0) throw new ArgumentOutOfRangeException(nameof(maxResults));
        var found = new List<FoundString>();
        if (maxResults == 0) return found;
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
            if (!ScanSection(img, s.StartVa, size, minLength, maxResults, found, gate, token))
                break;
            if (found.Count >= maxResults) break;
        }
        return found;
    }

    private static bool ScanSection(IBinaryImage img, ulong start, int size, int minLength, int maxResults,
        List<FoundString> found, IReadOnlySet<ulong>? gate, CancellationToken token)
    {
        int candidateLimit = maxResults > int.MaxValue / 2 ? int.MaxValue : Math.Max(16, maxResults * 2);
        var candidates = new List<Candidate>(Math.Min(candidateLimit, 4096));

        int asciiLength = 0;
        ulong asciiStart = 0;
        bool asciiTooLong = false;
        var asciiText = new StringBuilder();

        int[] wideLength = [0, 0];
        ulong[] wideStart = [0, 0];
        bool[] wideTooLong = [false, false];
        StringBuilder[] wideText = [new(), new()];

        void FinishAscii()
        {
            if (!asciiTooLong && asciiLength >= minLength && candidates.Count < candidateLimit
                && (gate is null || Referenced(gate, asciiStart, asciiLength)))
                candidates.Add(new Candidate(new FoundString(asciiStart, asciiLength, false, asciiText.ToString()), asciiLength));
            asciiLength = 0;
            asciiTooLong = false;
            asciiText.Clear();
        }

        void FinishWide(int parity)
        {
            if (!wideTooLong[parity] && wideLength[parity] >= minLength && candidates.Count < candidateLimit)
            {
                int byteLength = checked(wideLength[parity] * 2);
                if (gate is null || Referenced(gate, wideStart[parity], byteLength))
                    candidates.Add(new Candidate(
                        new FoundString(wideStart[parity], wideLength[parity], true, wideText[parity].ToString()),
                        byteLength));
            }
            wideLength[parity] = 0;
            wideTooLong[parity] = false;
            wideText[parity].Clear();
        }

        byte previous = 0;
        bool havePrevious = false;
        int read = 0;
        while (read < size && candidates.Count < candidateLimit)
        {
            if (token.IsCancellationRequested) return false;
            int requested = Math.Min(ScanReadChunkBytes, size - read);
            var chunk = img.ReadBytesAtVa(start + (ulong)read, requested);
            if (token.IsCancellationRequested) return false;
            int count = Math.Min(requested, chunk.Length);
            if (count == 0) break;

            for (int i = 0; i < count; i++)
            {
                if ((i & 0xFFFF) == 0 && token.IsCancellationRequested) return false;
                byte current = chunk[i];
                ulong va = start + (ulong)read + (ulong)i;

                if (IsPrintable(current))
                {
                    if (asciiLength == 0) asciiStart = va;
                    asciiLength++;
                    if (asciiLength <= MaxStringCharacters) asciiText.Append((char)current);
                    else asciiTooLong = true;
                }
                else
                {
                    FinishAscii();
                }

                if (havePrevious)
                {
                    ulong pairStart = va - 1;
                    int parity = (int)((pairStart - start) & 1);
                    if (IsPrintable(previous) && current == 0)
                    {
                        if (wideLength[parity] == 0) wideStart[parity] = pairStart;
                        wideLength[parity]++;
                        if (wideLength[parity] <= MaxStringCharacters) wideText[parity].Append((char)previous);
                        else wideTooLong[parity] = true;
                    }
                    else
                    {
                        FinishWide(parity);
                    }
                }
                previous = current;
                havePrevious = true;
            }

            read += count;
            if (count < requested) break;
        }

        FinishAscii();
        FinishWide(0);
        FinishWide(1);

        candidates.Sort((x, y) =>
        {
            int byVa = x.Value.Va.CompareTo(y.Value.Va);
            if (byVa != 0) return byVa;
            if (x.Value.Wide != y.Value.Wide) return x.Value.Wide ? -1 : 1;
            return y.ByteLength.CompareTo(x.ByteLength);
        });

        ulong skipUntil = start;
        for (int i = 0; i < candidates.Count && found.Count < maxResults;)
        {
            ulong va = candidates[i].Value.Va;
            int j = i;
            Candidate? ascii = null, wide = null;
            while (j < candidates.Count && candidates[j].Value.Va == va)
            {
                if (candidates[j].Value.Wide) wide ??= candidates[j];
                else ascii ??= candidates[j];
                j++;
            }

            Candidate chosen = wide is not null && (ascii is null || wide.ByteLength >= ascii.ByteLength) ? wide : ascii!;
            if (va >= skipUntil)
            {
                found.Add(chosen.Value);
                skipUntil = va > ulong.MaxValue - (ulong)chosen.ByteLength
                    ? ulong.MaxValue
                    : va + (ulong)chosen.ByteLength;
            }
            i = j;
        }
        return true;
    }

    /// <summary>True if any byte of the run is a recorded data-reference target.</summary>
    private static bool Referenced(IReadOnlySet<ulong> gate, ulong va, int byteLen)
    {
        for (int k = 0; k < byteLen; k++)
            if (gate.Contains(va + (ulong)k)) return true;
        return false;
    }

    private static bool IsPrintable(byte b) => b is >= 0x20 and < 0x7F or 0x09;

}

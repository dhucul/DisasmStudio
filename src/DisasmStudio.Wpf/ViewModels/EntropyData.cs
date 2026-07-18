using System;
using System.Collections.Generic;
using DisasmStudio.Core.Formats;
using DisasmStudio.Core.Unpacking;

namespace DisasmStudio.Wpf.ViewModels;

/// <summary>
/// Byte-entropy of a loaded file, computed once (lazily, off the UI thread) for the Entropy tab.
/// <see cref="Blocks"/> is a coarse per-block Shannon-entropy profile (bits/byte, 0…8) walking the
/// on-disk bytes front to back, which the graph plots against file offset; <see cref="Sections"/> is
/// the per-section breakdown for the table; <see cref="Overall"/> is the whole-file value. Everything
/// is file-offset based (on-disk layout), not VA — so a compressed/encrypted/packed region reads ≈8.
/// Format-agnostic: it consumes only <see cref="IBinaryImage.ReadByteAtOffset"/> + the section list.
/// </summary>
public sealed class EntropyData
{
    /// <summary>Per-block entropy (bits/byte, 0…8) walking the file front to back; ≤~1024 samples.</summary>
    public required double[] Blocks { get; init; }
    /// <summary>Bytes per block — <c>Blocks[i]</c> covers file offsets <c>[i*BlockSize, …)</c>.</summary>
    public required int BlockSize { get; init; }
    public required long FileLength { get; init; }
    /// <summary>Whole-file Shannon entropy (bits/byte, 0…8).</summary>
    public required double Overall { get; init; }
    public required IReadOnlyList<SectionEntropyItem> Sections { get; init; }
    /// <summary>Section spans in file-offset space, for the graph's vertical dividers + hover labels
    /// (real, non-empty sections only).</summary>
    public required IReadOnlyList<(string Name, long Start, long End)> Bounds { get; init; }

    private const int TargetBlocks = 1024;   // graph resolution cap, so large files stay cheap
    private const int MinBlock = 256;        // smallest block that yields a meaningful histogram

    /// <summary>Build the entropy profile from a loaded image's on-disk bytes. Pure and read-only, so it's
    /// safe to run on a background thread.</summary>
    public static EntropyData Build(IBinaryImage img)
    {
        long len = img.BackingLength;
        int blockSize = len <= 0 ? MinBlock
            : (int)Math.Max(MinBlock, (len + TargetBlocks - 1) / TargetBlocks);

        var blocks = new List<double>(len <= 0 ? 0 : (int)((len + blockSize - 1) / blockSize));
        var buf = new byte[blockSize];
        Span<int> total = stackalloc int[256];   // whole-file histogram, accumulated during the block scan

        for (long off = 0; off < len; off += blockSize)
        {
            int n = (int)Math.Min(blockSize, len - off);
            for (int i = 0; i < n; i++)
            {
                byte b = img.ReadByteAtOffset((int)(off + i));
                buf[i] = b;
                total[b]++;
            }
            blocks.Add(Entropy.Shannon(buf.AsSpan(0, n)));
        }

        double overall = ShannonOf(total, len);

        var sections = new List<SectionEntropyItem>();
        var bounds = new List<(string, long, long)>();
        foreach (var s in img.Sections)
        {
            if (s.FileSize <= 0) { sections.Add(new SectionEntropyItem(s.Name, -1)); continue; }
            double e = SectionEntropy(img, s.FileOffset, s.FileSize);
            sections.Add(new SectionEntropyItem(s.Name, e));
            bounds.Add((s.Name, s.FileOffset, (long)s.FileOffset + s.FileSize));
        }

        return new EntropyData
        {
            Blocks = blocks.ToArray(),
            BlockSize = blockSize,
            FileLength = len,
            Overall = overall,
            Sections = sections,
            Bounds = bounds,
        };
    }

    // Entropy of one on-disk section, histogrammed directly (sections can be MBs — avoid a big buffer).
    private static double SectionEntropy(IBinaryImage img, int offset, int size)
    {
        Span<int> counts = stackalloc int[256];
        long end = Math.Min((long)offset + size, img.BackingLength);
        for (long o = offset; o < end; o++) counts[img.ReadByteAtOffset((int)o)]++;
        return ShannonOf(counts, end - offset);
    }

    // Shannon entropy from a 256-bin histogram (the block path uses Entropy.Shannon over the bytes directly;
    // this variant lets the whole-file / per-section paths avoid a second pass or a large buffer).
    private static double ShannonOf(ReadOnlySpan<int> counts, long n)
    {
        if (n <= 0) return 0;
        double e = 0;
        foreach (int c in counts)
            if (c > 0) { double p = c / (double)n; e -= p * Math.Log2(p); }
        return e;
    }
}

/// <summary>One row in the Entropy tab's per-section table. <see cref="Value"/> is bits/byte (0…8), or
/// negative for a section with no on-disk bytes (e.g. <c>.bss</c>), shown as "—". <see cref="IsHigh"/>
/// (&gt;7.0) flags likely compressed/encrypted/packed data — the same threshold the packer detector uses.</summary>
public sealed class SectionEntropyItem(string name, double value)
{
    public string Name => name;
    public double Value => value;
    public bool HasData => value >= 0;
    public string Entropy => HasData ? value.ToString("F2") : "—";
    /// <summary>0…1 fill fraction for the mini bar (0 when the section has no data).</summary>
    public double Fraction => HasData ? Math.Clamp(value / 8.0, 0, 1) : 0;
    public bool IsHigh => HasData && value > 7.0;
    public string Flag => IsHigh ? "packed?" : "";
}

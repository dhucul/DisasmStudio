namespace DisasmStudio.Core.Analysis;

/// <summary>
/// The ordered start VA of every line in the linear view — code instructions and data runs — stored
/// as fixed-size chunks so even a many-million-line image never allocates one giant array on the LOH.
/// Each entry packs a code/data flag in the unused top bit (image VAs are well under 2^63), so a line
/// costs ~8 bytes and classification is free. Line <c>k</c> → <see cref="VaAt"/> is O(1) and the view
/// decodes/renders only the rows on screen.
/// </summary>
public sealed class LinearIndex
{
    private const int ChunkBits = 20;            // 1,048,576 entries per chunk
    private const int ChunkSize = 1 << ChunkBits;
    private const int ChunkMask = ChunkSize - 1;
    private const ulong DataFlag = 1UL << 63;
    private const ulong AddrMask = ~DataFlag;

    private readonly List<ulong[]> _chunks = [];
    private int _countInLast;

    public long Count { get; private set; }

    public void Add(ulong va, bool isData = false)
    {
        if (_chunks.Count == 0 || _countInLast == ChunkSize)
        {
            _chunks.Add(new ulong[ChunkSize]);
            _countInLast = 0;
        }
        _chunks[^1][_countInLast++] = isData ? (va | DataFlag) : va;
        Count++;
    }

    private ulong RawAt(long line) => _chunks[(int)(line >> ChunkBits)][(int)(line & ChunkMask)];

    public ulong VaAt(long line) => line < 0 || line >= Count ? 0 : RawAt(line) & AddrMask;

    /// <summary>True if line <paramref name="line"/> is a data run (rendered as db/dd/dq/string) rather than an instruction.</summary>
    public bool IsDataAt(long line) => line >= 0 && line < Count && (RawAt(line) & DataFlag) != 0;

    /// <summary>A copy with all entries in [<paramref name="start"/>, <paramref name="end"/>) replaced by
    /// <paramref name="codeStarts"/> (instruction starts of the re-decoded region). Used for local patch
    /// repair — no re-sweep of the whole image, just a copy of the (cheap) index.</summary>
    public LinearIndex CloneWithRegion(ulong start, ulong end, IReadOnlyList<ulong> codeStarts)
    {
        var ni = new LinearIndex();
        long i = 0;
        for (; i < Count && VaAt(i) < start; i++) ni.Add(VaAt(i), IsDataAt(i));
        foreach (var s in codeStarts) ni.Add(s);          // re-decoded region is code
        while (i < Count && VaAt(i) < end) i++;            // drop the old region's entries
        for (; i < Count; i++) ni.Add(VaAt(i), IsDataAt(i));
        return ni;
    }

    /// <summary>Line index of <paramref name="va"/> — the nearest entry at or below it, or 0 (the first line)
    /// when <paramref name="va"/> precedes every entry. Callers needing an exact hit must compare
    /// <see cref="VaAt"/> of the result to <paramref name="va"/>.</summary>
    public long IndexOf(ulong va)
    {
        if (Count == 0) return 0;
        long lo = 0, hi = Count - 1, best = 0;
        while (lo <= hi)
        {
            long mid = (lo + hi) >> 1;
            ulong m = VaAt(mid);
            if (m == va) return mid;
            if (m < va) { best = mid; lo = mid + 1; }
            else hi = mid - 1;
        }
        return best;
    }
}

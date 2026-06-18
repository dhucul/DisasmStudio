namespace DisasmStudio.Core.Analysis;

/// <summary>
/// The ordered VA of every instruction in the linear sweep, stored as fixed-size chunks so even a
/// many-million-instruction image never allocates one giant array on the LOH. This is the spine of
/// the large-file linear view: line <c>k</c> → <see cref="VaAt"/> is O(1), and the view decodes only
/// the rows on screen. ~8 bytes per instruction.
/// </summary>
public sealed class LinearIndex
{
    private const int ChunkBits = 20;            // 1,048,576 entries per chunk
    private const int ChunkSize = 1 << ChunkBits;
    private const int ChunkMask = ChunkSize - 1;

    private readonly List<ulong[]> _chunks = [];
    private int _countInLast;

    public long Count { get; private set; }

    public void Add(ulong va)
    {
        if (_chunks.Count == 0 || _countInLast == ChunkSize)
        {
            _chunks.Add(new ulong[ChunkSize]);
            _countInLast = 0;
        }
        _chunks[^1][_countInLast++] = va;
        Count++;
    }

    public ulong VaAt(long line)
    {
        if (line < 0 || line >= Count) return 0;
        return _chunks[(int)(line >> ChunkBits)][(int)(line & ChunkMask)];
    }

    /// <summary>Line index of <paramref name="va"/>, or the line of the nearest instruction at/below it.</summary>
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

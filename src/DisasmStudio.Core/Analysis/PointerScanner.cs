using DisasmStudio.Core.Formats;

namespace DisasmStudio.Core.Analysis;

/// <summary>
/// Builds, once during analysis, a map from a string VA to a data slot that points at it — i.e. a
/// <c>const char* table[]</c> entry. Lets the UI resolve strings that code reaches only through a
/// pointer (no direct reference to the string itself): cross-references to that slot then reveal the
/// code that loads it. Runs on the analysis (background) thread so the per-click lookup is O(1) and
/// never touches the disk-backed mapping on the UI thread.
/// </summary>
public static class PointerScanner
{
    private const int ScanReadChunkBytes = 1024 * 1024;

    public static Dictionary<ulong, ulong> BuildStringPointerMap(
        IBinaryImage img, IReadOnlySet<ulong> stringStarts, long maxBytes = 64 * 1024 * 1024,
        CancellationToken token = default)
    {
        var map = new Dictionary<ulong, ulong>();
        if (stringStarts.Count == 0 || maxBytes <= 0) return map;

        int ptr = img.Bitness / 8; // 4 or 8
        long scanned = 0;
        foreach (var s in img.Sections)
        {
            if (!s.IsReadable || s.IsExecutable || s.FileSize <= 0) continue;
            long sectionLimit = Math.Min(s.FileSize, maxBytes - scanned);
            int sectionOffset = 0;
            while (sectionOffset < sectionLimit)
            {
                if (token.IsCancellationRequested) return map;
                int requested = (int)Math.Min(ScanReadChunkBytes, sectionLimit - sectionOffset);
                var buf = img.ReadBytesAtVa(s.StartVa + (ulong)sectionOffset, requested);
                if (token.IsCancellationRequested) return map;
                int count = Math.Min(requested, buf.Length);
                for (int i = 0; i + ptr <= count; i += ptr) // pointers are aligned relative to the section
                {
                    if ((i & 0xFFFFF) == 0 && token.IsCancellationRequested) return map;
                    ulong val = ptr == 8 ? BitConverter.ToUInt64(buf, i) : BitConverter.ToUInt32(buf, i);
                    if (stringStarts.Contains(val)) map.TryAdd(val, s.StartVa + (ulong)sectionOffset + (ulong)i);
                }
                if (count == 0) break;
                scanned += count;
                sectionOffset += count;
                if (count < requested) break;
            }
            if (scanned >= maxBytes) break;
        }
        return map;
    }

    /// <summary>
    /// Collect aligned pointer-sized values in the data sections that point into executable memory —
    /// code pointers (vtable entries, callback tables, jump tables). Used to seed the code map so
    /// methods reachable only through a vtable aren't mis-classified as data. On 64-bit the executable
    /// range is tiny relative to 2^64, so a data value landing in it is almost always a real pointer.
    /// </summary>
    public static List<ulong> CollectCodePointers(IBinaryImage img, long maxBytes = 64 * 1024 * 1024,
        CancellationToken token = default)
    {
        var result = new List<ulong>();
        var seen = new HashSet<ulong>();
        if (maxBytes <= 0) return result;
        int ptr = img.Bitness / 8;
        long scanned = 0;
        foreach (var s in img.Sections)
        {
            if (!s.IsReadable || s.IsExecutable || s.FileSize <= 0) continue;
            long sectionLimit = Math.Min(s.FileSize, maxBytes - scanned);
            int sectionOffset = 0;
            while (sectionOffset < sectionLimit)
            {
                if (token.IsCancellationRequested) return result;
                int requested = (int)Math.Min(ScanReadChunkBytes, sectionLimit - sectionOffset);
                var buf = img.ReadBytesAtVa(s.StartVa + (ulong)sectionOffset, requested);
                if (token.IsCancellationRequested) return result;
                int count = Math.Min(requested, buf.Length);
                for (int i = 0; i + ptr <= count; i += ptr)
                {
                    if ((i & 0xFFFFF) == 0 && token.IsCancellationRequested) return result;
                    ulong v = ptr == 8 ? BitConverter.ToUInt64(buf, i) : BitConverter.ToUInt32(buf, i);
                    if (img.IsExecutableVa(v) && seen.Add(v)) result.Add(v);
                }
                if (count == 0) break;
                scanned += count;
                sectionOffset += count;
                if (count < requested) break;
            }
            if (scanned >= maxBytes) break;
        }
        return result;
    }
}

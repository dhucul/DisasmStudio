using System.Text;
using DisasmStudio.Core.Unpacking;

namespace DisasmStudio.Core.Formats;

/// <summary>One captured committed memory region in a process snapshot: its VA, bytes, PE-style
/// characteristics (exec/read/write), and a short name.</summary>
public sealed record SnapshotSegment(ulong Va, byte[] Bytes, uint Characteristics, string Name)
{
    public bool IsExecutable => (Characteristics & (PeConstants.SCN_MEM_EXECUTE | PeConstants.SCN_CNT_CODE)) != 0;
    public bool IsWritable => (Characteristics & PeConstants.SCN_MEM_WRITE) != 0;
}

/// <summary>
/// A multi-segment snapshot of a process's address space — the main image plus the private VM/heap regions a
/// virtualizing protector (Themida/VMProtect) keeps its decrypted bytecode and context in, *outside* the main
/// PE. Captured by <c>DisasmStudio.Debug.Unpacking.ProcessSnapshot</c> and stored in a small <c>.dssnap</c>
/// container. Unlike <see cref="PeMemoryImage"/> (one contiguous image) this maps several disjoint VA ranges,
/// so an indirect jump into a separately-allocated VM region (e.g. <c>jmp [0x780000]</c>) resolves during
/// analysis. The container's bytes ARE the backing store — each segment's "file offset" is its offset in the
/// <c>.dssnap</c> data area, so no copy is made on load.
/// </summary>
public sealed class ProcessSnapshotImage : IBinaryImage
{
    // "DSSNAP01" — the container magic (first 8 bytes).
    public static ReadOnlySpan<byte> Magic => "DSSNAP01"u8;
    private const int HeaderSize = 40;
    private const int SegEntrySize = 48;

    private readonly byte[] _backing;       // the whole .dssnap file; segment bytes live at their data offsets
    private readonly Seg[] _segs;           // sorted by Va
    private bool _dirty;
    private int _patchCount;

    private readonly record struct Seg(ulong Va, int Start, int Size, uint Characteristics, string Name);

    public string FilePath { get; }
    public BinaryFormat Format => BinaryFormat.Snapshot;
    public string FormatName => "Process snapshot";
    public int Bitness { get; }
    public string ArchName => Bitness == 64 ? "x64" : "x86";
    public ulong ImageBase { get; }
    public ulong EntryVa { get; }
    public bool IsDll => false;
    public IReadOnlyList<Section> Sections { get; }
    public IReadOnlyList<NamedSymbol> Symbols => [];
    public IReadOnlyList<ImportEntry> Imports => [];
    public Section? HeaderRegion => null;
    public ResourceTree? Resources => null;
    public IReadOnlyList<ulong> FunctionStarts => [];
    public IReadOnlyDictionary<ulong, ImportEntry> ImportsByIatVa { get; } = new Dictionary<ulong, ImportEntry>();
    public int BackingLength => _backing.Length;
    public ulong MinVa { get; }
    public ulong MaxVa { get; }

    private ProcessSnapshotImage(string path, byte[] backing, int bitness, ulong imageBase, ulong entryVa, Seg[] segs)
    {
        FilePath = path;
        _backing = backing;
        Bitness = bitness == 64 ? 64 : 32;
        ImageBase = imageBase;
        EntryVa = entryVa;
        _segs = segs;
        Sections = segs.Select(s => new Section
        {
            Name = s.Name,
            StartVa = s.Va,
            VirtualSize = (ulong)s.Size,
            FileOffset = s.Start,
            FileSize = s.Size,
            IsExecutable = (s.Characteristics & (PeConstants.SCN_MEM_EXECUTE | PeConstants.SCN_CNT_CODE)) != 0,
            IsReadable = true,
            IsWritable = (s.Characteristics & PeConstants.SCN_MEM_WRITE) != 0,
        }).ToList();
        MinVa = segs.Length > 0 ? segs[0].Va : imageBase;
        MaxVa = segs.Length > 0 ? segs.Max(s => s.Va + (ulong)s.Size) : imageBase;
    }

    // ---- container I/O ----

    /// <summary>Serialize a snapshot to a <c>.dssnap</c> file.</summary>
    public static void Write(string path, int bitness, ulong imageBase, ulong entryVa, IReadOnlyList<SnapshotSegment> segments)
    {
        long dataOffset = HeaderSize + (long)segments.Count * SegEntrySize;
        long total = dataOffset;
        foreach (var s in segments) total += s.Bytes.Length;

        var buf = new byte[total];
        Magic.CopyTo(buf);
        WriteU32(buf, 8, 1);                       // version
        WriteU32(buf, 12, (uint)bitness);
        WriteU64(buf, 16, imageBase);
        WriteU64(buf, 24, entryVa);
        WriteU32(buf, 32, (uint)segments.Count);

        long off = dataOffset;
        for (int i = 0; i < segments.Count; i++)
        {
            var s = segments[i];
            int e = HeaderSize + i * SegEntrySize;
            WriteU64(buf, e + 0, s.Va);
            WriteU64(buf, e + 8, (ulong)s.Bytes.Length);
            WriteU64(buf, e + 16, (ulong)off);
            WriteU32(buf, e + 24, s.Characteristics);
            var name = Encoding.ASCII.GetBytes(s.Name);
            Array.Copy(name, 0, buf, e + 32, Math.Min(name.Length, 15));
            Array.Copy(s.Bytes, 0, buf, off, s.Bytes.Length);
            off += s.Bytes.Length;
        }
        File.WriteAllBytes(path, buf);
    }

    public static bool IsSnapshot(ReadOnlySpan<byte> head) => head.Length >= 8 && head[..8].SequenceEqual(Magic);

    public static ProcessSnapshotImage Load(string path)
    {
        var b = File.ReadAllBytes(path);
        if (b.Length < HeaderSize || !IsSnapshot(b))
            throw new BinaryFormatException("Not a DisasmStudio process snapshot (.dssnap).");
        int bitness = (int)U32(b, 12);
        ulong imageBase = U64(b, 16);
        ulong entryVa = U64(b, 24);
        int segCount = (int)U32(b, 32);

        var segs = new List<Seg>(segCount);
        for (int i = 0; i < segCount; i++)
        {
            int e = HeaderSize + i * SegEntrySize;
            if (e + SegEntrySize > b.Length) break;
            ulong va = U64(b, e + 0);
            long size = (long)U64(b, e + 8);
            long start = (long)U64(b, e + 16);
            uint ch = U32(b, e + 24);
            string name = ReadName(b, e + 32);
            if (start < 0 || size < 0 || start + size > b.Length) continue;   // skip a corrupt entry
            segs.Add(new Seg(va, (int)start, (int)size, ch, name));
        }
        segs.Sort((x, y) => x.Va.CompareTo(y.Va));
        return new ProcessSnapshotImage(path, b, bitness, imageBase, entryVa, segs.ToArray());
    }

    // ---- segment lookup ----

    private int FindSeg(ulong va)
    {
        int lo = 0, hi = _segs.Length - 1;
        while (lo <= hi)
        {
            int mid = (lo + hi) >> 1;
            var s = _segs[mid];
            if (va < s.Va) hi = mid - 1;
            else if (va >= s.Va + (ulong)s.Size) lo = mid + 1;
            else return mid;
        }
        return -1;
    }

    public Section? SectionAt(ulong va) { int i = FindSeg(va); return i >= 0 ? Sections[i] : null; }

    public int VaToOffset(ulong va)
    {
        int i = FindSeg(va);
        return i < 0 ? -1 : _segs[i].Start + (int)(va - _segs[i].Va);
    }

    public bool IsMappedVa(ulong va) => FindSeg(va) >= 0;
    public bool IsExecutableVa(ulong va) { int i = FindSeg(va); return i >= 0 && Sections[i].IsExecutable; }

    public byte ReadByteAtOffset(int offset) => (uint)offset < (uint)_backing.Length ? _backing[offset] : (byte)0;

    public byte[] ReadBytesAtVa(ulong va, int count)
    {
        int i = FindSeg(va);
        if (i < 0 || count <= 0) return [];
        var s = _segs[i];
        int avail = s.Size - (int)(va - s.Va);                 // do not bleed past this segment into the gap
        count = Math.Min(count, avail);
        var outBuf = new byte[count];
        Array.Copy(_backing, s.Start + (int)(va - s.Va), outBuf, 0, count);
        return outBuf;
    }

    public int ReadVa(ulong va, Span<byte> dest)
    {
        int i = FindSeg(va);
        if (i < 0 || dest.Length == 0) return 0;
        var s = _segs[i];
        int avail = s.Size - (int)(va - s.Va);
        int n = Math.Min(dest.Length, avail);
        _backing.AsSpan(s.Start + (int)(va - s.Va), n).CopyTo(dest);
        return n;
    }

    // ---- patching (in place over the backing; persisted by re-writing the container) ----
    public void Patch(int offset, ReadOnlySpan<byte> bytes)
    {
        if (offset < 0 || offset >= _backing.Length || bytes.Length == 0) return;
        int n = Math.Min(bytes.Length, _backing.Length - offset);
        bytes[..n].CopyTo(_backing.AsSpan(offset, n));
        _dirty = true; _patchCount += n;
    }
    public bool PatchVa(ulong va, ReadOnlySpan<byte> bytes) { int o = VaToOffset(va); if (o < 0) return false; Patch(o, bytes); return true; }
    public void RevertPatch(int offset, int count) { }
    public bool IsPatchedAt(int offset) => false;
    public bool IsDirty => _dirty;
    public int PatchCount => _patchCount;
    public IReadOnlyDictionary<int, byte> Patches => System.Collections.Immutable.ImmutableDictionary<int, byte>.Empty;
    public bool Undo() => false;
    public bool CanUndo => false;
    public void SavePatchedAs(string path) => File.WriteAllBytes(path, _backing);

    private static void WriteU32(byte[] b, int o, uint v) => BitConverter.GetBytes(v).CopyTo(b, o);
    private static void WriteU64(byte[] b, int o, ulong v) => BitConverter.GetBytes(v).CopyTo(b, o);
    private static uint U32(byte[] b, int o) => BitConverter.ToUInt32(b, o);
    private static ulong U64(byte[] b, int o) => BitConverter.ToUInt64(b, o);
    private static string ReadName(byte[] b, int o)
    {
        int end = o;
        while (end < o + 16 && end < b.Length && b[end] != 0) end++;
        return Encoding.ASCII.GetString(b, o, end - o);
    }
}

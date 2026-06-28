using DisasmStudio.Core.Unpacking;

namespace DisasmStudio.Core.Formats;

/// <summary>
/// A PE image captured from process memory, where file offset == RVA. DebuggerEngine.DumpImage produces this
/// layout: headers at offset 0 and committed image pages copied to their runtime RVA. This is different from
/// an on-disk PE, whose section headers point at file raw offsets.
/// </summary>
public sealed class PeMemoryImage : IBinaryImage
{
    private readonly byte[] _bytes;
    private readonly PeView _view;
    private readonly List<Section> _sections;
    private bool _dirty;
    private int _patchCount;

    private PeMemoryImage(string path, byte[] bytes, PeView view, ulong? imageBaseOverride)
    {
        FilePath = path;
        _bytes = bytes;
        _view = view;
        ImageBase = imageBaseOverride is { } b && b != 0 ? b : view.ImageBase;
        _sections = BuildSections(bytes, view, ImageBase);
    }

    public static PeMemoryImage Load(string path, ulong? imageBaseOverride = null)
    {
        var bytes = File.ReadAllBytes(path);
        if (!PeView.TryParse(bytes, out var view))
            throw new BinaryFormatException("Not a PE memory image dump.");
        return new PeMemoryImage(path, bytes, view, imageBaseOverride);
    }

    public static bool TryLoad(string path, out PeMemoryImage image, ulong? imageBaseOverride = null)
    {
        image = null!;
        try
        {
            var bytes = File.ReadAllBytes(path);
            if (!PeView.TryParse(bytes, out var view)) return false;
            image = new PeMemoryImage(path, bytes, view, imageBaseOverride);
            return true;
        }
        catch { return false; }
    }

    /// <summary>Build a memory-image view directly from an in-memory dump (e.g. <c>DebuggerEngine.DumpImage</c>),
    /// with no file on disk. <paramref name="displayPath"/> is what the UI shows as the "file" (the process's
    /// module path, or a placeholder). Returns false if the bytes aren't a parseable PE.</summary>
    public static bool TryLoadFromBytes(byte[] bytes, ulong? imageBaseOverride, string displayPath, out PeMemoryImage image)
    {
        image = null!;
        try
        {
            if (bytes is null || bytes.Length == 0 || !PeView.TryParse(bytes, out var view)) return false;
            image = new PeMemoryImage(displayPath, bytes, view, imageBaseOverride);
            return true;
        }
        catch { return false; }
    }

    public string FilePath { get; }
    public BinaryFormat Format => BinaryFormat.Pe;
    public string FormatName => "PE memory";
    public int Bitness => _view.Is64 ? 64 : 32;
    public string ArchName => Bitness == 64 ? "x64" : "x86";
    public ulong ImageBase { get; }
    public ulong EntryVa => _view.EntryRva != 0 ? ImageBase + _view.EntryRva : 0;
    public bool IsDll => (_view.Characteristics & 0x2000) != 0;
    public IReadOnlyList<Section> Sections => _sections;
    public IReadOnlyList<NamedSymbol> Symbols => [];
    public IReadOnlyList<ImportEntry> Imports => [];
    public Section? HeaderRegion => new()
    {
        Name = "HEADER",
        StartVa = ImageBase,
        VirtualSize = _view.SizeOfHeaders,
        FileOffset = 0,
        FileSize = (int)Math.Min(_view.SizeOfHeaders, (uint)_bytes.Length),
        IsReadable = true,
    };
    public ResourceTree? Resources => null;
    public IReadOnlyList<ulong> FunctionStarts => [];
    public IReadOnlyDictionary<ulong, ImportEntry> ImportsByIatVa { get; } = new Dictionary<ulong, ImportEntry>();
    public int BackingLength => _bytes.Length;
    public ulong MinVa => ImageBase;
    public ulong MaxVa => ImageBase + (ulong)_bytes.Length;

    public byte ReadByteAtOffset(int offset) => (uint)offset < (uint)_bytes.Length ? _bytes[offset] : (byte)0;

    public void Patch(int offset, ReadOnlySpan<byte> bytes)
    {
        if (offset < 0 || offset >= _bytes.Length || bytes.Length == 0) return;
        int n = Math.Min(bytes.Length, _bytes.Length - offset);
        bytes[..n].CopyTo(_bytes.AsSpan(offset, n));
        _dirty = true;
        _patchCount += n;
    }

    public bool PatchVa(ulong va, ReadOnlySpan<byte> bytes)
    {
        int off = VaToOffset(va);
        if (off < 0) return false;
        Patch(off, bytes);
        return true;
    }

    public void RevertPatch(int offset, int count) { }
    public bool IsPatchedAt(int offset) => false;
    public bool IsDirty => _dirty;
    public int PatchCount => _patchCount;
    public bool Undo() => false;
    public bool CanUndo => false;
    public void SavePatchedAs(string path) => File.WriteAllBytes(path, _bytes);

    public Section? SectionAt(ulong va)
    {
        foreach (var s in _sections) if (s.ContainsVa(va)) return s;
        return null;
    }

    public int VaToOffset(ulong va)
    {
        if (va < ImageBase) return -1;
        ulong rva = va - ImageBase;
        return rva < (ulong)_bytes.Length ? (int)rva : -1;
    }

    public bool IsMappedVa(ulong va) => VaToOffset(va) >= 0;
    public bool IsExecutableVa(ulong va) => SectionAt(va) is { IsExecutable: true };

    public byte[] ReadBytesAtVa(ulong va, int count)
    {
        int off = VaToOffset(va);
        if (off < 0 || count <= 0) return [];
        count = Math.Min(count, _bytes.Length - off);
        var b = new byte[count];
        Array.Copy(_bytes, off, b, 0, count);
        return b;
    }

    public int ReadVa(ulong va, Span<byte> dest)
    {
        int off = VaToOffset(va);
        if (off < 0 || dest.Length == 0) return 0;
        int n = Math.Min(dest.Length, _bytes.Length - off);
        _bytes.AsSpan(off, n).CopyTo(dest);
        return n;
    }

    private static List<Section> BuildSections(byte[] bytes, PeView view, ulong imageBase)
    {
        var list = new List<Section>(view.Sections.Count);
        foreach (var s in view.Sections)
        {
            if (s.VirtualAddress >= bytes.Length) continue;
            ulong span = Math.Max(s.VirtualSize, s.SizeOfRawData);
            if (span == 0) span = 1;
            int fileSize = (int)Math.Min(span, (ulong)bytes.Length - s.VirtualAddress);
            list.Add(new Section
            {
                Name = s.Name,
                StartVa = imageBase + s.VirtualAddress,
                VirtualSize = (ulong)fileSize,
                FileOffset = (int)s.VirtualAddress,
                FileSize = fileSize,
                IsExecutable = s.IsExecutable,
                IsReadable = true,
                IsWritable = s.IsWritable,
            });
        }
        return list;
    }
}

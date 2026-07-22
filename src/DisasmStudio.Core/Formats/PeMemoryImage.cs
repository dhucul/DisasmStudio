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
    private readonly InPlacePatchMap _edits;

    private PeMemoryImage(string path, byte[] bytes, PeView view, ulong? imageBaseOverride)
    {
        FilePath = path;
        _bytes = bytes;
        _edits = new InPlacePatchMap(_bytes);
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

    /// <summary>Heuristic: do this PE file's on-disk bytes look like a raw memory image (sections at their virtual
    /// addresses, spanning ~SizeOfImage) rather than a normal on-disk executable (sections at file offsets)? Used to
    /// distinguish a genuine memory dump from an ordinary program that merely has an ambiguous extension (e.g. .bin)
    /// — loading the latter as a memory image would read every section at the wrong offset and render garbage.</summary>
    public static bool LooksLikeMemoryImage(string path)
    {
        try { return LooksLikeMemoryImage(File.ReadAllBytes(path)); }
        catch { return false; }
    }

    public static bool LooksLikeMemoryImage(byte[] bytes)
    {
        if (!PeView.TryParse(bytes, out var v) || v.Sections.Count == 0) return false;

        // If every section's raw pointer already equals its RVA — a single-section PE, a FileAlignment==SectionAlignment
        // build, or a dump with rebuilt headers — the on-disk and in-memory layouts coincide, so the NORMAL PE loader
        // reads the correct bytes AND recovers imports/exports/resources. Prefer it (don't claim a memory image).
        bool allAtRva = true;
        foreach (var s in v.Sections) if (s.PointerToRawData != s.VirtualAddress) { allAtRva = false; break; }
        if (allAtRva) return false;

        // Sections are file-aligned (raw pointer != RVA), so the two layouts differ. It's a raw memory image only if
        // the file is actually laid out by RVA: big enough to hold every section at its virtual address AND sized to
        // the virtual image (~SizeOfImage). A normal on-disk PE is file-aligned and smaller; even one with a large
        // appended overlay won't match the virtual-image size. This deliberately biases toward the normal PE loader.
        long len = bytes.LongLength;
        long virtEnd = v.SizeOfHeaders;
        foreach (var s in v.Sections) virtEnd = Math.Max(virtEnd, (long)s.VirtualAddress + Math.Max(s.VirtualSize, s.SizeOfRawData));
        long align = Math.Max(v.SectionAlignment, 0x1000u);
        return len >= virtEnd && len <= (long)v.SizeOfImage + align;   // spans the sections' RVAs and ≈ the virtual image
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

    public void Patch(int offset, ReadOnlySpan<byte> bytes) => _edits.Patch(offset, bytes);

    public bool PatchVa(ulong va, ReadOnlySpan<byte> bytes)
    {
        int off = VaToOffset(va);
        if (off < 0) return false;
        Patch(off, bytes);
        return true;
    }

    public void RevertPatch(int offset, int count) => _edits.RevertPatch(offset, count);
    public bool IsPatchedAt(int offset) => _edits.IsPatchedAt(offset);
    public bool IsDirty => _edits.IsDirty;
    public int PatchCount => _edits.PatchCount;
    public IReadOnlyDictionary<int, byte> Patches => _edits.Patches;
    public bool Undo() => _edits.Undo();
    public bool CanUndo => _edits.CanUndo;
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

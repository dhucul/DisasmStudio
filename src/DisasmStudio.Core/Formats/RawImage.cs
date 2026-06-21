namespace DisasmStudio.Core.Formats;

/// <summary>
/// A flat blob mapped 1:1 at a user-chosen base VA with a chosen bitness — for shellcode,
/// memory dumps, or firmware. The whole file is one read+execute "section", so VA = base + offset.
/// </summary>
public sealed class RawImage : IBinaryImage, IDisposable
{
    private readonly MappedFile _f;
    private readonly Section _section;

    public void Dispose() => _f.Dispose();   // release the memory-mapped file

    public string FilePath { get; }
    public BinaryFormat Format => BinaryFormat.Raw;
    public string FormatName => "Raw";
    public int Bitness { get; }
    public string ArchName => Bitness == 64 ? "x64" : "x86";
    public ulong ImageBase { get; }
    public ulong EntryVa => ImageBase;
    public bool IsDll => false;
    public IReadOnlyList<Section> Sections { get; }
    public IReadOnlyList<NamedSymbol> Symbols => [];
    public IReadOnlyList<ImportEntry> Imports => [];
    public Section? HeaderRegion => null;       // a flat blob has no header region
    public ResourceTree? Resources => null;     // and no resource directory
    public IReadOnlyList<ulong> FunctionStarts => [];
    public IReadOnlyDictionary<ulong, ImportEntry> ImportsByIatVa { get; } = new Dictionary<ulong, ImportEntry>();
    public int BackingLength => _f.Length;

    private RawImage(MappedFile f, string path, ulong baseVa, int bitness)
    {
        _f = f;
        FilePath = path;
        ImageBase = baseVa;
        Bitness = bitness == 64 ? 64 : 32;
        _section = new Section
        {
            Name = ".raw",
            StartVa = baseVa,
            VirtualSize = (ulong)f.Length,
            FileOffset = 0,
            FileSize = f.Length,
            IsExecutable = true,
            IsReadable = true,
            IsWritable = false,
        };
        Sections = [_section];
    }

    public static RawImage Load(string path, ulong baseVa, int bitness) =>
        new(MappedFile.Open(path), path, baseVa, bitness);

    public ulong MinVa => ImageBase;
    public ulong MaxVa => ImageBase + (ulong)_f.Length;

    public byte ReadByteAtOffset(int offset) => _f.ReadByte(offset);

    public void Patch(int offset, ReadOnlySpan<byte> bytes) => _f.Patch(offset, bytes);
    public bool PatchVa(ulong va, ReadOnlySpan<byte> bytes) { int o = VaToOffset(va); if (o < 0) return false; _f.Patch(o, bytes); return true; }
    public void RevertPatch(int offset, int count) => _f.RevertPatch(offset, count);
    public bool IsPatchedAt(int offset) => _f.IsPatched(offset);
    public bool IsDirty => _f.IsDirty;
    public int PatchCount => _f.PatchCount;
    public bool Undo() => _f.Undo();
    public bool CanUndo => _f.CanUndo;
    public void SavePatchedAs(string path) => _f.SaveAs(path);

    public Section? SectionAt(ulong va) => _section.ContainsVa(va) ? _section : null;

    public int VaToOffset(ulong va) =>
        va >= ImageBase && va < ImageBase + (ulong)_f.Length ? (int)(va - ImageBase) : -1;

    public bool IsMappedVa(ulong va) => VaToOffset(va) >= 0;
    public bool IsExecutableVa(ulong va) => IsMappedVa(va);

    public byte[] ReadBytesAtVa(ulong va, int count)
    {
        int off = VaToOffset(va);
        if (off < 0) return [];
        count = Math.Clamp(count, 0, _f.Length - off);
        return _f.ReadBytes(off, count);
    }

    public int ReadVa(ulong va, Span<byte> dest)
    {
        int off = VaToOffset(va);
        if (off < 0) return 0;
        return _f.ReadInto(off, dest);
    }
}

/// <summary>Sniffs a file's magic and loads the matching image.</summary>
public static class BinaryLoader
{
    public static BinaryFormat Detect(string path)
    {
        using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        Span<byte> head = stackalloc byte[4];
        int n = fs.Read(head);
        if (n >= 2 && head[0] == (byte)'M' && head[1] == (byte)'Z') return BinaryFormat.Pe;
        if (n >= 4 && head[0] == 0x7F && head[1] == (byte)'E' && head[2] == (byte)'L' && head[3] == (byte)'F')
            return BinaryFormat.Elf;
        return BinaryFormat.Unknown;
    }

    /// <summary>Load a PE or ELF by sniffing its magic; throws for anything else (use <see cref="RawImage.Load"/>).</summary>
    public static IBinaryImage Load(string path) => Detect(path) switch
    {
        BinaryFormat.Pe => PeImage.Load(path),
        BinaryFormat.Elf => ElfImage.Load(path),
        _ => throw new BinaryFormatException("Unrecognised format — open as raw instead."),
    };
}

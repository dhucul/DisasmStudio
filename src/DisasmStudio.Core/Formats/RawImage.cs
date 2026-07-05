namespace DisasmStudio.Core.Formats;

/// <summary>
/// A flat blob mapped 1:1 at a user-chosen base VA with a chosen bitness — for shellcode,
/// memory dumps, or firmware. The whole file is one read+execute "section", so VA = base + offset.
/// The entry point is separate from the base (firmware begins at a reset vector near the top of the
/// image, not at offset 0), and any firmware markers found by <see cref="FirmwareScanner"/> are exposed
/// as <see cref="Symbols"/> so they seed analysis and name the listing.
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
    public Architecture Arch { get; }
    public string ArchName => Arch switch
    {
        Architecture.Arm => "arm",
        Architecture.Thumb => "thumb",
        Architecture.Arm64 => "arm64",
        Architecture.I8051 => "8051",
        _ => Bitness switch { 64 => "x64", 16 => "x86-16", _ => "x86" },
    };
    public ulong ImageBase { get; }
    public ulong EntryVa { get; }
    public bool IsDll => false;
    public IReadOnlyList<Section> Sections { get; }
    public IReadOnlyList<NamedSymbol> Symbols { get; }
    public IReadOnlyList<ImportEntry> Imports => [];
    public Section? HeaderRegion => null;       // a flat blob has no header region
    public ResourceTree? Resources => null;     // and no resource directory
    public IReadOnlyList<ulong> FunctionStarts => [];
    public IReadOnlyDictionary<ulong, ImportEntry> ImportsByIatVa { get; } = new Dictionary<ulong, ImportEntry>();
    public int BackingLength => _f.Length;

    private RawImage(MappedFile f, string path, ulong baseVa, int bitness, ulong entryVa,
                     Architecture arch, IReadOnlyList<NamedSymbol>? symbols)
    {
        _f = f;
        FilePath = path;
        ImageBase = baseVa;
        Arch = arch;
        // ARM/Thumb are 32-bit, AArch64 is 64-bit; 8051 is 8-bit with a 16-bit code space. 8051 never
        // reaches Iced, but a few UI paths still construct the Iced Disassembler unconditionally, and
        // Decoder.Create only accepts 16/32/64 — so report 16 (never 8). Otherwise honour the x86 bitness.
        Bitness = arch switch
        {
            Architecture.Arm64 => 64,
            Architecture.Arm or Architecture.Thumb => 32,
            Architecture.I8051 => 16,
            _ => bitness switch { 64 => 64, 16 => 16, _ => 32 },
        };
        EntryVa = entryVa;
        // Keep only markers that land inside the mapped blob, so a seed can never point analysis at an
        // unmapped VA (e.g. a legacy reset vector's far jump into low memory that this mapping doesn't cover).
        ulong end = baseVa + (ulong)f.Length;
        Symbols = symbols is null || symbols.Count == 0
            ? []
            : symbols.Where(s => s.Va >= baseVa && s.Va < end).ToArray();
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

    /// <summary>Map a flat blob at <paramref name="baseVa"/> with the entry at the base (shellcode / dumps).</summary>
    public static RawImage Load(string path, ulong baseVa, int bitness) =>
        new(MappedFile.Open(path), path, baseVa, bitness, baseVa, ArchFor(bitness), null);

    /// <summary>Map a flat blob with an explicit entry point and optional firmware markers (see
    /// <see cref="FirmwareScanner"/>). Used for firmware, whose entry is a reset vector near the top of the image.</summary>
    public static RawImage Load(string path, ulong baseVa, int bitness, ulong entryVa,
                                IReadOnlyList<NamedSymbol>? symbols) =>
        new(MappedFile.Open(path), path, baseVa, bitness, entryVa, ArchFor(bitness), symbols);

    /// <summary>Map a flat blob with an explicit instruction-set architecture — the ARM-family path used by
    /// the raw-load dialog to open firmware as ARM/Thumb/AArch64. Bitness is derived from the architecture.</summary>
    public static RawImage Load(string path, ulong baseVa, int bitness, ulong entryVa,
                                Architecture arch, IReadOnlyList<NamedSymbol>? symbols) =>
        new(MappedFile.Open(path), path, baseVa, bitness, entryVa, arch, symbols);

    private static Architecture ArchFor(int bitness) => bitness == 64 ? Architecture.X64 : Architecture.X86;

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
        Span<byte> head = stackalloc byte[8];
        int n = fs.Read(head);
        if (n >= 8 && ProcessSnapshotImage.IsSnapshot(head)) return BinaryFormat.Snapshot;
        if (n >= 2 && head[0] == (byte)'M' && head[1] == (byte)'Z') return BinaryFormat.Pe;
        if (n >= 4 && head[0] == 0x7F && head[1] == (byte)'E' && head[2] == (byte)'L' && head[3] == (byte)'F')
            return BinaryFormat.Elf;
        return BinaryFormat.Unknown;
    }

    /// <summary>Load a PE, ELF or process snapshot by sniffing its magic; throws for anything else
    /// (use <see cref="RawImage.Load"/>).</summary>
    public static IBinaryImage Load(string path) => Detect(path) switch
    {
        BinaryFormat.Pe => PeImage.Load(path),
        BinaryFormat.Elf => ElfImage.Load(path),
        BinaryFormat.Snapshot => ProcessSnapshotImage.Load(path),
        _ => throw new BinaryFormatException("Unrecognised format — open as raw instead."),
    };
}

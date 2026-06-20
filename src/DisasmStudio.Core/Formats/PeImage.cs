using System.Text;

namespace DisasmStudio.Core.Formats;

/// <summary>
/// A parsed Portable Executable (PE32 / PE32+). The RVA↔VA↔offset math, section model and
/// import parsing follow RipperStudio's read-only loader; export parsing is added so the
/// disassembler can name exported functions. All reads go through a memory-mapped backing.
/// </summary>
public sealed class PeImage : IBinaryImage
{
    private readonly MappedFile _f;
    private readonly List<Section> _sections;
    private readonly List<NamedSymbol> _symbols = [];
    private readonly List<ImportEntry> _imports = [];
    private readonly Dictionary<ulong, ImportEntry> _importsByIat = [];
    private readonly List<ulong> _runtimeFunctions = [];

    private readonly int _peHeader;

    private PeImage(MappedFile f, string path)
    {
        _f = f;
        FilePath = path;
        _peHeader = _f.ReadI32(0x3C);
        Validate();

        _sections = ReadSections();
        ParseImports();
        ParseExports();
        ParseExceptions();
        ImportsByIatVa = _importsByIat;
    }

    public static PeImage Load(string path) => new(MappedFile.Open(path), path);

    // ---- IBinaryImage ----
    public string FilePath { get; }
    public BinaryFormat Format => BinaryFormat.Pe;
    public string FormatName => "PE";
    public int Bitness => Is64Bit ? 64 : 32;
    public string ArchName => Machine switch { 0x014C => "x86", 0x8664 => "x64", 0xAA64 => "arm64", _ => $"0x{Machine:X}" };
    public ulong ImageBase => Is64Bit ? _f.ReadU64(OptHeader + 24) : _f.ReadU32(OptHeader + 28);
    public ulong EntryVa => ImageBase + _f.ReadU32(OptHeader + 16);
    public IReadOnlyList<Section> Sections => _sections;
    public IReadOnlyList<NamedSymbol> Symbols => _symbols;
    public IReadOnlyList<ImportEntry> Imports => _imports;
    public IReadOnlyList<ulong> FunctionStarts => _runtimeFunctions;
    public IReadOnlyDictionary<ulong, ImportEntry> ImportsByIatVa { get; }
    public int BackingLength => _f.Length;

    public ulong MinVa => ImageBase;
    public ulong MaxVa
    {
        get
        {
            ulong max = ImageBase + SizeOfHeaders;
            foreach (var s in _sections) max = Math.Max(max, s.EndVa);
            return max;
        }
    }

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

    public Section? SectionAt(ulong va)
    {
        foreach (var s in _sections) if (s.ContainsVa(va)) return s;
        return null;
    }

    public int VaToOffset(ulong va)
    {
        if (va < ImageBase || va - ImageBase > uint.MaxValue) return -1;
        uint rva = (uint)(va - ImageBase);
        if (rva < SizeOfHeaders) return (int)rva;
        var s = SectionAt(va);
        if (s is null) return -1;
        long off = (long)(va - s.StartVa) + s.FileOffset;
        return off >= 0 && off < _f.Length ? (int)off : -1;
    }

    public bool IsMappedVa(ulong va)
    {
        if (va < ImageBase || va - ImageBase > uint.MaxValue) return false;
        int off = VaToOffset(va);
        return off >= 0 && off < _f.Length;
    }

    public bool IsExecutableVa(ulong va) => SectionAt(va) is { IsExecutable: true };

    public byte[] ReadBytesAtVa(ulong va, int count)
    {
        int off = VaToOffset(va);
        if (off < 0) return [];
        count = Math.Clamp(count, 0, _f.Length - off);
        return _f.ReadBytes(off, count);
    }

    public int ReadVa(ulong va, Span<byte> dest)
    {
        int n = 0;
        for (; n < dest.Length; n++)
        {
            int off = VaToOffset(va + (ulong)n);
            if (off < 0) break;
            dest[n] = _f.ReadByte(off);
        }
        return n;
    }

    // ---- PE header fields ----
    private int OptHeader => _peHeader + 24;
    private int FileHeader => _peHeader + 4;
    private ushort OptMagic => _f.ReadU16(OptHeader);
    private bool Is64Bit => OptMagic == 0x20B;
    private ushort Machine => _f.ReadU16(FileHeader + 0);
    private ushort NumberOfSections => _f.ReadU16(FileHeader + 2);
    private ushort SizeOfOptionalHeader => _f.ReadU16(FileHeader + 16);
    private uint SizeOfHeaders => _f.ReadU32(OptHeader + 60);
    private uint NumberOfRvaAndSizes => _f.ReadU32(OptHeader + (Is64Bit ? 108 : 92));
    private int DataDirBase => OptHeader + (Is64Bit ? 112 : 96);
    private int SectionTableOffset => OptHeader + SizeOfOptionalHeader;
    private int PointerSize => Is64Bit ? 8 : 4;

    private (uint Rva, uint Size) DataDir(int index)
    {
        if ((uint)index >= NumberOfRvaAndSizes) return (0, 0);
        int off = DataDirBase + index * 8;
        return (_f.ReadU32(off), _f.ReadU32(off + 4));
    }

    private int RvaToOffset(uint rva)
    {
        if (rva < SizeOfHeaders) return (int)rva;
        foreach (var s in _sections)
        {
            long secRva = (long)(s.StartVa - ImageBase);
            // Translate within the section's RAW data only (FileSize = SizeOfRawData). An RVA in a section's
            // virtual-only tail (VirtualSize > raw size) has no file bytes; mapping it via EndVa would fold
            // it into the next section's raw data. Bound the result like VaToOffset does.
            if (rva >= secRva && rva < secRva + s.FileSize)
            {
                long off = (rva - secRva) + s.FileOffset;
                return off >= 0 && off < _f.Length ? (int)off : -1;
            }
        }
        return -1;
    }

    private List<Section> ReadSections()
    {
        var list = new List<Section>(NumberOfSections);
        for (int i = 0; i < NumberOfSections; i++)
        {
            int h = SectionTableOffset + i * 40;
            var raw = _f.ReadBytes(h, 8);
            int len = Array.IndexOf(raw, (byte)0);
            string name = Encoding.ASCII.GetString(raw, 0, len < 0 ? 8 : len);
            uint vsize = _f.ReadU32(h + 8);
            uint vaddr = _f.ReadU32(h + 12);
            uint rawSize = _f.ReadU32(h + 16);
            uint rawPtr = _f.ReadU32(h + 20);
            uint chars = _f.ReadU32(h + 36);
            list.Add(new Section
            {
                Name = name,
                StartVa = ImageBase + vaddr,
                VirtualSize = vsize,
                FileOffset = (int)rawPtr,
                FileSize = (int)rawSize,
                IsExecutable = (chars & 0x20000000) != 0 || (chars & 0x00000020) != 0,
                IsReadable = (chars & 0x40000000) != 0,
                IsWritable = (chars & 0x80000000) != 0,
            });
        }
        return list;
    }

    // ---- imports (standard + delay) ----
    private void ParseImports()
    {
        var (dirRva, _) = DataDir(1); // Import
        ParseImportDescriptors(dirRva, descSize: 20, delay: false);
        var (delayRva, _) = DataDir(13); // DelayImport
        ParseImportDescriptors(delayRva, descSize: 32, delay: true);
    }

    private void ParseImportDescriptors(uint dirRva, int descSize, bool delay)
    {
        if (dirRva == 0) return;
        int descOff = RvaToOffset(dirRva);
        if (descOff < 0) return;

        for (int d = 0; ; d++)
        {
            int b = descOff + d * descSize;
            if (b + descSize > _f.Length) break;

            uint intRva, iatRva, nameRva;
            if (!delay)
            {
                uint oft = _f.ReadU32(b + 0);
                nameRva = _f.ReadU32(b + 12);
                iatRva = _f.ReadU32(b + 16);
                if (oft == 0 && iatRva == 0 && nameRva == 0) break;
                intRva = oft != 0 ? oft : iatRva;
            }
            else
            {
                uint attrs = _f.ReadU32(b + 0);
                uint nameField = _f.ReadU32(b + 4);
                uint iatField = _f.ReadU32(b + 12);
                uint intField = _f.ReadU32(b + 16);
                if (nameField == 0 && iatField == 0 && intField == 0) break;
                bool rvaBased = (attrs & 1) != 0;
                nameRva = rvaBased ? nameField : (uint)(nameField - ImageBase);
                iatRva = rvaBased ? iatField : (uint)(iatField - ImageBase);
                intRva = rvaBased ? intField : (uint)(intField - ImageBase);
            }

            string dll = nameRva != 0 ? _f.ReadAsciiZ(RvaToOffset(nameRva)) : "?";
            ReadThunks(dll, intRva, iatRva);
        }
    }

    private void ReadThunks(string dll, uint nameThunkRva, uint iatRva)
    {
        int intOff = RvaToOffset(nameThunkRva);
        if (intOff < 0) return;
        int ptr = PointerSize;
        ulong ordinalFlag = Is64Bit ? 0x8000_0000_0000_0000UL : 0x8000_0000UL;

        for (int i = 0; ; i++)
        {
            int thunkOff = intOff + i * ptr;
            if (thunkOff + ptr > _f.Length) break;
            ulong entry = Is64Bit ? _f.ReadU64(thunkOff) : _f.ReadU32(thunkOff);
            if (entry == 0) break;

            ulong iatVa = ImageBase + iatRva + (ulong)(i * ptr);
            string fn;
            if ((entry & ordinalFlag) != 0)
                fn = $"Ordinal_{entry & 0xFFFF}";
            else
            {
                int byNameOff = RvaToOffset((uint)entry);
                fn = byNameOff >= 0 ? _f.ReadAsciiZ(byNameOff + 2) : $"imp_{entry:X}";
                if (string.IsNullOrEmpty(fn)) fn = $"imp_{entry:X}";
            }

            var imp = new ImportEntry(dll, fn, iatVa);
            _imports.Add(imp);
            _importsByIat[iatVa] = imp;
            _symbols.Add(new NamedSymbol(iatVa, fn, NamedSymbolKind.Import));
        }
    }

    // ---- exports ----
    private void ParseExports()
    {
        var (dirRva, dirSize) = DataDir(0); // Export
        if (dirRva == 0) return;
        int dir = RvaToOffset(dirRva);
        if (dir < 0) return;

        uint ordinalBase = _f.ReadU32(dir + 0x10);
        uint numFuncs = _f.ReadU32(dir + 0x14);
        uint numNames = _f.ReadU32(dir + 0x18);
        int eat = RvaToOffset(_f.ReadU32(dir + 0x1C));
        int nameTbl = RvaToOffset(_f.ReadU32(dir + 0x20));
        int ordTbl = RvaToOffset(_f.ReadU32(dir + 0x24));
        if (eat < 0 || nameTbl < 0 || ordTbl < 0) return;

        uint exportLo = dirRva, exportHi = dirRva + dirSize;
        for (uint i = 0; i < numNames && i < 0x10000; i++)
        {
            int nameRvaOff = nameTbl + (int)i * 4;
            uint nameRva = _f.ReadU32(nameRvaOff);
            ushort ord = _f.ReadU16(ordTbl + (int)i * 2);
            if (ord >= numFuncs) continue;
            uint funcRva = _f.ReadU32(eat + ord * 4);
            if (funcRva == 0) continue;
            if (funcRva >= exportLo && funcRva < exportHi) continue; // forwarder, not code

            string name = _f.ReadAsciiZ(RvaToOffset(nameRva));
            if (name.Length == 0) name = $"export_{ordinalBase + ord}";
            _symbols.Add(new NamedSymbol(ImageBase + funcRva, name, NamedSymbolKind.Export));
        }
    }

    // ---- exception directory (.pdata RUNTIME_FUNCTION table, x64) ----
    private void ParseExceptions()
    {
        var (rva, size) = DataDir(3); // Exception
        if (rva == 0 || size == 0) return;
        int off = RvaToOffset(rva);
        if (off < 0) return;
        int count = (int)(size / 12); // sizeof(RUNTIME_FUNCTION) = 12 (BeginAddress, EndAddress, UnwindInfo)
        for (int i = 0; i < count && i < 4_000_000; i++)
        {
            uint begin = _f.ReadU32(off + i * 12);
            if (begin != 0) _runtimeFunctions.Add(ImageBase + begin);
        }
    }

    private void Validate()
    {
        if (_f.Length < 0x40 || _f.ReadByte(0) != (byte)'M' || _f.ReadByte(1) != (byte)'Z')
            throw new BinaryFormatException("Not a valid MZ/DOS image.");
        if (_peHeader <= 0 || _peHeader + 0x100 > _f.Length)
            throw new BinaryFormatException("Invalid PE header offset.");
        if (_f.ReadU32(_peHeader) != 0x00004550)
            throw new BinaryFormatException("Missing 'PE\\0\\0' signature.");
        ushort magic = OptMagic;
        if (magic != 0x10B && magic != 0x20B)
            throw new BinaryFormatException($"Unsupported optional header magic 0x{magic:X}.");
    }
}

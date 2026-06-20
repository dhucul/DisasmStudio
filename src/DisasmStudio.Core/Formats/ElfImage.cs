using System.Text;

namespace DisasmStudio.Core.Formats;

/// <summary>
/// A parsed ELF (ELF32 / ELF64, little-endian — i.e. x86 / x86-64). Sections come from the
/// section header table; function names come from .symtab / .dynsym. VAs are the ELF virtual
/// addresses directly (ImageBase is 0), so a PIE/ET_DYN object is shown at its link-time VAs.
/// </summary>
public sealed class ElfImage : IBinaryImage, IDisposable
{
    private readonly MappedFile _f;
    private readonly bool _is64;

    public void Dispose() => _f.Dispose();   // release the memory-mapped file
    private readonly List<Section> _sections = [];
    private readonly List<NamedSymbol> _symbols = [];

    public string FilePath { get; }
    public BinaryFormat Format => BinaryFormat.Elf;
    public string FormatName => "ELF";
    public int Bitness => _is64 ? 64 : 32;
    public string ArchName { get; }
    public ulong ImageBase => 0;
    public ulong EntryVa { get; }
    public IReadOnlyList<Section> Sections => _sections;
    public IReadOnlyList<NamedSymbol> Symbols => _symbols;
    public IReadOnlyList<ImportEntry> Imports => [];
    public IReadOnlyList<ulong> FunctionStarts => [];   // ELF function starts come from .symtab/.dynsym (Symbols)
    public IReadOnlyDictionary<ulong, ImportEntry> ImportsByIatVa { get; } = new Dictionary<ulong, ImportEntry>();
    public int BackingLength => _f.Length;

    private ElfImage(MappedFile f, string path)
    {
        _f = f;
        FilePath = path;

        if (_f.Length < 0x40 || _f.ReadByte(0) != 0x7F || _f.ReadByte(1) != (byte)'E'
            || _f.ReadByte(2) != (byte)'L' || _f.ReadByte(3) != (byte)'F')
            throw new BinaryFormatException("Not a valid ELF image.");

        byte cls = _f.ReadByte(4);   // EI_CLASS: 1=32, 2=64
        byte data = _f.ReadByte(5);  // EI_DATA:  1=LE
        if (cls is not (1 or 2)) throw new BinaryFormatException("Unknown ELF class.");
        if (data != 1) throw new BinaryFormatException("Only little-endian ELF is supported.");
        _is64 = cls == 2;

        ushort machine = _f.ReadU16(0x12);
        ArchName = machine switch { 0x03 => "x86", 0x3E => "x64", 0xB7 => "arm64", _ => $"0x{machine:X}" };
        if (machine is not (0x03 or 0x3E))
            throw new BinaryFormatException($"Unsupported ELF machine 0x{machine:X} (only x86/x64).");

        EntryVa = _is64 ? _f.ReadU64(0x18) : _f.ReadU32(0x18);
        ReadSections();
        ReadSymbols();
    }

    public static ElfImage Load(string path) => new(MappedFile.Open(path), path);

    // Only allocated (SHF_ALLOC ⇒ IsReadable) sections are actually mapped into memory; non-alloc
    // sections (.symtab, .strtab, debug info) carry sh_addr=0 and must not affect VA↔offset mapping.
    private IEnumerable<Section> Allocated => _sections.Where(s => s.IsReadable);

    public ulong MinVa => Allocated.Any() ? Allocated.Min(s => s.StartVa) : 0;
    public ulong MaxVa => Allocated.Any() ? Allocated.Max(s => s.EndVa) : 0;

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
        foreach (var s in _sections) if (s.IsReadable && s.FileSize > 0 && s.ContainsVa(va)) return s;
        return null;
    }

    public int VaToOffset(ulong va)
    {
        var s = SectionAt(va);
        if (s is null) return -1;
        long off = (long)(va - s.StartVa) + s.FileOffset;
        return off >= 0 && off < _f.Length ? (int)off : -1;
    }

    public bool IsMappedVa(ulong va) => VaToOffset(va) >= 0;
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

    // ---- header parsing ----
    private ulong ShOff => _is64 ? _f.ReadU64(0x28) : _f.ReadU32(0x20);
    private ushort ShEntSize => _f.ReadU16(_is64 ? 0x3A : 0x2E);
    private ushort ShNum => _f.ReadU16(_is64 ? 0x3C : 0x30);
    private ushort ShStrNdx => _f.ReadU16(_is64 ? 0x3E : 0x32);

    private (uint type, ulong flags, ulong addr, ulong offset, ulong size, uint link, uint entsize, uint name) ReadShdr(int idx)
    {
        int b = (int)ShOff + idx * ShEntSize;
        if (_is64)
            return (_f.ReadU32(b + 4), _f.ReadU64(b + 8), _f.ReadU64(b + 16), _f.ReadU64(b + 24),
                    _f.ReadU64(b + 32), _f.ReadU32(b + 40), (uint)_f.ReadU64(b + 56), _f.ReadU32(b + 0));
        return (_f.ReadU32(b + 4), _f.ReadU32(b + 8), _f.ReadU32(b + 12), _f.ReadU32(b + 16),
                _f.ReadU32(b + 20), _f.ReadU32(b + 24), _f.ReadU32(b + 36), _f.ReadU32(b + 0));
    }

    private void ReadSections()
    {
        int count = ShNum;
        if (count == 0 || ShOff == 0) return;
        int strBase = ShStrNdx < count ? (int)ReadShdr(ShStrNdx).offset : -1;

        for (int i = 0; i < count; i++)
        {
            var sh = ReadShdr(i);
            string name = strBase >= 0 ? _f.ReadAsciiZ(strBase + (int)sh.name, 256) : $"sec{i}";
            bool nobits = sh.type == 8; // SHT_NOBITS (.bss)
            _sections.Add(new Section
            {
                Name = name.Length == 0 ? $"sec{i}" : name,
                StartVa = sh.addr,
                VirtualSize = sh.size,
                FileOffset = (int)sh.offset,
                FileSize = nobits ? 0 : (int)sh.size,
                IsExecutable = (sh.flags & 0x4) != 0,           // SHF_EXECINSTR
                IsReadable = (sh.flags & 0x2) != 0,             // SHF_ALLOC
                IsWritable = (sh.flags & 0x1) != 0,             // SHF_WRITE
            });
        }
    }

    private void ReadSymbols()
    {
        int count = ShNum;
        for (int i = 0; i < count; i++)
        {
            var sh = ReadShdr(i);
            if (sh.type is not (2 or 11)) continue; // SHT_SYMTAB / SHT_DYNSYM
            if (sh.link >= count) continue;
            int strBase = (int)ReadShdr((int)sh.link).offset;
            int entSize = sh.entsize > 0 ? (int)sh.entsize : (_is64 ? 24 : 16);
            int n = entSize > 0 ? (int)(sh.size / (ulong)entSize) : 0;

            for (int k = 0; k < n && k < 500_000; k++)
            {
                int e = (int)sh.offset + k * entSize;
                uint stName; ulong stValue; byte stInfo;
                if (_is64) { stName = _f.ReadU32(e + 0); stInfo = _f.ReadByte(e + 4); stValue = _f.ReadU64(e + 8); }
                else { stName = _f.ReadU32(e + 0); stValue = _f.ReadU32(e + 4); stInfo = _f.ReadByte(e + 12); }

                int type = stInfo & 0xF; // STT_FUNC == 2
                if (type != 2 || stValue == 0) continue;
                string name = _f.ReadAsciiZ(strBase + (int)stName, 256);
                if (name.Length == 0) continue;
                _symbols.Add(new NamedSymbol(stValue, name, NamedSymbolKind.Function));
            }
        }
    }
}

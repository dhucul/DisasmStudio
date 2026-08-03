using System.Text;

namespace DisasmStudio.Core.Formats;

/// <summary>
/// A parsed ELF (ELF32 / ELF64, little-endian). Sections come from the section header table, or — for a
/// stripped binary with none — are synthesised from the PT_LOAD program headers. Function/data names come
/// from .symtab / .dynsym; dynamic imports come from the PLT relocations (.rela.plt / .rel.plt). VAs are the
/// ELF virtual addresses directly (ImageBase is 0), so a PIE/ET_DYN object is shown at its link-time VAs.
/// x86/x64 decode through Iced; EM_ARM/EM_AARCH64 route to Capstone via <see cref="Arch"/>.
/// </summary>
public sealed class ElfImage : IBinaryImage, IDisposable
{
    private readonly MappedFile _f;
    private readonly bool _is64;
    private readonly Architecture _arch;

    public void Dispose() => _f.Dispose();   // release the memory-mapped file
    private readonly List<Section> _sections = [];
    private readonly List<NamedSymbol> _symbols = [];
    private readonly List<ImportEntry> _imports = [];
    private readonly Dictionary<ulong, ImportEntry> _importsByIat = [];
    private int _shStrBase = -1;             // .shstrtab file offset, or -1 when there are no section headers

    public string FilePath { get; }
    public BinaryFormat Format => BinaryFormat.Elf;
    public string FormatName => "ELF";
    public int Bitness => _is64 ? 64 : 32;
    public Architecture Arch => _arch;
    public string ArchName { get; }
    public ulong ImageBase => 0;
    public ulong EntryVa { get; }
    public bool IsDll => false;
    public IReadOnlyList<Section> Sections => _sections;
    public IReadOnlyList<NamedSymbol> Symbols => _symbols;
    public IReadOnlyList<ImportEntry> Imports => _imports;
    public Section? HeaderRegion => null;               // not surfaced for ELF (scope is the PE header)
    public ResourceTree? Resources => null;             // ELF has no .rsrc resource directory
    public IReadOnlyList<ulong> FunctionStarts => [];   // ELF function starts come from .symtab/.dynsym (Symbols)
    public IReadOnlyDictionary<ulong, ImportEntry> ImportsByIatVa => _importsByIat;
    public int BackingLength => _f.Length;

    private ElfImage(MappedFile f, string path)
    {
        _f = f;
        FilePath = path;

        if (_f.Length < 0x10 || _f.ReadByte(0) != 0x7F || _f.ReadByte(1) != (byte)'E'
            || _f.ReadByte(2) != (byte)'L' || _f.ReadByte(3) != (byte)'F')
            throw new BinaryFormatException("Not a valid ELF image.");

        byte cls = _f.ReadByte(4);   // EI_CLASS: 1=32, 2=64
        byte data = _f.ReadByte(5);  // EI_DATA:  1=LE
        if (cls is not (1 or 2)) throw new BinaryFormatException("Unknown ELF class.");
        if (data != 1) throw new BinaryFormatException("Only little-endian ELF is supported.");
        _is64 = cls == 2;
        int requiredHeader = _is64 ? 0x40 : 0x34;
        if (_f.Length < requiredHeader)
            throw new BinaryFormatException("Truncated ELF header.");
        ushort headerSize = _f.ReadU16(_is64 ? 0x34 : 0x28);
        if (headerSize < requiredHeader)
            throw new BinaryFormatException("Invalid ELF header size.");

        ushort machine = _f.ReadU16(0x12);   // e_machine: 0x03 x86, 0x3E x64, 0x28 ARM, 0xB7 AArch64
        (_arch, ArchName) = machine switch
        {
            0x03 => (Architecture.X86, "x86"),
            0x3E => (Architecture.X64, "x64"),
            0x28 => (Architecture.Arm, "arm"),
            0xB7 => (Architecture.Arm64, "arm64"),
            _ => throw new BinaryFormatException($"Unsupported ELF machine 0x{machine:X}."),
        };

        EntryVa = _is64 ? _f.ReadU64(0x18) : _f.ReadU32(0x18);
        ReadSections();
        if (_sections.Count == 0) ReadProgramHeaders();   // stripped: synthesise mapped regions from PT_LOAD
        try { ReadSymbols(); } catch { /* symbols are optional; malformed metadata must not block loading */ }
        try { ReadImports(); } catch { /* imports are best-effort; a malformed PLT must never block load */ }
    }

    public static ElfImage Load(string path)
    {
        var file = MappedFile.Open(path);
        try { return new ElfImage(file, path); }
        catch { file.Dispose(); throw; }
    }

    // Only allocated (SHF_ALLOC ⇒ IsReadable) sections are actually mapped into memory; non-alloc
    // sections (.symtab, .strtab, debug info) carry sh_addr=0 and must not affect VA↔offset mapping.
    private IEnumerable<Section> Allocated => _sections.Where(s => s.IsReadable);

    public ulong MinVa => Allocated.Any() ? Allocated.Min(s => s.StartVa) : 0;
    public ulong MaxVa => Allocated.Any() ? Allocated.Max(s => s.EndVa) : 0;

    public byte ReadByteAtOffset(int offset) => _f.ReadByte(offset);

    public void Patch(int offset, ReadOnlySpan<byte> bytes) => _f.Patch(offset, bytes);
    public bool PatchVa(ulong va, ReadOnlySpan<byte> bytes)
    {
        if (!TryFileSpan(va, bytes.Length, out int offset, out _)) return false;
        _f.Patch(offset, bytes);
        return true;
    }
    public void RevertPatch(int offset, int count) => _f.RevertPatch(offset, count);
    public bool IsPatchedAt(int offset) => _f.IsPatched(offset);
    public bool IsDirty => _f.IsDirty;
    public int PatchCount => _f.PatchCount;
    public IReadOnlyDictionary<int, byte> Patches => _f.Patches;
    public bool Undo() => _f.Undo();
    public bool CanUndo => _f.CanUndo;
    public void SavePatchedAs(string path) => _f.SaveAs(path);

    public Section? SectionAt(ulong va)
    {
        foreach (var s in _sections) if (s.IsReadable && s.FileSize > 0 && s.ContainsVa(va)) return s;
        return null;
    }

    private Section? FileSectionAt(ulong va)
    {
        foreach (var s in _sections)
            if (s.IsReadable && s.FileSize > 0 && va >= s.StartVa && va - s.StartVa < (ulong)s.FileSize)
                return s;
        return null;
    }

    private bool TryFileSpan(ulong va, int requested, out int offset, out int available)
    {
        offset = -1;
        available = 0;
        if (requested < 0) return false;
        var s = FileSectionAt(va);
        if (s is null) return false;
        int delta = (int)(va - s.StartVa);
        long fileOffset = (long)s.FileOffset + delta;
        if (fileOffset < 0 || fileOffset >= _f.Length) return false;
        offset = (int)fileOffset;
        available = Math.Min(s.FileSize - delta, _f.Length - offset);
        return requested <= available;
    }

    public int VaToOffset(ulong va)
    {
        return TryFileSpan(va, 1, out int offset, out _) ? offset : -1;
    }

    public bool IsMappedVa(ulong va) => VaToOffset(va) >= 0;
    public bool IsExecutableVa(ulong va) => SectionAt(va) is { IsExecutable: true };

    public byte[] ReadBytesAtVa(ulong va, int count)
    {
        if (count <= 0 || !TryFileSpan(va, 1, out int offset, out int available)) return [];
        return _f.ReadBytes(offset, Math.Min(count, available));
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

    private ulong PhOff => _is64 ? _f.ReadU64(0x20) : _f.ReadU32(0x1C);
    private ushort PhEntSize => _f.ReadU16(_is64 ? 0x36 : 0x2A);
    private ushort PhNum => _f.ReadU16(_is64 ? 0x38 : 0x2C);

    private int CheckedTableEntry(ulong tableOffset, ushort entrySize, int index, int requiredSize, int count)
    {
        if (index < 0 || index >= count || entrySize < requiredSize || tableOffset > (ulong)_f.Length)
            throw new BinaryFormatException("Invalid ELF table metadata.");
        ulong delta = checked((ulong)index * entrySize);
        if (delta > (ulong)_f.Length - tableOffset)
            throw new BinaryFormatException("ELF table exceeds the file.");
        ulong entry = tableOffset + delta;
        if ((ulong)requiredSize > (ulong)_f.Length - entry)
            throw new BinaryFormatException("Truncated ELF table entry.");
        return checked((int)entry);
    }

    private void ValidateTable(ulong tableOffset, ushort entrySize, int count, int requiredSize, string name)
    {
        if (count == 0) return;
        if (tableOffset == 0 || entrySize < requiredSize || tableOffset > (ulong)_f.Length)
            throw new BinaryFormatException($"Invalid ELF {name} table.");
        ulong bytes = checked((ulong)entrySize * (ulong)count);
        if (bytes > (ulong)_f.Length - tableOffset)
            throw new BinaryFormatException($"ELF {name} table exceeds the file.");
    }

    private (uint type, ulong flags, ulong addr, ulong offset, ulong size, uint link, uint info, ulong entsize, uint name) ReadShdr(int idx)
    {
        int b = CheckedTableEntry(ShOff, ShEntSize, idx, _is64 ? 64 : 40, ShNum);
        if (_is64)
            return (_f.ReadU32(b + 4), _f.ReadU64(b + 8), _f.ReadU64(b + 16), _f.ReadU64(b + 24),
                    _f.ReadU64(b + 32), _f.ReadU32(b + 40), _f.ReadU32(b + 44), _f.ReadU64(b + 56), _f.ReadU32(b + 0));
        return (_f.ReadU32(b + 4), _f.ReadU32(b + 8), _f.ReadU32(b + 12), _f.ReadU32(b + 16),
                _f.ReadU32(b + 20), _f.ReadU32(b + 24), _f.ReadU32(b + 28), _f.ReadU32(b + 36), _f.ReadU32(b + 0));
    }

    private string SectionName(int idx) => _shStrBase >= 0 ? _f.ReadAsciiZ(_shStrBase + (int)ReadShdr(idx).name, 256) : "";

    private int FindSection(string name)
    {
        int count = ShNum;
        for (int i = 0; i < count; i++) if (SectionName(i) == name) return i;
        return -1;
    }

    private void ReadSections()
    {
        int count = ShNum;
        if (count == 0 || ShOff == 0) return;
        ValidateTable(ShOff, ShEntSize, count, _is64 ? 64 : 40, "section-header");
        // SHN_UNDEF (0) is a valid declaration that this ELF has no section-name string table.
        if (ShStrNdx != 0 && ShStrNdx < count)
        {
            var names = ReadShdr(ShStrNdx);
            if (names.type != 3 || names.offset > (ulong)_f.Length ||
                names.size > (ulong)_f.Length - names.offset || names.offset > int.MaxValue)
                throw new BinaryFormatException("Invalid ELF section-name string table.");
            _shStrBase = (int)names.offset;
        }

        for (int i = 0; i < count; i++)
        {
            var sh = ReadShdr(i);
            if (sh.addr > ulong.MaxValue - sh.size)
                throw new BinaryFormatException($"ELF section {i} has an overflowing virtual range.");
            string name = _shStrBase >= 0 ? _f.ReadAsciiZ(_shStrBase + (int)sh.name, 256) : $"sec{i}";
            bool nobits = sh.type == 8; // SHT_NOBITS (.bss)
            int fileOffset = 0, fileSize = 0;
            if (!nobits)
            {
                if (sh.offset > (ulong)_f.Length || sh.size > (ulong)_f.Length - sh.offset ||
                    sh.offset > int.MaxValue || sh.size > int.MaxValue)
                    throw new BinaryFormatException($"ELF section {i} exceeds the file.");
                fileOffset = (int)sh.offset;
                fileSize = (int)sh.size;
            }
            _sections.Add(new Section
            {
                Name = name.Length == 0 ? $"sec{i}" : name,
                StartVa = sh.addr,
                VirtualSize = sh.size,
                FileOffset = fileOffset,
                FileSize = fileSize,
                IsExecutable = (sh.flags & 0x4) != 0,           // SHF_EXECINSTR
                IsReadable = (sh.flags & 0x2) != 0,             // SHF_ALLOC
                IsWritable = (sh.flags & 0x1) != 0,             // SHF_WRITE
            });
        }
    }

    // Fallback for stripped binaries with no section header table: synthesise one Section per PT_LOAD
    // segment so the loadable (and executable) regions are still mapped and disassemblable.
    private void ReadProgramHeaders()
    {
        int count = PhNum;
        if (count == 0 || PhOff == 0) return;
        int required = _is64 ? 56 : 32;
        ValidateTable(PhOff, PhEntSize, count, required, "program-header");
        int load = 0;
        for (int i = 0; i < count; i++)
        {
            int b = CheckedTableEntry(PhOff, PhEntSize, i, required, count);
            uint type = _f.ReadU32(b + 0);
            if (type != 1) continue; // PT_LOAD
            ulong off, vaddr, filesz, memsz; uint flags;
            if (_is64)
            {
                flags = _f.ReadU32(b + 4);
                off = _f.ReadU64(b + 8); vaddr = _f.ReadU64(b + 16);
                filesz = _f.ReadU64(b + 32); memsz = _f.ReadU64(b + 40);
            }
            else
            {
                off = _f.ReadU32(b + 4); vaddr = _f.ReadU32(b + 8);
                filesz = _f.ReadU32(b + 16); memsz = _f.ReadU32(b + 20); flags = _f.ReadU32(b + 24);
            }
            if (filesz > memsz || off > (ulong)_f.Length || filesz > (ulong)_f.Length - off ||
                off > int.MaxValue || filesz > int.MaxValue || vaddr > ulong.MaxValue - memsz)
                throw new BinaryFormatException($"ELF PT_LOAD entry {i} has an invalid range.");
            _sections.Add(new Section
            {
                Name = $"load{load++}",
                StartVa = vaddr,
                VirtualSize = memsz,
                FileOffset = (int)off,
                FileSize = (int)filesz,
                IsExecutable = (flags & 0x1) != 0,   // PF_X
                // Execute-only PT_LOAD segments are still mapped and must be readable by the analyzer.
                IsReadable = (flags & (0x4 | 0x1)) != 0,      // PF_R | PF_X
                IsWritable = (flags & 0x2) != 0,      // PF_W
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
            if (sh.entsize > int.MaxValue) continue;
            int entSize = sh.entsize > 0 ? (int)sh.entsize : (_is64 ? 24 : 16);
            int n = entSize > 0 ? (int)(sh.size / (ulong)entSize) : 0;

            for (int k = 0; k < n && k < 500_000 && _symbols.Count < 1_000_000; k++)
            {
                int e = (int)sh.offset + k * entSize;
                uint stName; ulong stValue; byte stInfo;
                if (_is64) { stName = _f.ReadU32(e + 0); stInfo = _f.ReadByte(e + 4); stValue = _f.ReadU64(e + 8); }
                else { stName = _f.ReadU32(e + 0); stValue = _f.ReadU32(e + 4); stInfo = _f.ReadByte(e + 12); }

                int type = stInfo & 0xF; // STT_FUNC == 2, STT_OBJECT == 1
                if (type is not (1 or 2) || stValue == 0) continue;
                string name = _f.ReadAsciiZ(strBase + (int)stName, 256);
                if (name.Length == 0) continue;
                var kind = type == 2 ? NamedSymbolKind.Function : NamedSymbolKind.Data;
                _symbols.Add(new NamedSymbol(stValue, name, kind));
            }
        }
    }

    // Dynamic imports: walk the PLT relocation table (.rela.plt / .rel.plt), naming each GOT slot with its
    // imported symbol (so indirect jmp [got] resolves like a PE IAT), and — on x86/x64 where the PLT layout is
    // well known — synthesising a "name@plt" label at each PLT stub so a direct call func@plt reads clearly.
    private void ReadImports()
    {
        int count = ShNum;
        if (count == 0) return;

        int relIdx = FindSection(".rela.plt");
        bool rela = true;
        if (relIdx < 0) { relIdx = FindSection(".rel.plt"); rela = false; }
        if (relIdx < 0) return;

        var rel = ReadShdr(relIdx);
        if (rel.link >= (uint)count) return;
        var dynsym = ReadShdr((int)rel.link);          // the linked symbol table (.dynsym)
        if (dynsym.link >= (uint)count) return;
        int dynstrBase = (int)ReadShdr((int)dynsym.link).offset;
        if (dynsym.entsize > int.MaxValue) return;
        int symEnt = dynsym.entsize > 0 ? (int)dynsym.entsize : (_is64 ? 24 : 16);

        // PLT stubs: prefer .plt.sec (present with IBT/CET, 1:1 with .rela.plt), else .plt (has a PLT0 resolver
        // entry at index 0, so stub i lives at (i+1) entries in). Only x86/x64 layouts are named here.
        bool synthStubs = _arch is Architecture.X86 or Architecture.X64;
        int pltSecIdx = FindSection(".plt.sec");
        int pltIdx = pltSecIdx >= 0 ? pltSecIdx : FindSection(".plt");
        Section? plt = synthStubs && pltIdx >= 0 && pltIdx < _sections.Count ? _sections[pltIdx] : null;
        bool hasPlt0 = pltSecIdx < 0;
        ulong pltEnt = plt is not null ? (ReadShdr(pltIdx).entsize > 0 ? ReadShdr(pltIdx).entsize : 16UL) : 16UL;

        // Elf64_Rela=24, Elf32_Rela=12, Elf64_Rel=16, Elf32_Rel=8 (only used when sh_entsize is 0).
        if (rel.entsize > int.MaxValue) return;
        int relEnt = rel.entsize > 0 ? (int)rel.entsize : (rela ? (_is64 ? 24 : 12) : (_is64 ? 16 : 8));
        int nrel = relEnt > 0 ? (int)(rel.size / (ulong)relEnt) : 0;

        for (int i = 0; i < nrel && i < 200_000; i++)
        {
            int e = (int)rel.offset + i * relEnt;
            ulong rOffset, rInfo;
            if (_is64) { rOffset = _f.ReadU64(e + 0); rInfo = _f.ReadU64(e + 8); }
            else { rOffset = _f.ReadU32(e + 0); rInfo = _f.ReadU32(e + 4); }
            uint symIdx = _is64 ? (uint)(rInfo >> 32) : (uint)(rInfo >> 8);

            int se = (int)dynsym.offset + (int)symIdx * symEnt;
            uint stName = _f.ReadU32(se + 0);
            string name = _f.ReadAsciiZ(dynstrBase + (int)stName, 256);
            if (name.Length == 0) continue;

            var entry = new ImportEntry("", name, rOffset);
            _imports.Add(entry);
            _importsByIat[rOffset] = entry;

            if (plt is not null)
            {
                ulong stubVa = plt.StartVa + (hasPlt0 ? (ulong)(i + 1) : (ulong)i) * pltEnt;
                _symbols.Add(new NamedSymbol(stubVa, name + "@plt", NamedSymbolKind.Import));
            }
        }
    }
}

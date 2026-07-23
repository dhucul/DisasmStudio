using System.Buffers.Binary;
using System.Text;

namespace DisasmStudio.Core.Formats;

/// <summary>
/// A parsed thin Mach-O (32/64-bit, little-endian: Intel and Apple-Silicon). Sections come from the
/// LC_SEGMENT(_64) load commands; names from LC_SYMTAB (nlist); function starts from LC_FUNCTION_STARTS; the
/// entry point from LC_MAIN. VAs are the link-time virtual addresses directly (dylibs link at 0, like an ELF
/// PIE). x86_64 decodes through Iced (full pipeline); arm64/arm route to Capstone via <see cref="Arch"/>.
/// Objective-C class/method metadata (if present) is parsed into <see cref="ObjC"/> and its method IMPs are
/// merged into <see cref="Symbols"/> so they name the listing.
///
/// A fat/universal file is opened at a single slice: <paramref name="sliceOffset"/> is the slice's byte offset
/// within the file, and every internal Mach-O offset is slice-relative, so it is added to <c>_base</c> at the
/// point of read (and baked into each <see cref="Section.FileOffset"/> so the VA↔offset math needs no change).
/// </summary>
public sealed class MachOImage : IBinaryImage, IDisposable
{
    // ---- Mach-O constants ----
    private const uint MH_MAGIC = 0xFEEDFACE, MH_MAGIC_64 = 0xFEEDFACF;
    internal const int CPU_TYPE_X86 = 7, CPU_TYPE_X86_64 = 0x01000007, CPU_TYPE_ARM = 12, CPU_TYPE_ARM64 = 0x0100000C;
    private const uint LC_SEGMENT = 0x1, LC_SYMTAB = 0x2, LC_LOAD_DYLIB = 0xC, LC_SEGMENT_64 = 0x19,
                       LC_FUNCTION_STARTS = 0x26, LC_MAIN = 0x80000028, LC_DYLD_CHAINED_FIXUPS = 0x80000034;

    private readonly MappedFile _f;
    private readonly int _base;              // this slice's byte offset within the file (0 for a thin file)
    private readonly bool _is64;
    private readonly Architecture _arch;

    public void Dispose() => _f.Dispose();

    private readonly List<Section> _sections = [];
    private readonly List<NamedSymbol> _symbols = [];
    private readonly List<ulong> _funcStarts = [];
    private readonly List<ImportEntry> _imports = [];
    private readonly Dictionary<ulong, ImportEntry> _importsByIat = [];
    private readonly List<string> _dylibs = [];                              // 1-based ordinal → name
    private readonly List<(ulong vmaddr, ulong fileoff, ulong filesize)> _segments = [];
    private Dictionary<ulong, ulong>? _rebaseMap;                            // slotVa → target VA (chained fixups)

    public string FilePath { get; }
    public BinaryFormat Format => BinaryFormat.MachO;
    public string FormatName => "Mach-O";
    public int Bitness { get; }
    public Architecture Arch => _arch;
    public string ArchName { get; }
    public ulong ImageBase { get; private set; }
    public ulong EntryVa { get; private set; }
    public bool IsDll { get; }
    public IReadOnlyList<Section> Sections => _sections;
    public IReadOnlyList<NamedSymbol> Symbols => _symbols;
    public IReadOnlyList<ImportEntry> Imports => _imports;
    public Section? HeaderRegion => null;
    public ResourceTree? Resources => null;
    public IReadOnlyList<ulong> FunctionStarts => _funcStarts;
    public IReadOnlyDictionary<ulong, ImportEntry> ImportsByIatVa => _importsByIat;
    public int BackingLength => _f.Length;
    public long SliceOffset => _base;

    /// <summary>Parsed Objective-C metadata (classes/methods), or null if the binary has none.</summary>
    public ObjCImage? ObjC { get; private set; }

    /// <summary>True when the binary carries LC_DYLD_CHAINED_FIXUPS (modern arm64 / arm64e).</summary>
    public bool HasChainedFixups => ChainedFixupsOffset >= 0;

    /// <summary>Number of chained-fixup rebase slots reconstructed (0 if none / not chained).</summary>
    public int RebaseCount => _rebaseMap?.Count ?? 0;

    // ---- accessors used by ObjCMetadata / ChainedFixups (same assembly) ----
    internal MappedFile File => _f;
    internal int Base => _base;
    internal bool Is64 => _is64;
    internal IReadOnlyList<string> Dylibs => _dylibs;
    internal IReadOnlyList<(ulong vmaddr, ulong fileoff, ulong filesize)> Segments => _segments;
    internal int ChainedFixupsOffset { get; private set; } = -1;   // slice-relative, or -1
    internal int ChainedFixupsSize { get; private set; }

    private MachOImage(MappedFile f, string path, long sliceOffset)
    {
        _f = f;
        FilePath = path;
        _base = checked((int)sliceOffset);

        if (_f.Length < _base + 0x1C) throw new BinaryFormatException("Truncated Mach-O.");
        uint magic = _f.ReadU32(_base);
        _is64 = magic == MH_MAGIC_64;
        if (magic is not (MH_MAGIC or MH_MAGIC_64))
            throw new BinaryFormatException("Not a thin little-endian Mach-O (byte-swapped/PPC not supported).");

        int cpuType = _f.ReadI32(_base + 4);
        uint filetype = _f.ReadU32(_base + 0x0C);
        uint ncmds = _f.ReadU32(_base + 0x10);
        uint sizeofcmds = _f.ReadU32(_base + 0x14);
        (_arch, Bitness, ArchName) = MapCpu(cpuType, _is64);
        IsDll = filetype is 6 or 8;                                 // MH_DYLIB / MH_BUNDLE

        int lc = _base + (_is64 ? 0x20 : 0x1C);
        int? entryFileOff = null;
        int fnStartsOff = -1, fnStartsSize = 0;

        ReadLoadCommands(lc, ncmds, (int)sizeofcmds, ref entryFileOff, ref fnStartsOff, ref fnStartsSize);

        if (fnStartsOff >= 0) ReadFunctionStarts(fnStartsOff, fnStartsSize);
        if (entryFileOff is int eo) EntryVa = OffsetToVa((ulong)eo);

        // Reconstruct chained-fixup rebases/binds (arm64e / modern arm64) so __objc_* pointers resolve, then
        // parse Objective-C. Both are best-effort: a malformed table must never block the image from loading.
        try { ChainedFixups.Apply(this); } catch { _rebaseMap = null; }
        try
        {
            ObjC = ObjCMetadata.Parse(this);
            if (ObjC is not null) _symbols.AddRange(ObjC.MethodSymbols);
        }
        catch { ObjC = null; }
    }

    /// <summary>Load a thin Mach-O, or a fat/universal file auto-picking a preferred slice (x86_64 → arm64 →
    /// first). The WPF UI overrides this by presenting a slice chooser and calling <see cref="Load(string,long)"/>.</summary>
    public static MachOImage Load(string path)
    {
        if (MachOFat.TryList(path, out var slices) && slices.Count > 0)
        {
            var pick = slices.FirstOrDefault(s => s.CpuType == CPU_TYPE_X86_64);
            if (pick.Size == 0) pick = slices.FirstOrDefault(s => s.CpuType == CPU_TYPE_ARM64);
            if (pick.Size == 0) pick = slices[0];
            return Load(path, pick.Offset);
        }
        return Load(path, 0);
    }

    /// <summary>Load a specific slice of a Mach-O file (offset 0 for a thin file).</summary>
    public static MachOImage Load(string path, long sliceOffset) => new(MappedFile.Open(path), path, sliceOffset);

    internal static (Architecture arch, int bitness, string name) MapCpu(int cpuType, bool is64) => cpuType switch
    {
        CPU_TYPE_X86_64 => (Architecture.X64, 64, "x64"),
        CPU_TYPE_X86 => (Architecture.X86, 32, "x86"),
        CPU_TYPE_ARM64 => (Architecture.Arm64, 64, "arm64"),
        CPU_TYPE_ARM => (Architecture.Arm, 32, "arm"),
        _ => (is64 ? Architecture.X64 : Architecture.X86, is64 ? 64 : 32, $"cpu{cpuType:X}"),
    };

    internal static string CpuName(int cpuType) => cpuType switch
    {
        CPU_TYPE_X86 => "x86", CPU_TYPE_X86_64 => "x64", CPU_TYPE_ARM => "arm", CPU_TYPE_ARM64 => "arm64",
        _ => $"cpu{cpuType:X}",
    };

    // ---- load-command walk ----
    private void ReadLoadCommands(int lc, uint ncmds, int sizeofcmds, ref int? entryFileOff, ref int fnStartsOff, ref int fnStartsSize)
    {
        int p = lc;
        int end = lc + sizeofcmds;
        for (uint i = 0; i < ncmds && p + 8 <= _f.Length && p < end; i++)
        {
            uint cmd = _f.ReadU32(p);
            uint cmdsize = _f.ReadU32(p + 4);
            if (cmdsize < 8) break;   // malformed — avoid an infinite loop

            switch (cmd)
            {
                case LC_SEGMENT_64: ReadSegment(p, is64: true); break;
                case LC_SEGMENT: ReadSegment(p, is64: false); break;
                case LC_SYMTAB: ReadSymtab(p); break;
                case LC_LOAD_DYLIB: _dylibs.Add(ReadDylibName(p)); break;
                case LC_MAIN: entryFileOff = (int)_f.ReadU64(p + 0x08); break;
                case LC_FUNCTION_STARTS:
                    fnStartsOff = _base + (int)_f.ReadU32(p + 0x08);
                    fnStartsSize = (int)_f.ReadU32(p + 0x0C);
                    break;
                case LC_DYLD_CHAINED_FIXUPS:
                    ChainedFixupsOffset = _base + (int)_f.ReadU32(p + 0x08);
                    ChainedFixupsSize = (int)_f.ReadU32(p + 0x0C);
                    break;
            }
            p += (int)cmdsize;
        }
    }

    private void ReadSegment(int p, bool is64)
    {
        string segname = ReadFixedStr(p + 0x08, 16);
        ulong vmaddr, vmsize, fileoff, filesize; int initprot; uint nsects; int secBase, secSize;
        if (is64)
        {
            vmaddr = _f.ReadU64(p + 0x18); vmsize = _f.ReadU64(p + 0x20);
            fileoff = _f.ReadU64(p + 0x28); filesize = _f.ReadU64(p + 0x30);
            initprot = _f.ReadI32(p + 0x3C); nsects = _f.ReadU32(p + 0x40);
            secBase = p + 72; secSize = 80;
        }
        else
        {
            vmaddr = _f.ReadU32(p + 0x18); vmsize = _f.ReadU32(p + 0x1C);
            fileoff = _f.ReadU32(p + 0x20); filesize = _f.ReadU32(p + 0x24);
            initprot = _f.ReadI32(p + 0x2C); nsects = _f.ReadU32(p + 0x30);
            secBase = p + 56; secSize = 68;
        }

        if (segname != "__PAGEZERO")
            _segments.Add((vmaddr, fileoff, filesize));
        if (segname == "__TEXT") ImageBase = vmaddr;

        bool segReadable = (initprot & 0x1) != 0;   // VM_PROT_READ
        bool segWritable = (initprot & 0x2) != 0;   // VM_PROT_WRITE
        bool segExec = (initprot & 0x4) != 0;       // VM_PROT_EXECUTE

        for (uint s = 0; s < nsects && s < 4096; s++)
        {
            int sb = secBase + (int)s * secSize;
            string sectname = ReadFixedStr(sb + 0x00, 16);
            ulong addr, size; uint offset, flags;
            if (is64)
            {
                // section_64: addr@0x20 size@0x28 offset@0x30 align@0x34 reloff@0x38 nreloc@0x3C flags@0x40
                addr = _f.ReadU64(sb + 0x20); size = _f.ReadU64(sb + 0x28);
                offset = _f.ReadU32(sb + 0x30); flags = _f.ReadU32(sb + 0x40);
            }
            else
            {
                addr = _f.ReadU32(sb + 0x20); size = _f.ReadU32(sb + 0x24);
                offset = _f.ReadU32(sb + 0x28); flags = _f.ReadU32(sb + 0x38);
            }
            uint stype = flags & 0xFF;
            bool zerofill = stype is 0x1 or 0xC or 0x12;   // S_ZEROFILL / S_GB_ZEROFILL / S_THREAD_LOCAL_ZEROFILL
            // Prefer the section instruction-attributes; but some compilers leave them unset on __text, so fall
            // back to "in an executable segment and a known code section" (avoids sweeping __cstring/__const).
            bool isExec = (flags & 0x80000000) != 0 || (flags & 0x400) != 0   // S_ATTR_PURE/SOME_INSTRUCTIONS
                || (segExec && (sectname == "__text" || sectname.Contains("stub", StringComparison.Ordinal)));
            _sections.Add(new Section
            {
                Name = sectname.Length == 0 ? $"sect{_sections.Count}" : sectname,
                StartVa = addr,
                VirtualSize = size,
                FileOffset = (int)(_base + offset),
                FileSize = zerofill ? 0 : (int)size,
                IsExecutable = isExec,
                IsReadable = segReadable,
                IsWritable = segWritable,
            });
        }
    }

    private void ReadSymtab(int p)
    {
        uint symoff = _f.ReadU32(p + 0x08);
        uint nsyms = _f.ReadU32(p + 0x0C);
        uint stroff = _f.ReadU32(p + 0x10);
        int nlistSize = _is64 ? 16 : 12;
        int strBase = _base + (int)stroff;

        for (int i = 0; i < nsyms && i < 500_000; i++)
        {
            int e = _base + (int)symoff + i * nlistSize;
            uint nStrx = _f.ReadU32(e + 0);
            byte nType = _f.ReadByte(e + 4);
            ulong nValue = _is64 ? _f.ReadU64(e + 8) : _f.ReadU32(e + 8);

            if ((nType & 0xE0) != 0) continue;         // N_STAB debug symbol
            if ((nType & 0x0E) != 0x0E) continue;      // keep only N_SECT (defined in a section)
            if (nValue == 0) continue;
            string name = _f.ReadAsciiZ(strBase + (int)nStrx, 512);
            if (name.Length == 0) continue;
            if (name[0] == '_') name = name[1..];       // strip the C-symbol leading underscore
            var kind = (nType & 0x01) != 0 ? NamedSymbolKind.Export : NamedSymbolKind.Function;
            _symbols.Add(new NamedSymbol(nValue, name, kind));
        }
    }

    private string ReadDylibName(int p)
    {
        // dylib_command: cmd, cmdsize, dylib{ name(lc_str offset)@0x08, ... }
        uint nameOff = _f.ReadU32(p + 0x08);
        uint cmdsize = _f.ReadU32(p + 4);
        int start = p + (int)nameOff;
        int max = p + (int)cmdsize - start;
        string full = max > 0 ? _f.ReadAsciiZ(start, max) : "";
        int slash = full.LastIndexOf('/');
        return slash >= 0 ? full[(slash + 1)..] : full;   // leaf name (e.g. "libSystem.B.dylib")
    }

    private void ReadFunctionStarts(int off, int size)
    {
        ulong addr = ImageBase;
        int p = off, end = off + size;
        while (p < end)
        {
            (ulong delta, int len) = ReadUleb(p, end);
            if (len == 0 || delta == 0) break;
            p += len;
            addr += delta;
            if (_funcStarts.Count < 500_000) _funcStarts.Add(addr);
        }
    }

    private (ulong value, int len) ReadUleb(int p, int end)
    {
        ulong result = 0; int shift = 0, len = 0;
        while (p + len < end && len < 10)
        {
            byte b = _f.ReadByte(p + len);
            result |= (ulong)(b & 0x7F) << shift;
            len++;
            if ((b & 0x80) == 0) return (result, len);
            shift += 7;
        }
        return (result, 0);   // truncated
    }

    // Map a slice-relative file offset to a VA using the segment table (LC_MAIN entryoff is a file offset).
    private ulong OffsetToVa(ulong sliceOff)
    {
        foreach (var (vmaddr, fileoff, filesize) in _segments)
            if (sliceOff >= fileoff && sliceOff < fileoff + filesize)
                return vmaddr + (sliceOff - fileoff);
        return ImageBase + sliceOff;   // fall back (entry usually lands in __TEXT which maps fileoff 0 → base)
    }

    private string ReadFixedStr(int off, int len)
    {
        var b = _f.ReadBytes(off, len);
        int z = Array.IndexOf(b, (byte)0);
        if (z < 0) z = b.Length;
        return Encoding.ASCII.GetString(b, 0, z);
    }

    // ---- helpers for ObjCMetadata ----
    internal Section? FindSectionByName(string name)
    {
        foreach (var s in _sections) if (s.Name == name) return s;
        return null;
    }

    internal string ReadCStrAtVa(ulong va, int max = 512)
    {
        int off = VaToOffset(va);
        return off < 0 ? "" : _f.ReadAsciiZ(off, max);
    }

    internal ulong ReadU64AtVa(ulong va)
    {
        int off = VaToOffset(va);
        return off < 0 ? 0 : _f.ReadU64(off);
    }

    internal uint ReadU32AtVa(ulong va)
    {
        int off = VaToOffset(va);
        return off < 0 ? 0 : _f.ReadU32(off);
    }

    internal int ReadI32AtVa(ulong va)
    {
        int off = VaToOffset(va);
        return off < 0 ? 0 : _f.ReadI32(off);
    }

    internal void SetRebaseMap(Dictionary<ulong, ulong>? map) => _rebaseMap = map;

    internal void AddImport(ulong slotVa, string name)
    {
        var entry = new ImportEntry("", name, slotVa);
        _imports.Add(entry);
        _importsByIat[slotVa] = entry;
    }

    /// <summary>Resolve a pointer stored in the file (in an __objc_* struct) to a usable VA. Consults the
    /// chained-fixups rebase map first; falls back to treating the raw value as a link-time VA (classic
    /// non-chained rebases already applied on disk), then to an image-base-relative heuristic; else 0 (skip).</summary>
    internal ulong ResolvePtr(ulong raw, ulong slotVa)
    {
        if (_rebaseMap is not null && _rebaseMap.TryGetValue(slotVa, out var t)) return t;
        if (raw != 0 && IsMappedVa(raw)) return raw;
        ulong guess = ImageBase + (raw & 0x0007_FFFF_FFFF_FFFF);   // DYLD_CHAINED_PTR_64 rebase target (51-bit)
        return IsMappedVa(guess) ? guess : 0;
    }

    // ---- IBinaryImage VA math (mirrors ElfImage) ----
    private IEnumerable<Section> Mapped => _sections.Where(s => s.IsReadable && s.FileSize > 0);
    public ulong MinVa => Mapped.Any() ? Mapped.Min(s => s.StartVa) : 0;
    public ulong MaxVa => Mapped.Any() ? Mapped.Max(s => s.EndVa) : 0;

    public byte ReadByteAtOffset(int offset) => _f.ReadByte(offset);

    public void Patch(int offset, ReadOnlySpan<byte> bytes) => _f.Patch(offset, bytes);
    public bool PatchVa(ulong va, ReadOnlySpan<byte> bytes) { int o = VaToOffset(va); if (o < 0) return false; _f.Patch(o, bytes); return true; }
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
}

/// <summary>One architecture slice inside a fat/universal Mach-O.</summary>
public readonly record struct MachOSlice(int CpuType, long Offset, long Size, string ArchName);

/// <summary>Reads the (big-endian) fat/universal header, listing the architecture slices. Doubles as the
/// disambiguator for the FAT_MAGIC / Java <c>.class</c> collision: a real fat header has a sane slice count and
/// every slice lands inside the file.</summary>
public static class MachOFat
{
    private const uint FAT_MAGIC = 0xCAFEBABE, FAT_MAGIC_64 = 0xCAFEBABF;

    public static bool TryList(string path, out IReadOnlyList<MachOSlice> slices)
    {
        slices = [];
        try
        {
            using var fs = System.IO.File.OpenRead(path);
            long fileLen = fs.Length;
            Span<byte> head = stackalloc byte[8];
            if (fs.Read(head) < 8) return false;
            uint magic = BinaryPrimitives.ReadUInt32BigEndian(head);
            if (magic is not (FAT_MAGIC or FAT_MAGIC_64)) return false;
            bool is64 = magic == FAT_MAGIC_64;
            uint nfat = BinaryPrimitives.ReadUInt32BigEndian(head[4..]);
            if (nfat is 0 or > 64) return false;              // Java .class / not a real fat

            int entSize = is64 ? 32 : 20;
            var buf = new byte[entSize];
            var list = new List<MachOSlice>();
            fs.Position = 8;
            for (int i = 0; i < nfat; i++)
            {
                if (fs.Read(buf, 0, entSize) < entSize) return false;
                int cpuType = BinaryPrimitives.ReadInt32BigEndian(buf);
                long off, size;
                if (is64)
                {
                    off = (long)BinaryPrimitives.ReadUInt64BigEndian(buf.AsSpan(8));
                    size = (long)BinaryPrimitives.ReadUInt64BigEndian(buf.AsSpan(16));
                }
                else
                {
                    off = BinaryPrimitives.ReadUInt32BigEndian(buf.AsSpan(8));
                    size = BinaryPrimitives.ReadUInt32BigEndian(buf.AsSpan(12));
                }
                if (off < 8 || size <= 0 || off + size > fileLen) return false;   // out of bounds → not fat
                list.Add(new MachOSlice(cpuType, off, size, MachOImage.CpuName(cpuType)));
            }
            slices = list;
            return list.Count > 0;
        }
        catch { return false; }
    }
}

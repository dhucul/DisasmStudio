namespace DisasmStudio.Core.Formats;

/// <summary>
/// Walks a Mach-O's <c>LC_DYLD_CHAINED_FIXUPS</c> blob and applies its rebases/binds. Modern arm64(e) dylibs
/// store the pointers inside <c>__objc_*</c> (and everywhere else) as packed chain entries that dyld rewrites at
/// load time, so on disk they are NOT usable VAs — this reconstructs them: a rebase slot → its target VA (fed to
/// <see cref="MachOImage.ResolvePtr"/>), a bind slot → an imported symbol (fed to <see cref="MachOImage.AddImport"/>).
///
/// Handles the 64-bit formats (DYLD_CHAINED_PTR_64 / _64_OFFSET) and the arm64e family (plain + auth, userland).
/// For a dylib (ImageBase 0) the "unslid target" and "image-base-relative offset" encodings coincide, so a single
/// <c>ImageBase + target</c> formula is used; auth pointers contribute only their runtime offset (the signing
/// diversity/key is irrelevant to static analysis). Anything unrecognised is skipped so a parse gap degrades
/// gracefully rather than corrupting the image.
/// </summary>
internal static class ChainedFixups
{
    private const ushort DYLD_CHAINED_PTR_START_NONE = 0xFFFF;      // page has no fixups
    private const ushort DYLD_CHAINED_PTR_START_MULTIPLE = 0x8000;  // page_start[]: low 15 bits index the overflow list
    private const ushort DYLD_CHAINED_PTR_START_LAST = 0x8000;      // overflow list: last chain-start for the page

    public static void Apply(MachOImage image)
    {
        int blob = image.ChainedFixupsOffset;
        if (blob < 0 || image.ChainedFixupsSize < 0x1C) return;
        var f = image.File;

        // dyld_chained_fixups_header
        uint startsOffset = f.ReadU32(blob + 4);
        uint importsOffset = f.ReadU32(blob + 8);
        uint symbolsOffset = f.ReadU32(blob + 12);
        uint importsCount = f.ReadU32(blob + 16);
        uint importsFormat = f.ReadU32(blob + 20);

        var imports = new ImportTable(f, blob + (int)importsOffset, importsCount, importsFormat, blob + (int)symbolsOffset);

        int startsBase = blob + (int)startsOffset;
        uint segCount = f.ReadU32(startsBase);
        var rebases = new Dictionary<ulong, ulong>();

        for (uint si = 0; si < segCount && si < 4096; si++)
        {
            uint segInfoOff = f.ReadU32(startsBase + 4 + (int)si * 4);
            if (segInfoOff == 0) continue;                          // segment has no fixups
            int seg = startsBase + (int)segInfoOff;

            // dyld_chained_starts_in_segment
            ushort pageSize = f.ReadU16(seg + 4);
            ushort ptrFormat = f.ReadU16(seg + 6);
            ulong segOffset = f.ReadU64(seg + 8);
            ushort pageCount = f.ReadU16(seg + 20);
            if (pageSize == 0) continue;

            for (int pi = 0; pi < pageCount; pi++)
            {
                ushort pageStart = f.ReadU16(seg + 22 + pi * 2);
                if (pageStart == DYLD_CHAINED_PTR_START_NONE) continue;
                ulong pageVa = image.ImageBase + segOffset + (ulong)pi * pageSize;

                if ((pageStart & DYLD_CHAINED_PTR_START_MULTIPLE) == 0)
                {
                    WalkChain(image, pageVa + pageStart, ptrFormat, rebases, imports);
                    continue;
                }
                // Multiple chains on this page: the low 15 bits index into the page_start[] array (past
                // page_count), a list of chain-start offsets running until an entry has the START_LAST bit set.
                int ovf = pageStart & 0x7FFF;
                for (int guard = 0; guard < 0x10000; guard++)
                {
                    ushort start = f.ReadU16(seg + 22 + ovf * 2);
                    WalkChain(image, pageVa + (ulong)(start & 0x7FFF), ptrFormat, rebases, imports);
                    if ((start & DYLD_CHAINED_PTR_START_LAST) != 0) break;
                    ovf++;
                }
            }
        }

        image.SetRebaseMap(rebases);
    }

    private static void WalkChain(MachOImage image, ulong va, ushort format, Dictionary<ulong, ulong> rebases, ImportTable imports)
    {
        bool arm64e = format is 1 or 7 or 9 or 10 or 12;   // ARM64E / _KERNEL / _USERLAND / _FIRMWARE / _USERLAND24
        // `next` is in stride-byte units: 8 for the arm64e userland formats (1/9/12), 4 for everything else
        // (the 64-bit formats 2/6 and the arm64e kernel/firmware formats 7/10).
        int stride = format is 1 or 9 or 12 ? 8 : 4;

        for (int guard = 0; guard < 5_000_000; guard++)
        {
            int off = image.VaToOffset(va);
            if (off < 0) break;
            ulong raw = image.File.ReadU64(off);
            int next;

            if (arm64e)
            {
                bool auth = (raw >> 63 & 1) != 0;
                bool bind = (raw >> 62 & 1) != 0;
                next = (int)(raw >> 51 & 0x7FF);
                if (bind)
                {
                    // USERLAND24 (12) uses a 24-bit ordinal for BOTH plain and authenticated binds; all other
                    // arm64e formats use 16 bits.
                    uint ordinal = format == 12 ? (uint)(raw & 0xFFFFFF) : (uint)(raw & 0xFFFF);
                    if (imports.TryName(ordinal, out var name)) image.AddImport(va, name);
                }
                else if (auth)
                {
                    rebases[va] = image.ImageBase + (raw & 0xFFFFFFFF);            // 32-bit runtime offset
                }
                else
                {
                    ulong target = raw & 0x7FF_FFFF_FFFF;                          // 43-bit
                    rebases[va] = image.ImageBase + target + ((raw >> 43 & 0xFF) << 56);
                }
            }
            else // DYLD_CHAINED_PTR_64 (2) / _64_OFFSET (6)
            {
                bool bind = (raw >> 63 & 1) != 0;
                next = (int)(raw >> 51 & 0xFFF);
                if (bind)
                {
                    uint ordinal = (uint)(raw & 0xFFFFFF);
                    if (imports.TryName(ordinal, out var name)) image.AddImport(va, name);
                }
                else
                {
                    ulong target = raw & 0xF_FFFF_FFFF;                            // 36-bit
                    rebases[va] = image.ImageBase + target + ((raw >> 36 & 0xFF) << 56);
                }
            }

            if (next == 0) break;
            va += (ulong)(next * stride);
        }
    }

    /// <summary>The chained-fixups imports table: ordinal → imported symbol name (from the blob's symbol pool).</summary>
    private sealed class ImportTable
    {
        private readonly MappedFile _f;
        private readonly int _base, _symbols, _entSize, _shift;
        private readonly uint _count, _format;

        public ImportTable(MappedFile f, int importsBase, uint count, uint format, int symbolsBase)
        {
            _f = f; _base = importsBase; _count = count; _format = format; _symbols = symbolsBase;
            (_entSize, _shift) = format switch
            {
                1 => (4, 9),    // dyld_chained_import          : lib_ordinal:8, weak:1, name_offset:23
                2 => (8, 9),    // dyld_chained_import_addend   : + int32 addend
                3 => (16, 32),  // dyld_chained_import_addend64 : lib_ordinal:16, weak:1, reserved:15, name_offset:32
                _ => (0, 0),
            };
        }

        public bool TryName(uint ordinal, out string name)
        {
            name = "";
            if (_entSize == 0 || ordinal >= _count) return false;
            int e = _base + (int)ordinal * _entSize;
            ulong nameOffset = _format == 3 ? _f.ReadU64(e) >> 32 : _f.ReadU32(e) >> _shift;
            name = _f.ReadAsciiZ(_symbols + (int)nameOffset, 512);
            if (name.Length > 0 && name[0] == '_') name = name[1..];
            return name.Length > 0;
        }
    }
}

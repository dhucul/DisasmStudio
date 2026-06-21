using System.Text;

namespace DisasmStudio.Core.Formats;

/// <summary>One labelled field of a parsed PE structure (header / .pdata / .reloc): where it is, how many
/// bytes, a human label shown as a comment (empty = no comment, just size it as a scalar), and an optional
/// <see cref="RefVa"/> the field points at (so the caller can append the target's symbol name).</summary>
public readonly record struct HeaderField(ulong Va, int Size, string Label, ulong RefVa = 0);

/// <summary>
/// Describes the PE header as an ordered list of labelled fields (DOS header, PE signature, COFF file
/// header, optional header, data directories, section table) so the linear view can render the folded-in
/// header as a structure — `dd … ; AddressOfEntryPoint` — instead of a meaningless wall of db bytes.
/// All reads go through <see cref="IBinaryImage.ReadBytesAtVa"/>; out-of-range reads degrade to 0.
/// </summary>
public static class PeHeaderLayout
{
    public static List<HeaderField> Describe(IBinaryImage img)
    {
        var f = new List<HeaderField>();
        if (img.Format != BinaryFormat.Pe) return f;

        ulong b = img.ImageBase;
        ushort U16(ulong va) { var x = img.ReadBytesAtVa(va, 2); return x.Length < 2 ? (ushort)0 : BitConverter.ToUInt16(x, 0); }
        uint U32(ulong va) { var x = img.ReadBytesAtVa(va, 4); return x.Length < 4 ? 0u : BitConverter.ToUInt32(x, 0); }

        // ---- DOS header ----
        f.Add(new(b + 0, 2, "e_magic 'MZ'"));
        uint peOff = U32(b + 0x3C);
        f.Add(new(b + 0x3C, 4, $"e_lfanew = 0x{peOff:X} → PE header"));

        ulong pe = b + peOff;
        if (img.ReadBytesAtVa(pe, 4) is not [(byte)'P', (byte)'E', 0, 0]) return f;   // not where we think — bail to db
        f.Add(new(pe, 4, "Signature 'PE\\0\\0'"));

        // ---- COFF file header ----
        ulong coff = pe + 4;
        f.Add(new(coff + 0, 2, $"Machine = {MachineName(U16(coff + 0))}"));
        ushort nsec = U16(coff + 2);
        f.Add(new(coff + 2, 2, $"NumberOfSections = {nsec}"));
        f.Add(new(coff + 4, 4, "TimeDateStamp"));
        f.Add(new(coff + 8, 4, "PointerToSymbolTable"));
        f.Add(new(coff + 12, 4, "NumberOfSymbols"));
        ushort optSize = U16(coff + 16);
        f.Add(new(coff + 16, 2, $"SizeOfOptionalHeader = 0x{optSize:X}"));
        f.Add(new(coff + 18, 2, $"Characteristics = 0x{U16(coff + 18):X4}"));

        // ---- optional header ----
        ulong opt = coff + 20;
        ushort magic = U16(opt + 0);
        bool plus = magic == 0x20B;   // PE32+ (64-bit)
        f.Add(new(opt + 0, 2, $"Magic = {(plus ? "PE32+" : magic == 0x10B ? "PE32" : $"0x{magic:X}")}"));
        f.Add(new(opt + 2, 1, "MajorLinkerVersion"));
        f.Add(new(opt + 3, 1, "MinorLinkerVersion"));
        f.Add(new(opt + 4, 4, "SizeOfCode"));
        f.Add(new(opt + 8, 4, "SizeOfInitializedData"));
        f.Add(new(opt + 12, 4, "SizeOfUninitializedData"));
        f.Add(new(opt + 16, 4, $"AddressOfEntryPoint = 0x{U32(opt + 16):X}"));
        f.Add(new(opt + 20, 4, "BaseOfCode"));
        if (plus)
            f.Add(new(opt + 24, 8, "ImageBase"));
        else { f.Add(new(opt + 24, 4, "BaseOfData")); f.Add(new(opt + 28, 4, "ImageBase")); }
        f.Add(new(opt + 32, 4, "SectionAlignment"));
        f.Add(new(opt + 36, 4, "FileAlignment"));
        f.Add(new(opt + 40, 2, "MajorOperatingSystemVersion"));
        f.Add(new(opt + 42, 2, "MinorOperatingSystemVersion"));
        f.Add(new(opt + 44, 2, "MajorImageVersion"));
        f.Add(new(opt + 46, 2, "MinorImageVersion"));
        f.Add(new(opt + 48, 2, "MajorSubsystemVersion"));
        f.Add(new(opt + 50, 2, "MinorSubsystemVersion"));
        f.Add(new(opt + 52, 4, "Win32VersionValue"));
        f.Add(new(opt + 56, 4, $"SizeOfImage = 0x{U32(opt + 56):X}"));
        f.Add(new(opt + 60, 4, $"SizeOfHeaders = 0x{U32(opt + 60):X}"));
        f.Add(new(opt + 64, 4, "CheckSum"));
        f.Add(new(opt + 68, 2, $"Subsystem = {SubsystemName(U16(opt + 68))}"));
        f.Add(new(opt + 70, 2, $"DllCharacteristics = 0x{U16(opt + 70):X4}"));
        // SizeOfStack/Heap reserve+commit: 4 fields, 8 bytes each (PE32+) or 4 bytes each (PE32).
        int wsz = plus ? 8 : 4;
        ulong w = opt + 72;
        foreach (var nm in new[] { "SizeOfStackReserve", "SizeOfStackCommit", "SizeOfHeapReserve", "SizeOfHeapCommit" })
        { f.Add(new(w, wsz, nm)); w += (ulong)wsz; }
        f.Add(new(w, 4, "LoaderFlags")); w += 4;
        uint numRva = U32(w);
        f.Add(new(w, 4, $"NumberOfRvaAndSizes = {numRva}")); w += 4;

        // ---- data directories ----
        for (uint i = 0; i < numRva && i < 16; i++)
        {
            f.Add(new(w + i * 8, 4, $"DataDir[{DirName(i)}].RVA"));
            f.Add(new(w + i * 8 + 4, 4, $"DataDir[{DirName(i)}].Size"));
        }

        // ---- section table ----
        ulong sectTbl = opt + optSize;
        for (int i = 0; i < nsec && i < 96; i++)
        {
            ulong s = sectTbl + (ulong)(i * 40);
            string sname = Encoding.ASCII.GetString(img.ReadBytesAtVa(s, 8)).TrimEnd('\0', ' ');
            f.Add(new(s + 0, 8, $"Section[{i}] '{sname}'"));
            f.Add(new(s + 8, 4, "  VirtualSize"));
            f.Add(new(s + 12, 4, "  VirtualAddress"));
            f.Add(new(s + 16, 4, "  SizeOfRawData"));
            f.Add(new(s + 20, 4, "  PointerToRawData"));
            f.Add(new(s + 24, 4, "  PointerToRelocations"));
            f.Add(new(s + 28, 4, "  PointerToLinenumbers"));
            f.Add(new(s + 32, 2, "  NumberOfRelocations"));
            f.Add(new(s + 34, 2, "  NumberOfLinenumbers"));
            f.Add(new(s + 36, 4, $"  Characteristics '{sname}'"));
        }
        return f;
    }

    /// <summary>Describe the x64 exception table (.pdata) as an array of RUNTIME_FUNCTION records — three
    /// RVAs each (Begin, End, UnwindInfo) — so each renders as labelled dd lines with the begin RVA's
    /// absolute VA (the caller resolves it to a function name). Empty for x86 (no .pdata records).</summary>
    public static List<HeaderField> DescribePdata(IBinaryImage img, Section sec)
    {
        var f = new List<HeaderField>();
        if (img.Format != BinaryFormat.Pe || img.Bitness != 64) return f;
        ulong b = sec.StartVa;
        int count = Math.Min(sec.FileSize / 12, 2_000_000);
        for (int i = 0; i < count; i++)
        {
            ulong e = b + (ulong)(i * 12);
            uint begin = RU32(img, e + 0), endA = RU32(img, e + 4);
            if (begin == 0 && endA == 0 && RU32(img, e + 8) == 0) continue;   // null terminator / padding
            ulong beginVa = img.ImageBase + begin;
            f.Add(new(e + 0, 4, $"RUNTIME_FUNCTION[{i}] begin → {beginVa:X}", beginVa));
            f.Add(new(e + 4, 4, $"  end → {img.ImageBase + endA:X}"));
            f.Add(new(e + 8, 4, "  unwindInfo"));
        }
        return f;
    }

    /// <summary>Describe the base-relocation table (.reloc) as a sequence of blocks: each block's PageRVA and
    /// BlockSize are labelled, and the WORD fixups are sized as dw (no per-entry comment — there can be tens
    /// of thousands). Bounded against a corrupt table.</summary>
    public static List<HeaderField> DescribeReloc(IBinaryImage img, Section sec)
    {
        var f = new List<HeaderField>();
        if (img.Format != BinaryFormat.Pe) return f;
        ulong b = sec.StartVa, end = b + (ulong)sec.FileSize;
        ulong p = b;
        int budget = 4_000_000;
        while (p + 8 <= end && budget > 0)
        {
            uint pageRva = RU32(img, p), blockSize = RU32(img, p + 4);
            if (blockSize < 8 || p + blockSize > end) break;            // malformed → stop
            f.Add(new(p + 0, 4, $"reloc block → page {img.ImageBase + pageRva:X}", img.ImageBase + pageRva));
            f.Add(new(p + 4, 4, $"  blockSize = 0x{blockSize:X}"));
            int entries = (int)((blockSize - 8) / 2);
            for (int i = 0; i < entries && budget-- > 0; i++)
                f.Add(new(p + 8 + (ulong)(i * 2), 2, ""));              // WORD fixup → dw, no comment
            p += blockSize;
        }
        return f;
    }

    /// <summary>Describe the import directory: per-DLL IMAGE_IMPORT_DESCRIPTOR records (labelled with the DLL
    /// name). The IAT slots themselves are already named via the import symbols, so this structures the table.</summary>
    public static List<HeaderField> DescribeImports(PeImage pe)
    {
        var f = new List<HeaderField>();
        var (rva, _) = pe.DataDirectory(1);
        if (rva == 0) return f;
        ulong b = pe.ImageBase;
        for (int d = 0; d < 8192; d++)
        {
            ulong desc = b + rva + (ulong)(d * 20);
            uint oft = RU32(pe, desc + 0), nameRva = RU32(pe, desc + 12), iatRva = RU32(pe, desc + 16);
            if (oft == 0 && nameRva == 0 && iatRva == 0) break;   // terminator
            string dll = nameRva != 0 ? ReadAsciiZ(pe, b + nameRva) : "?";
            f.Add(new(desc + 0, 4, $"ImportDescriptor[{dll}] OriginalFirstThunk"));
            f.Add(new(desc + 4, 4, "  TimeDateStamp"));
            f.Add(new(desc + 8, 4, "  ForwarderChain"));
            f.Add(new(desc + 12, 4, $"  Name → {dll}"));
            f.Add(new(desc + 16, 4, "  FirstThunk (IAT)"));
        }
        return f;
    }

    /// <summary>Describe the export directory: the IMAGE_EXPORT_DIRECTORY header plus the export address table
    /// (each entry's function RVA resolved to its absolute VA / name).</summary>
    public static List<HeaderField> DescribeExports(PeImage pe)
    {
        var f = new List<HeaderField>();
        var (rva, _) = pe.DataDirectory(0);
        if (rva == 0) return f;
        ulong b = pe.ImageBase, dir = b + rva;
        uint nameRva = RU32(pe, dir + 12), numFuncs = RU32(pe, dir + 20), numNames = RU32(pe, dir + 24), eatRva = RU32(pe, dir + 28);
        f.Add(new(dir + 0, 4, "ExportDir.Characteristics"));
        f.Add(new(dir + 4, 4, "  TimeDateStamp"));
        f.Add(new(dir + 8, 2, "  MajorVersion"));
        f.Add(new(dir + 10, 2, "  MinorVersion"));
        f.Add(new(dir + 12, 4, $"  Name → {(nameRva != 0 ? ReadAsciiZ(pe, b + nameRva) : "?")}"));
        f.Add(new(dir + 16, 4, "  OrdinalBase"));
        f.Add(new(dir + 20, 4, $"  NumberOfFunctions = {numFuncs}"));
        f.Add(new(dir + 24, 4, $"  NumberOfNames = {numNames}"));
        f.Add(new(dir + 28, 4, "  AddressOfFunctions (EAT)"));
        f.Add(new(dir + 32, 4, "  AddressOfNames"));
        f.Add(new(dir + 36, 4, "  AddressOfNameOrdinals"));
        for (uint i = 0; i < numFuncs && i < 200_000; i++)
        {
            ulong e = b + eatRva + i * 4;
            uint funcRva = RU32(pe, e);
            f.Add(new(e, 4, funcRva == 0 ? "" : $"EAT[{i}] → {b + funcRva:X}", funcRva == 0 ? 0 : b + funcRva));
        }
        return f;
    }

    /// <summary>Describe the TLS directory and, crucially, name the TLS callback array entries (they run before
    /// the entry point — a common RE blind spot).</summary>
    public static List<HeaderField> DescribeTls(PeImage pe)
    {
        var f = new List<HeaderField>();
        var (rva, _) = pe.DataDirectory(9);
        if (rva == 0) return f;
        ulong b = pe.ImageBase, dir = b + rva;
        bool plus = pe.Bitness == 64;
        int ptr = plus ? 8 : 4;
        f.Add(new(dir + 0, ptr, "TLS StartAddressOfRawData"));
        f.Add(new(dir + (ulong)ptr, ptr, "  EndAddressOfRawData"));
        f.Add(new(dir + (ulong)(2 * ptr), ptr, "  AddressOfIndex"));
        ulong cbField = dir + (ulong)(3 * ptr);
        ulong cbArr = ReadPtr(pe, cbField, plus);
        f.Add(new(cbField, ptr, $"  AddressOfCallBacks → {cbArr:X}"));
        f.Add(new(dir + (ulong)(4 * ptr), 4, "  SizeOfZeroFill"));
        f.Add(new(dir + (ulong)(4 * ptr) + 4, 4, "  Characteristics"));
        if (cbArr != 0)
            for (int i = 0; i < 4096; i++)
            {
                ulong ce = cbArr + (ulong)(i * ptr);
                ulong cb = ReadPtr(pe, ce, plus);
                if (cb == 0) break;
                f.Add(new(ce, ptr, $"TLS callback[{i}] → {cb:X}", cb));
            }
        return f;
    }

    /// <summary>Describe the debug directory entries (type, sizes, RVAs).</summary>
    public static List<HeaderField> DescribeDebug(PeImage pe)
    {
        var f = new List<HeaderField>();
        var (rva, size) = pe.DataDirectory(6);
        if (rva == 0) return f;
        ulong b = pe.ImageBase;
        int count = Math.Min((int)(size / 28), 64);   // sizeof(IMAGE_DEBUG_DIRECTORY) == 28
        for (int i = 0; i < count; i++)
        {
            ulong e = b + rva + (ulong)(i * 28);
            f.Add(new(e + 0, 4, $"DebugDir[{i}].Characteristics"));
            f.Add(new(e + 4, 4, "  TimeDateStamp"));
            f.Add(new(e + 8, 2, "  MajorVersion"));
            f.Add(new(e + 10, 2, "  MinorVersion"));
            f.Add(new(e + 12, 4, $"  Type = {DebugType(RU32(pe, e + 12))}"));
            f.Add(new(e + 16, 4, "  SizeOfData"));
            f.Add(new(e + 20, 4, "  AddressOfRawData"));
            f.Add(new(e + 24, 4, "  PointerToRawData"));
        }
        return f;
    }

    private static string DebugType(uint t) => t switch
    {
        2 => "CODEVIEW", 4 => "MISC", 6 => "EXCEPTION", 9 => "BORLAND", 12 => "VC_FEATURE",
        13 => "POGO", 14 => "ILTCG", 16 => "REPRO", _ => $"#{t}",
    };

    private static uint RU32(IBinaryImage img, ulong va)
    {
        var x = img.ReadBytesAtVa(va, 4);
        return x.Length < 4 ? 0u : BitConverter.ToUInt32(x, 0);
    }

    private static ulong ReadPtr(IBinaryImage img, ulong va, bool plus)
    {
        var x = img.ReadBytesAtVa(va, plus ? 8 : 4);
        if (plus) return x.Length < 8 ? 0 : BitConverter.ToUInt64(x, 0);
        return x.Length < 4 ? 0 : BitConverter.ToUInt32(x, 0);
    }

    private static string ReadAsciiZ(IBinaryImage img, ulong va, int max = 256)
    {
        var x = img.ReadBytesAtVa(va, max);
        int n = Array.IndexOf(x, (byte)0);
        return Encoding.ASCII.GetString(x, 0, n < 0 ? x.Length : n);
    }

    private static string MachineName(ushort m) => m switch
    {
        0x014C => "i386", 0x8664 => "AMD64", 0xAA64 => "ARM64", 0x01C4 => "ARMNT", 0x0200 => "IA64",
        _ => $"0x{m:X}",
    };

    private static string SubsystemName(ushort s) => s switch
    {
        1 => "NATIVE", 2 => "WINDOWS_GUI", 3 => "WINDOWS_CUI", 5 => "OS2_CUI", 7 => "POSIX_CUI",
        9 => "WINDOWS_CE_GUI", 10 => "EFI_APPLICATION", 14 => "XBOX", _ => $"0x{s:X}",
    };

    private static string DirName(uint i) => i switch
    {
        0 => "Export", 1 => "Import", 2 => "Resource", 3 => "Exception", 4 => "Security",
        5 => "BaseReloc", 6 => "Debug", 7 => "Architecture", 8 => "GlobalPtr", 9 => "TLS",
        10 => "LoadConfig", 11 => "BoundImport", 12 => "IAT", 13 => "DelayImport", 14 => "CLR",
        _ => $"#{i}",
    };
}

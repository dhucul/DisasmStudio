namespace DisasmStudio.Core.Unpacking;

/// <summary>
/// PE header field offsets and characteristic/data-directory constants, shared by the unpacker's
/// in-memory header reader (<see cref="PeView"/>) and writer (<see cref="PeBuilder"/>) so both agree
/// on the byte layout. Offsets named <c>Coff_*</c> are relative to the COFF file header; <c>Opt_*</c>
/// to the optional header; <c>Sec_*</c> to a 40-byte section header. Mirrors the offsets used by
/// <see cref="DisasmStudio.Core.Formats.PeImage"/>.
/// </summary>
public static class PeConstants
{
    public const int DosLfanewOffset = 0x3C;            // e_lfanew: file offset of the PE signature
    public const uint PeSignature = 0x0000_4550;        // "PE\0\0"
    public const ushort Pe32Magic = 0x10B;
    public const ushort Pe32PlusMagic = 0x20B;

    // From the PE signature offset.
    public const int FileHeaderFromSig = 4;             // COFF file header
    public const int OptHeaderFromSig = 24;             // optional header (sig 4 + COFF 20)

    // COFF file header (from its start).
    public const int Coff_Machine = 0;
    public const int Coff_NumberOfSections = 2;
    public const int Coff_SizeOfOptionalHeader = 16;
    public const int Coff_Characteristics = 18;

    public const ushort Machine_x86 = 0x014C;
    public const ushort Machine_x64 = 0x8664;
    public const ushort IMAGE_FILE_DLL = 0x2000;
    public const ushort IMAGE_FILE_RELOCS_STRIPPED = 0x0001;
    public const ushort IMAGE_FILE_EXECUTABLE_IMAGE = 0x0002;

    // Optional header (from its start).
    public const int Opt_Magic = 0;
    public const int Opt_AddressOfEntryPoint = 16;
    public const int Opt_BaseOfData32 = 24;             // PE32 only
    public const int Opt_ImageBase32 = 28;              // PE32: DWORD
    public const int Opt_ImageBase64 = 24;              // PE32+: QWORD
    public const int Opt_SectionAlignment = 32;
    public const int Opt_FileAlignment = 36;
    public const int Opt_SizeOfImage = 56;
    public const int Opt_SizeOfHeaders = 60;
    public const int Opt_CheckSum = 64;
    public const int Opt_Subsystem = 68;
    public const int Opt_DllCharacteristics = 70;

    // DllCharacteristics bits that a relocation-stripped, rebased dump must NOT advertise, or the loader
    // rejects the image (0xC000007B): ASLR + high-entropy ASLR, and Control-Flow-Guard metadata we don't rebuild.
    public const ushort IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA = 0x0020;
    public const ushort IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE = 0x0040;
    public const ushort IMAGE_DLLCHARACTERISTICS_GUARD_CF = 0x4000;
    public const int Opt_NumberOfRvaAndSizes32 = 92;
    public const int Opt_NumberOfRvaAndSizes64 = 108;
    public const int DataDirBase32 = 96;
    public const int DataDirBase64 = 112;

    public const int SectionHeaderSize = 40;
    public const int Sec_Name = 0;                      // 8 bytes, NUL-padded ASCII
    public const int Sec_VirtualSize = 8;
    public const int Sec_VirtualAddress = 12;
    public const int Sec_SizeOfRawData = 16;
    public const int Sec_PointerToRawData = 20;
    public const int Sec_Characteristics = 36;

    // Section characteristics.
    public const uint SCN_CNT_CODE = 0x0000_0020;
    public const uint SCN_CNT_INITIALIZED_DATA = 0x0000_0040;
    public const uint SCN_MEM_EXECUTE = 0x2000_0000;
    public const uint SCN_MEM_READ = 0x4000_0000;
    public const uint SCN_MEM_WRITE = 0x8000_0000;

    // Data-directory indices.
    public const int DirExport = 0;
    public const int DirImport = 1;
    public const int DirResource = 2;
    public const int DirException = 3;
    public const int DirBaseReloc = 5;
    public const int DirTls = 9;
    public const int DirLoadConfig = 10;
    public const int DirBoundImport = 11;
    public const int DirIat = 12;
    public const int DirDelayImport = 13;
    public const int DirComDescriptor = 14;             // CLR header — presence marks a .NET managed image

    public static int OptImageBaseOffset(bool is64) => is64 ? Opt_ImageBase64 : Opt_ImageBase32;
    public static int DataDirBaseOffset(bool is64) => is64 ? DataDirBase64 : DataDirBase32;
    public static int NumberOfRvaAndSizesOffset(bool is64) => is64 ? Opt_NumberOfRvaAndSizes64 : Opt_NumberOfRvaAndSizes32;

    public static uint Align(uint value, uint alignment) =>
        alignment == 0 ? value : (value + alignment - 1) & ~(alignment - 1);
}

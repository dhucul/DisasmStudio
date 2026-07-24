using System.Text;

namespace DisasmStudio.Core.Unpacking;

/// <summary>One section header read from an in-memory image.</summary>
public sealed record SectionHeader(
    string Name, uint VirtualAddress, uint VirtualSize, uint SizeOfRawData, uint PointerToRawData, uint Characteristics)
{
    public bool IsExecutable => (Characteristics & (PeConstants.SCN_MEM_EXECUTE | PeConstants.SCN_CNT_CODE)) != 0;
    public bool IsWritable => (Characteristics & PeConstants.SCN_MEM_WRITE) != 0;
}

/// <summary>
/// A read-only view over the PE headers of an image laid out <b>as it appears in memory</b> — i.e. the
/// backing buffer is RVA-indexed (<c>buffer[rva]</c> is the byte at <c>ImageBase + rva</c>). This is the
/// shape of a process dump produced by <c>DebuggerEngine.DumpImage</c>, where each section sits at its
/// <c>VirtualAddress</c>. Field offsets come from <see cref="PeConstants"/>, matching
/// <see cref="DisasmStudio.Core.Formats.PeImage"/>. All reads are bounds-checked and return 0 past the end.
/// </summary>
public sealed class PeView
{
    private readonly byte[] _b;

    public int PeOffset { get; }
    public bool Is64 { get; }
    public ushort Machine { get; }
    public ushort NumberOfSections { get; }
    public ushort SizeOfOptionalHeader { get; }
    public ushort Characteristics { get; }
    public uint EntryRva => U32(OptOffset + PeConstants.Opt_AddressOfEntryPoint);
    public ulong ImageBase { get; }
    public uint SectionAlignment { get; }
    public uint FileAlignment { get; }
    public uint SizeOfImage { get; }
    public uint SizeOfHeaders { get; }
    public uint NumberOfRvaAndSizes { get; }
    public IReadOnlyList<SectionHeader> Sections { get; }

    private int OptOffset => PeOffset + PeConstants.OptHeaderFromSig;
    private int FileHeaderOffset => PeOffset + PeConstants.FileHeaderFromSig;

    private PeView(byte[] buffer, int peOffset)
    {
        _b = buffer;
        PeOffset = peOffset;
        Machine = U16(FileHeaderOffset + PeConstants.Coff_Machine);
        NumberOfSections = U16(FileHeaderOffset + PeConstants.Coff_NumberOfSections);
        SizeOfOptionalHeader = U16(FileHeaderOffset + PeConstants.Coff_SizeOfOptionalHeader);
        Characteristics = U16(FileHeaderOffset + PeConstants.Coff_Characteristics);
        Is64 = U16(OptOffset + PeConstants.Opt_Magic) == PeConstants.Pe32PlusMagic;
        ImageBase = Is64 ? U64(OptOffset + PeConstants.Opt_ImageBase64) : U32(OptOffset + PeConstants.Opt_ImageBase32);
        SectionAlignment = U32(OptOffset + PeConstants.Opt_SectionAlignment);
        FileAlignment = U32(OptOffset + PeConstants.Opt_FileAlignment);
        SizeOfImage = U32(OptOffset + PeConstants.Opt_SizeOfImage);
        SizeOfHeaders = U32(OptOffset + PeConstants.Opt_SizeOfHeaders);
        NumberOfRvaAndSizes = U32(OptOffset + PeConstants.NumberOfRvaAndSizesOffset(Is64));

        int secBase = OptOffset + SizeOfOptionalHeader;
        var secs = new List<SectionHeader>(NumberOfSections);
        for (int i = 0; i < NumberOfSections; i++)
        {
            int h = secBase + i * PeConstants.SectionHeaderSize;
            if (h + PeConstants.SectionHeaderSize > _b.Length) break;
            secs.Add(new SectionHeader(
                ReadName(h + PeConstants.Sec_Name),
                U32(h + PeConstants.Sec_VirtualAddress),
                U32(h + PeConstants.Sec_VirtualSize),
                U32(h + PeConstants.Sec_SizeOfRawData),
                U32(h + PeConstants.Sec_PointerToRawData),
                U32(h + PeConstants.Sec_Characteristics)));
        }
        Sections = secs;
    }

    /// <summary>Parse the headers of an in-memory image buffer; false if the MZ/PE signatures are missing.</summary>
    public static bool TryParse(byte[] buffer, out PeView view)
    {
        view = null!;
        if (buffer.Length < 0x40 || buffer[0] != (byte)'M' || buffer[1] != (byte)'Z') return false;
        int pe = BitConverter.ToInt32(buffer, PeConstants.DosLfanewOffset);
        if (pe <= 0 || buffer.Length < 0x108 || pe > buffer.Length - 0x108) return false;
        if (BitConverter.ToUInt32(buffer, pe) != PeConstants.PeSignature) return false;
        ushort magic = BitConverter.ToUInt16(buffer, pe + PeConstants.OptHeaderFromSig + PeConstants.Opt_Magic);
        if (magic != PeConstants.Pe32Magic && magic != PeConstants.Pe32PlusMagic) return false;
        view = new PeView(buffer, pe);
        return true;
    }

    /// <summary>The (RVA, Size) of data directory <paramref name="index"/>, or (0,0) if absent.</summary>
    public (uint Rva, uint Size) DataDir(int index)
    {
        if ((uint)index >= NumberOfRvaAndSizes) return (0, 0);
        int off = OptOffset + PeConstants.DataDirBaseOffset(Is64) + index * 8;
        return (U32(off), U32(off + 4));
    }

    public SectionHeader? SectionContainingRva(uint rva)
    {
        foreach (var s in Sections)
        {
            uint size = Math.Max(s.VirtualSize, s.SizeOfRawData);
            if (rva >= s.VirtualAddress && rva < s.VirtualAddress + size) return s;
        }
        return null;
    }

    private string ReadName(int off)
    {
        int end = off;
        while (end < off + 8 && end < _b.Length && _b[end] != 0) end++;
        return Encoding.ASCII.GetString(_b, off, end - off);
    }

    public byte U8(int off) => (uint)off < (uint)_b.Length ? _b[off] : (byte)0;
    public ushort U16(int off) => off >= 0 && off + 2 <= _b.Length ? BitConverter.ToUInt16(_b, off) : (ushort)0;
    public uint U32(int off) => off >= 0 && off + 4 <= _b.Length ? BitConverter.ToUInt32(_b, off) : 0;
    public ulong U64(int off) => off >= 0 && off + 8 <= _b.Length ? BitConverter.ToUInt64(_b, off) : 0;
}

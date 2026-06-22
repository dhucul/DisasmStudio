using System.Text;

namespace DisasmStudio.Core.Unpacking;

/// <summary>
/// Serializes a clean, on-disk PE from a post-unpack memory image. The dump is written in <b>virtual
/// layout</b> — <c>FileAlignment = SectionAlignment</c> and every section's <c>PointerToRawData =
/// VirtualAddress</c> — so the file's raw bytes mirror the image and no RVA→offset translation is needed.
/// The entry point is corrected to the OEP, a fresh import directory (built by <see cref="ImportRebuilder"/>)
/// is appended as a new section, and base relocations are stripped (the dump is captured at the real load
/// base, so relocating it again would corrupt it).
/// </summary>
public static class PeBuilder
{
    /// <summary>Build the rebuilt PE bytes. <paramref name="imageBase"/> is the image's <b>actual</b> load base
    /// (the dump is captured there and its addresses are relocated to it), which is written into the optional
    /// header so the relocation-stripped output reloads consistently even when ASLR moved the image.
    /// <paramref name="imports"/> may be null/empty, in which case the original import directory is preserved
    /// and only the entry point + raw layout are fixed.</summary>
    public static byte[] Build(byte[] dumpImage, PeView view, uint oepRva, IatRebuildResult? imports, ulong imageBase, out string log)
    {
        var sb = new StringBuilder();
        bool is64 = view.Is64;
        uint sectionAlign = view.SectionAlignment == 0 ? 0x1000 : view.SectionAlignment;

        // New import section goes just past the current image.
        uint imageEnd = PeConstants.Align(Math.Max(view.SizeOfImage, LastSectionEnd(view)), sectionAlign);
        uint newSecRva = imageEnd;
        byte[] importBytes = [];
        uint descriptorSize = 0;
        bool addSection = imports is { Ok: true };
        if (addSection)
        {
            importBytes = ImportRebuilder.SerializeImportSection(imports!.Runs, newSecRva, is64, out descriptorSize);
            sb.Append($"Rebuilt import section: {imports.Runs.Count} descriptor(s), {imports.Resolved} imports, {importBytes.Length} bytes.\n");
        }
        uint newSecRaw = addSection ? PeConstants.Align((uint)importBytes.Length, sectionAlign) : 0;
        uint finalSize = addSection ? newSecRva + newSecRaw : imageEnd;

        var outBuf = new byte[finalSize];
        Array.Copy(dumpImage, 0, outBuf, 0, Math.Min(dumpImage.Length, (int)Math.Min(finalSize, (uint)int.MaxValue)));
        if (addSection) Array.Copy(importBytes, 0, outBuf, (int)newSecRva, importBytes.Length);

        int peOff = view.PeOffset;
        int fileHdr = peOff + PeConstants.FileHeaderFromSig;
        int optOff = peOff + PeConstants.OptHeaderFromSig;
        ushort sizeOfOpt = view.SizeOfOptionalHeader;
        int secBase = optOff + sizeOfOpt;
        int numSec = view.NumberOfSections;

        // Keep relocations only if the table fixes up a DATA section. A genuine table relocates data pointers
        // in .data/.rdata/.pdata; a packer (UPX) strips the original relocations and leaves only a tiny stub
        // table covering its executable unpack stub. Keeping that + ASLR would relocate the stub but corrupt
        // the real code it doesn't cover. (Size alone can't tell them apart — x64 is RIP-relative so a real
        // table is small and never touches the code section.) With no usable table we strip relocations and
        // pin the image to the dump load base, where its absolute addresses are already correct.
        var (relRva, relSize) = view.DataDir(PeConstants.DirBaseReloc);
        bool hasReloc = relRva != 0 && relSize != 0 && view.SectionContainingRva(relRva) is not null
            && RelocCoversData(dumpImage, view, relRva, relSize);

        // The dump's bytes were relocated by the loader to the runtime base (imageBase), but the dumped header
        // still records the preferred base (view.ImageBase). When ASLR moved the image, un-relocate the bytes
        // back to the preferred base and keep that base — producing an image byte-equivalent to the original,
        // which the OS can then ASLR-relocate normally. (No reloc table ⇒ the image never moved ⇒ nothing to do.)
        ulong preferredBase = view.ImageBase;
        long delta = (long)preferredBase - (long)imageBase;
        ulong finalBase = imageBase;
        if (hasReloc && delta != 0)
        {
            int applied = ApplyRelocations(outBuf, relRva, relSize, delta, is64);
            finalBase = preferredBase;
            sb.Append($"Un-relocated dump to preferred base {preferredBase:X} (delta {delta:X}, {applied} fixups).\n");
        }
        else if (hasReloc) finalBase = preferredBase;   // not moved; preferred == runtime

        // --- optional header fixups ---
        WriteU32(outBuf, optOff + PeConstants.Opt_AddressOfEntryPoint, oepRva);
        if (is64) BitConverter.GetBytes(finalBase).CopyTo(outBuf, optOff + PeConstants.Opt_ImageBase64);
        else WriteU32(outBuf, optOff + PeConstants.Opt_ImageBase32, (uint)finalBase);
        WriteU32(outBuf, optOff + PeConstants.Opt_FileAlignment, sectionAlign);
        WriteU32(outBuf, optOff + PeConstants.Opt_SizeOfImage, finalSize);
        WriteU32(outBuf, optOff + PeConstants.Opt_CheckSum, 0);   // stale after our edits; 0 means "skip"
        WriteU32(outBuf, optOff + PeConstants.NumberOfRvaAndSizesOffset(is64), 16);

        // Headers occupy the first SectionAlignment-aligned span; verify the (grown) section table fits.
        int headerEnd = secBase + (numSec + 1) * PeConstants.SectionHeaderSize;
        uint sizeOfHeaders = PeConstants.Align((uint)headerEnd, sectionAlign);
        uint firstSecRva = numSec > 0 ? view.Sections[0].VirtualAddress : sectionAlign;
        if (sizeOfHeaders > firstSecRva)
            sb.Append($"WARNING: header table ({headerEnd:X}) grows past first section RVA ({firstSecRva:X}); output may be malformed.\n");
        WriteU32(outBuf, optOff + PeConstants.Opt_SizeOfHeaders, sizeOfHeaders);

        // --- COFF header: one more section; strip relocations only if there are none to keep ---
        WriteU16(outBuf, fileHdr + PeConstants.Coff_NumberOfSections, (ushort)(numSec + (addSection ? 1 : 0)));
        ushort chars = (ushort)(view.Characteristics | PeConstants.IMAGE_FILE_EXECUTABLE_IMAGE);
        if (!hasReloc) chars |= PeConstants.IMAGE_FILE_RELOCS_STRIPPED;
        WriteU16(outBuf, fileHdr + PeConstants.Coff_Characteristics, chars);

        // --- DllCharacteristics: keep Control-Flow-Guard ON so the loader re-initialises the guard function
        // pointers (__guard_check/dispatch_icall_fptr) for the new module bases — clearing CFG would leave the
        // dumped (stale) ntdll guard pointers in place and crash the first guarded indirect call. Drop ASLR
        // only when relocations are gone (then a fixed base), and high-entropy ASLR for safety. ---
        ushort dllc = view.U16(optOff + PeConstants.Opt_DllCharacteristics);
        ushort mask = PeConstants.IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA;
        if (!hasReloc) mask |= PeConstants.IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;
        ushort cleared = (ushort)(dllc & ~mask);
        WriteU16(outBuf, optOff + PeConstants.Opt_DllCharacteristics, cleared);
        sb.Append($"Relocations {(hasReloc ? "kept" : "stripped")}; DllCharacteristics {dllc:X4} → {cleared:X4}.\n");

        // --- existing section headers: virtual == raw layout, IAT section made writable ---
        uint iatRva = imports?.IatStartRva ?? 0;
        for (int i = 0; i < numSec; i++)
        {
            int h = secBase + i * PeConstants.SectionHeaderSize;
            var s = view.Sections[i];
            uint rawSize = PeConstants.Align(Math.Max(s.VirtualSize, s.SizeOfRawData), sectionAlign);
            if (s.VirtualAddress + rawSize > finalSize) rawSize = finalSize > s.VirtualAddress ? finalSize - s.VirtualAddress : 0;
            WriteU32(outBuf, h + PeConstants.Sec_SizeOfRawData, rawSize);
            WriteU32(outBuf, h + PeConstants.Sec_PointerToRawData, s.VirtualAddress);
            if (iatRva != 0 && iatRva >= s.VirtualAddress && iatRva < s.VirtualAddress + Math.Max(s.VirtualSize, s.SizeOfRawData))
                WriteU32(outBuf, h + PeConstants.Sec_Characteristics, s.Characteristics | PeConstants.SCN_MEM_WRITE);
        }

        // --- data directories ---
        int dirBase = optOff + PeConstants.DataDirBaseOffset(is64);
        if (!hasReloc) WriteDir(outBuf, dirBase, PeConstants.DirBaseReloc, 0, 0);
        WriteDir(outBuf, dirBase, PeConstants.DirBoundImport, 0, 0);  // stale
        WriteDir(outBuf, dirBase, 4, 0, 0);                          // Certificate: the signature overlay isn't dumped
        if (addSection)
        {
            WriteDir(outBuf, dirBase, PeConstants.DirImport, newSecRva, descriptorSize);
            WriteDir(outBuf, dirBase, PeConstants.DirIat, imports!.IatStartRva, imports.IatSize);
        }

        // --- append the new section header ---
        if (addSection)
        {
            int h = secBase + numSec * PeConstants.SectionHeaderSize;
            WriteName(outBuf, h + PeConstants.Sec_Name, ".idata2");
            WriteU32(outBuf, h + PeConstants.Sec_VirtualSize, (uint)importBytes.Length);
            WriteU32(outBuf, h + PeConstants.Sec_VirtualAddress, newSecRva);
            WriteU32(outBuf, h + PeConstants.Sec_SizeOfRawData, newSecRaw);
            WriteU32(outBuf, h + PeConstants.Sec_PointerToRawData, newSecRva);
            WriteU32(outBuf, h + PeConstants.Sec_Characteristics,
                PeConstants.SCN_CNT_INITIALIZED_DATA | PeConstants.SCN_MEM_READ | PeConstants.SCN_MEM_WRITE);
        }

        // Reset the /GS security cookie to its default. A memory dump captures the cookie already randomized by
        // the running CRT; a freshly-loaded image must hold the default so the loader/CRT re-initializes it —
        // otherwise process creation rejects the image (STATUS_INVALID_IMAGE_FORMAT). Cookie VA is in the Load
        // Config directory (SecurityCookie field), relative to the base we wrote (finalBase).
        var (lcRva, lcSize) = view.DataDir(PeConstants.DirLoadConfig);
        if (lcRva != 0)
        {
            int scOff = is64 ? 0x58 : 0x3C, psz = is64 ? 8 : 4;
            if (scOff + psz <= lcSize && lcRva + scOff + psz <= finalSize)
            {
                ulong scVa = is64 ? BitConverter.ToUInt64(outBuf, (int)lcRva + scOff) : BitConverter.ToUInt32(outBuf, (int)lcRva + scOff);
                if (scVa > finalBase && scVa - finalBase + (ulong)psz <= finalSize)
                {
                    uint cookieRva = (uint)(scVa - finalBase);
                    ulong def = is64 ? 0x00002B992DDFA232UL : 0xBB40E64EUL;   // MSVC default /GS cookie
                    if (is64) BitConverter.GetBytes(def).CopyTo(outBuf, (int)cookieRva);
                    else BitConverter.GetBytes((uint)def).CopyTo(outBuf, (int)cookieRva);
                    sb.Append($"Reset /GS security cookie @ RVA {cookieRva:X} to default.\n");
                }
            }
        }

        // Neutralize Control-Flow-Guard indirect-call pointers. The unpacked code may contain CFG-guarded
        // calls (`call [__guard_check/dispatch_icall_fptr]`) even when a packer cleared the CFG header flag
        // (UPX does: C140→8140). With CFG off the loader won't fix those pointers, so the dumped (stale) ntdll
        // addresses crash the first guarded call. Point them at tiny stubs — check→`ret` (no-op validation),
        // dispatch→`jmp rax/eax` (transfer to the target) — appended to a made-executable import section. If
        // CFG stays on, the loader overwrites them with the real ntdll routines; either way the call works.
        if (addSection && lcRva != 0)
        {
            int chkOff = is64 ? 0x70 : 0x48, dspOff = is64 ? 0x78 : 0x4C, psz = is64 ? 8 : 4;
            uint stubBase = newSecRva + (uint)((importBytes.Length + 3) & ~3);
            uint retStub = stubBase, jmpStub = stubBase + 4;
            if (Math.Max(chkOff, dspOff) + psz <= lcSize && jmpStub + 2 <= newSecRva + newSecRaw)
            {
                outBuf[retStub] = 0xC3;                                   // ret
                outBuf[jmpStub] = 0xFF; outBuf[jmpStub + 1] = 0xE0;      // jmp rax / jmp eax
                int set = 0;
                void SetFptr(int off, uint stubRva)
                {
                    ulong varVa = is64 ? BitConverter.ToUInt64(outBuf, (int)lcRva + off) : BitConverter.ToUInt32(outBuf, (int)lcRva + off);
                    if (varVa <= finalBase || varVa - finalBase + (ulong)psz > finalSize) return;
                    uint varRva = (uint)(varVa - finalBase);
                    ulong stubVa = finalBase + stubRva;
                    if (is64) BitConverter.GetBytes(stubVa).CopyTo(outBuf, (int)varRva);
                    else BitConverter.GetBytes((uint)stubVa).CopyTo(outBuf, (int)varRva);
                    set++;
                }
                SetFptr(chkOff, retStub);
                SetFptr(dspOff, jmpStub);
                if (set > 0)
                {
                    // Extend the import section over the stubs and make it executable.
                    int hIdata = secBase + numSec * PeConstants.SectionHeaderSize;
                    WriteU32(outBuf, hIdata + PeConstants.Sec_VirtualSize, jmpStub + 2 - newSecRva);
                    WriteU32(outBuf, hIdata + PeConstants.Sec_Characteristics,
                        PeConstants.SCN_CNT_INITIALIZED_DATA | PeConstants.SCN_MEM_READ | PeConstants.SCN_MEM_WRITE | PeConstants.SCN_MEM_EXECUTE);
                    sb.Append($"Neutralized {set} CFG guard pointer(s).\n");
                }
            }
        }

        WriteU32(outBuf, optOff + PeConstants.Opt_AddressOfEntryPoint, oepRva);   // re-assert after any overlap
        sb.Append($"Output: {finalSize:X} bytes, entry RVA {oepRva:X}, {numSec + (addSection ? 1 : 0)} sections.\n");
        log = sb.ToString();
        return outBuf;
    }

    /// <summary>True if the relocation table fixes up at least one non-executable (data) section — the mark of
    /// a genuine table rather than a packer's stub-only remnant (which covers just its executable stub).</summary>
    private static bool RelocCoversData(byte[] image, PeView view, uint relRva, uint relSize)
    {
        int p = (int)relRva, end = (int)Math.Min(relRva + relSize, (uint)image.Length);
        while (p + 8 <= end)
        {
            uint page = BitConverter.ToUInt32(image, p);
            uint blockSize = BitConverter.ToUInt32(image, p + 4);
            if (blockSize < 8 || p + blockSize > end) break;
            var s = view.SectionContainingRva(page);
            if (s is { IsExecutable: false }) return true;
            p += (int)blockSize;
        }
        return false;
    }

    /// <summary>Apply base relocations to the (RVA-indexed) image buffer, adding <paramref name="delta"/> to
    /// each fixup target. Used to un-relocate a dump from its runtime base back to the preferred base.
    /// Returns the number of fixups applied.</summary>
    private static int ApplyRelocations(byte[] image, uint relRva, uint relSize, long delta, bool is64)
    {
        int p = (int)relRva, end = (int)Math.Min(relRva + relSize, (uint)image.Length);
        int applied = 0;
        while (p + 8 <= end)
        {
            uint pageRva = BitConverter.ToUInt32(image, p);
            uint blockSize = BitConverter.ToUInt32(image, p + 4);
            if (blockSize < 8 || p + blockSize > end) break;
            int entries = (int)((blockSize - 8) / 2);
            for (int i = 0; i < entries; i++)
            {
                ushort e = BitConverter.ToUInt16(image, p + 8 + i * 2);
                int type = e >> 12, off = e & 0xFFF;
                int t = (int)pageRva + off;   // RVA == file offset in our virtual layout
                if (type == 10 && t + 8 <= image.Length)        // IMAGE_REL_BASED_DIR64
                { ulong v = BitConverter.ToUInt64(image, t); BitConverter.GetBytes(v + (ulong)delta).CopyTo(image, t); applied++; }
                else if (type == 3 && t + 4 <= image.Length)    // IMAGE_REL_BASED_HIGHLOW
                { uint v = BitConverter.ToUInt32(image, t); BitConverter.GetBytes((uint)(v + delta)).CopyTo(image, t); applied++; }
                // type 0 = IMAGE_REL_BASED_ABSOLUTE (padding) — skip
            }
            p += (int)blockSize;
        }
        return applied;
    }

    private static uint LastSectionEnd(PeView view)
    {
        uint end = view.SizeOfHeaders;
        foreach (var s in view.Sections)
            end = Math.Max(end, s.VirtualAddress + Math.Max(s.VirtualSize, s.SizeOfRawData));
        return end;
    }

    private static void WriteU16(byte[] b, int off, ushort v) => BitConverter.GetBytes(v).CopyTo(b, off);
    private static void WriteU32(byte[] b, int off, uint v) => BitConverter.GetBytes(v).CopyTo(b, off);
    private static void WriteDir(byte[] b, int dirBase, int index, uint rva, uint size)
    {
        WriteU32(b, dirBase + index * 8, rva);
        WriteU32(b, dirBase + index * 8 + 4, size);
    }
    private static void WriteName(byte[] b, int off, string name)
    {
        for (int i = 0; i < 8; i++) b[off + i] = 0;
        var bytes = Encoding.ASCII.GetBytes(name);
        Array.Copy(bytes, 0, b, off, Math.Min(8, bytes.Length));
    }
}

using System.Text;

namespace DisasmStudio.Core.Unpacking;

/// <summary>
/// Serializes a clean, on-disk PE from a post-unpack memory image. The dump is written in <b>virtual
/// layout</b> — <c>FileAlignment = SectionAlignment</c> and every section's <c>PointerToRawData =
/// VirtualAddress</c> — so the file's raw bytes mirror the image and no RVA→offset translation is needed.
/// The entry point is corrected to the OEP, a fresh import directory (built by <see cref="ImportRebuilder"/>)
/// is appended as a new section, and base relocations are stripped (the dump is captured at the real load
/// base, so relocating it again would corrupt it). The packer's sections are also tidied so the result reads
/// like an ordinary executable: the section holding the OEP becomes <c>.text</c>, the resource section
/// <c>.rsrc</c>, the rebuilt imports <c>.idata</c>, and the now-dead unpack stub section (executable, held the
/// original entry point, but not the OEP/IAT/any directory) is dropped and its bytes zeroed.
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

        // Appending the import section needs one more 40-byte section header. If the header table is already
        // full — its growth would reach into the first section's data — skip the rebuild and keep the original
        // import directory rather than emit a corrupt image.
        int secBaseHdr = view.PeOffset + PeConstants.OptHeaderFromSig + view.SizeOfOptionalHeader;
        uint firstSecRva0 = view.NumberOfSections > 0 ? view.Sections[0].VirtualAddress : sectionAlign;
        int grownHeaderEnd = secBaseHdr + (view.NumberOfSections + 1) * PeConstants.SectionHeaderSize;
        bool headerHasRoom = PeConstants.Align((uint)grownHeaderEnd, sectionAlign) <= firstSecRva0;
        if (imports is { Ok: true } && !headerHasRoom)
            sb.Append("WARNING: section header table is full; appending the rebuilt import section would overrun " +
                      "the first section — writing the dump with its original import directory instead.\n");

        bool addSection = imports is { Ok: true } && headerHasRoom;
        if (addSection)
        {
            importBytes = ImportRebuilder.SerializeImportSection(imports!.Runs, newSecRva, is64, out descriptorSize);
            sb.Append($"Rebuilt import section: {imports.Runs.Count} descriptor(s), {imports.Resolved} imports, {importBytes.Length} bytes.\n");
        }

        // Load Config relocation: a UPX stub keeps the Load Config inside its (otherwise dead) stub section,
        // and the loader reads it at load time, so that one directory would pin the stub. Copy it into the
        // rebuilt .idata section and repoint the directory, freeing the stub to be dropped. .idata is laid out
        // as [import data | CFG stubs | relocated Load Config]; reserve the space here so the section fits all.
        var (lcRva0, lcSize0) = view.DataDir(PeConstants.DirLoadConfig);
        bool relocLc = addSection && lcRva0 != 0 && lcSize0 >= 0x40 && lcSize0 <= 0x400
                       && (ulong)lcRva0 + lcSize0 <= (ulong)dumpImage.Length;
        uint cfgStubOff = PeConstants.Align((uint)importBytes.Length, 16);   // CFG ret/jmp stubs (≤ 8 bytes)
        uint lcCopyOff = PeConstants.Align(cfgStubOff + 8, 16);              // relocated Load Config
        uint idataLen = !addSection ? 0 : relocLc ? lcCopyOff + lcSize0 : cfgStubOff + 8;
        uint newSecRaw = addSection ? PeConstants.Align(idataLen, sectionAlign) : 0;
        uint finalSize = addSection ? newSecRva + newSecRaw : imageEnd;
        uint lcRva = relocLc ? newSecRva + lcCopyOff : lcRva0;   // where the Load Config lives in the output

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

        // Relocate the Load Config into .idata now the dump bytes are final (post un-relocation). Its internal
        // fields are absolute VAs into other sections, so a byte copy stays valid; only the directory moves.
        if (relocLc)
        {
            Array.Copy(outBuf, (int)lcRva0, outBuf, (int)(newSecRva + lcCopyOff), (int)lcSize0);
            sb.Append($"Relocated Load Config ({lcSize0:X} bytes) {lcRva0:X} → {lcRva:X} (.idata).\n");
        }

        // --- section cleanup plan: rename the packer's sections to conventional roles and drop the dead
        // unpack stub, so the rebuilt image reads like an ordinary executable instead of UPX0/UPX1/… ---
        uint iatRva = imports?.IatStartRva ?? 0;
        uint origEpRva = view.EntryRva;                 // the packer stub's entry (≠ the recovered OEP)
        uint resDirRva = view.DataDir(PeConstants.DirResource).Rva;
        // RVAs that must stay inside a mapped section — a section holding any of these is never dropped.
        var protectedRvas = new List<uint>();
        void Protect(int dir) { var (r, _) = view.DataDir(dir); if (r != 0) protectedRvas.Add(r); }
        Protect(PeConstants.DirExport); Protect(PeConstants.DirResource); Protect(PeConstants.DirException);
        Protect(PeConstants.DirTls); Protect(PeConstants.DirDelayImport);
        if (!relocLc) Protect(PeConstants.DirLoadConfig);   // kept in place ⇒ its section must survive
        if (hasReloc) Protect(PeConstants.DirBaseReloc);
        // The import directory: when we rebuild it (addSection) the header is repointed to the new .idata and
        // the in-place IAT, so the packer's own original import dir/IAT (which a UPX stub keeps inside its stub
        // section) no longer matters and must NOT pin that section. When not rebuilding, keep them protected.
        if (addSection) { if (iatRva != 0) protectedRvas.Add(iatRva); }
        else { Protect(PeConstants.DirImport); Protect(PeConstants.DirIat); Protect(PeConstants.DirBoundImport); }

        var plan = new List<(SectionHeader Src, string Name, uint Chars)>();
        var dropped = new List<(uint Va, uint Size)>();
        for (int i = 0; i < numSec; i++)
        {
            var s = view.Sections[i];
            bool hasOep = SecHas(s, oepRva);
            // The unpack stub: an executable section that held the original entry point but neither the
            // recovered OEP, the IAT, nor any needed directory — dead once unpacking is done. Drop it only
            // when imports were rebuilt (so the IAT location is known and protected) to stay conservative.
            // Never drop the first (lowest-VA) section: contiguity is restored by growing the *preceding*
            // section over the gap, and there is none before section 0 — dropping it would leave a gap between
            // the headers and the first section, which the loader rejects. (UPX's stub is never section 0.)
            bool isStub = addSection && i != 0 && s.IsExecutable && SecHas(s, origEpRva) && !hasOep
                          && !protectedRvas.Any(r => SecHas(s, r));
            if (isStub) { dropped.Add((s.VirtualAddress, Math.Max(s.VirtualSize, s.SizeOfRawData))); continue; }

            string name = hasOep ? ".text"
                        : SecHas(s, resDirRva) ? ".rsrc"
                        : s.Name.StartsWith('.') ? s.Name : ".data";
            uint secChars = s.Characteristics;
            if (hasOep)   // present the unpacked section as code, not the packer's uninitialized-data RWX blob
                secChars = PeConstants.SCN_CNT_CODE | PeConstants.SCN_MEM_EXECUTE | PeConstants.SCN_MEM_READ
                        | (secChars & PeConstants.SCN_MEM_WRITE);
            if (iatRva != 0 && SecHas(s, iatRva)) secChars |= PeConstants.SCN_MEM_WRITE;   // in-place IAT is written
            plan.Add((s, name, secChars));
        }
        int keptCount = plan.Count;
        foreach (var (va, size) in dropped)                 // erase the stub bytes so no packer code remains
        {
            ulong end = Math.Min((ulong)va + size, finalSize);
            for (int z = (int)va; (ulong)z < end && z < outBuf.Length; z++) outBuf[z] = 0;
        }

        // --- optional header fixups ---
        WriteU32(outBuf, optOff + PeConstants.Opt_AddressOfEntryPoint, oepRva);
        if (is64) BitConverter.GetBytes(finalBase).CopyTo(outBuf, optOff + PeConstants.Opt_ImageBase64);
        else WriteU32(outBuf, optOff + PeConstants.Opt_ImageBase32, (uint)finalBase);
        WriteU32(outBuf, optOff + PeConstants.Opt_FileAlignment, sectionAlign);
        WriteU32(outBuf, optOff + PeConstants.Opt_SizeOfImage, finalSize);
        WriteU32(outBuf, optOff + PeConstants.Opt_CheckSum, 0);   // stale after our edits; 0 means "skip"

        // Headers occupy the first SectionAlignment-aligned span; verify the (grown) section table fits.
        int headerEnd = secBase + (keptCount + (addSection ? 1 : 0)) * PeConstants.SectionHeaderSize;
        uint sizeOfHeaders = PeConstants.Align((uint)headerEnd, sectionAlign);
        uint firstSecRva = keptCount > 0 ? plan[0].Src.VirtualAddress : sectionAlign;
        if (sizeOfHeaders > firstSecRva)
            sb.Append($"WARNING: header table ({headerEnd:X}) grows past first section RVA ({firstSecRva:X}); output may be malformed.\n");
        WriteU32(outBuf, optOff + PeConstants.Opt_SizeOfHeaders, sizeOfHeaders);

        // --- COFF header: one more section; strip relocations only if there are none to keep ---
        WriteU16(outBuf, fileHdr + PeConstants.Coff_NumberOfSections, (ushort)(keptCount + (addSection ? 1 : 0)));
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

        // --- section headers: re-emitted from the cleanup plan (renamed, stub dropped), virtual == raw
        // layout, IAT section made writable. Headers are rewritten fresh so dropped sections compact away. ---
        for (int oi = 0; oi < keptCount; oi++)
        {
            var (s, name, secChars) = plan[oi];
            int h = secBase + oi * PeConstants.SectionHeaderSize;
            // Grow each kept section's virtual extent up to the next section in the final layout, so dropping
            // the stub leaves the section table contiguous (the loader rejects an image with an RVA gap between
            // sections). The absorbed range is the zeroed former-stub bytes — dead, never referenced.
            uint nextVa = oi + 1 < keptCount ? plan[oi + 1].Src.VirtualAddress : (addSection ? newSecRva : finalSize);
            uint vsize = nextVa > s.VirtualAddress ? nextVa - s.VirtualAddress : Math.Max(s.VirtualSize, s.SizeOfRawData);
            uint rawSize = PeConstants.Align(vsize, sectionAlign);
            if (s.VirtualAddress + rawSize > finalSize) rawSize = finalSize > s.VirtualAddress ? finalSize - s.VirtualAddress : 0;
            WriteName(outBuf, h + PeConstants.Sec_Name, name);
            WriteU32(outBuf, h + PeConstants.Sec_VirtualSize, vsize);
            WriteU32(outBuf, h + PeConstants.Sec_VirtualAddress, s.VirtualAddress);
            WriteU32(outBuf, h + PeConstants.Sec_SizeOfRawData, rawSize);
            WriteU32(outBuf, h + PeConstants.Sec_PointerToRawData, s.VirtualAddress);
            for (int z = 24; z < 36; z++) outBuf[h + z] = 0;   // clear stale PointerToReloc/Linenumbers/counts
            WriteU32(outBuf, h + PeConstants.Sec_Characteristics, secChars);
        }
        // Clear any header slots the (now-shorter) table no longer uses, leaving the appended import slot.
        for (int oi = keptCount + (addSection ? 1 : 0); oi < numSec; oi++)
        {
            int h = secBase + oi * PeConstants.SectionHeaderSize;
            for (int z = 0; z < PeConstants.SectionHeaderSize; z++) outBuf[h + z] = 0;
        }

        // --- data directories ---
        // Clamp the directory count to what the optional header can physically hold (DataDir array must stay
        // inside SizeOfOptionalHeader, before the section table) so a packer that shrank the optional header
        // can't make us scribble directory entries over the section headers. Standard headers hold 16.
        int dirBase = optOff + PeConstants.DataDirBaseOffset(is64);
        int dirCapacity = (sizeOfOpt - PeConstants.DataDirBaseOffset(is64)) / 8;
        uint dirCount = (uint)Math.Min(16, Math.Max(0, dirCapacity));
        WriteU32(outBuf, optOff + PeConstants.NumberOfRvaAndSizesOffset(is64), dirCount);
        void WriteDirSafe(int index, uint rva, uint size) { if (index < dirCount) WriteDir(outBuf, dirBase, index, rva, size); }

        if (!hasReloc) WriteDirSafe(PeConstants.DirBaseReloc, 0, 0);
        WriteDirSafe(PeConstants.DirBoundImport, 0, 0);  // stale
        WriteDirSafe(4, 0, 0);                           // Certificate: the signature overlay isn't dumped
        if (addSection)
        {
            if (PeConstants.DirIat < dirCount)
            {
                WriteDirSafe(PeConstants.DirImport, newSecRva, descriptorSize);
                WriteDirSafe(PeConstants.DirIat, imports!.IatStartRva, imports.IatSize);
            }
            else sb.Append($"WARNING: optional header holds only {dirCount} data directories; the rebuilt import table is present but not registered in the header.\n");
        }
        if (relocLc) WriteDirSafe(PeConstants.DirLoadConfig, lcRva, lcSize0);   // point at the relocated copy

        // --- append the new section header ---
        if (addSection)
        {
            int h = secBase + keptCount * PeConstants.SectionHeaderSize;
            WriteName(outBuf, h + PeConstants.Sec_Name, ".idata");
            WriteU32(outBuf, h + PeConstants.Sec_VirtualSize, idataLen);
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
        if (lcRva != 0)
        {
            int scOff = is64 ? 0x58 : 0x3C, psz = is64 ? 8 : 4;
            if (scOff + psz <= lcSize0 && lcRva + scOff + psz <= finalSize)
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
            uint retStub = newSecRva + cfgStubOff, jmpStub = retStub + 4;   // reserved CFG-stub slot in .idata
            if (Math.Max(chkOff, dspOff) + psz <= lcSize0 && jmpStub + 2 <= newSecRva + newSecRaw)
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
                    // Make the import section executable so the CFG stubs can run (VirtualSize already covers them).
                    int hIdata = secBase + keptCount * PeConstants.SectionHeaderSize;
                    WriteU32(outBuf, hIdata + PeConstants.Sec_Characteristics,
                        PeConstants.SCN_CNT_INITIALIZED_DATA | PeConstants.SCN_MEM_READ | PeConstants.SCN_MEM_WRITE | PeConstants.SCN_MEM_EXECUTE);
                    sb.Append($"Neutralized {set} CFG guard pointer(s).\n");
                }
            }
        }

        WriteU32(outBuf, optOff + PeConstants.Opt_AddressOfEntryPoint, oepRva);   // re-assert after any overlap
        if (dropped.Count > 0) sb.Append($"Removed {dropped.Count} packer stub section(s); renamed sections to .text/.rsrc/.idata.\n");
        sb.Append($"Output: {finalSize:X} bytes, entry RVA {oepRva:X}, {keptCount + (addSection ? 1 : 0)} sections.\n");
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

    /// <summary>True if RVA <paramref name="rva"/> (non-zero) falls within section <paramref name="s"/>.</summary>
    private static bool SecHas(SectionHeader s, uint rva)
    {
        if (rva == 0) return false;
        uint size = Math.Max(s.VirtualSize, s.SizeOfRawData);
        return rva >= s.VirtualAddress && rva < s.VirtualAddress + size;
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

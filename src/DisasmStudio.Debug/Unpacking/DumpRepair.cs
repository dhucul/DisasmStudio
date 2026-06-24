using DisasmStudio.Core.Unpacking;

namespace DisasmStudio.Debug.Unpacking;

/// <summary>
/// Repairs a dumped image whose in-memory PE header a protector has wiped. Themida/WinLicense-class protectors
/// zero or garble their own section table (and clear the section-executable flags) at runtime as an anti-dump
/// measure, so a memory dump parses with no usable sections and <see cref="PeBuilder"/> emits a degenerate PE.
/// This reconstructs a plausible section table from the committed-memory region map (the same region walk
/// <see cref="MemoryImageDump"/> already does) — one section per coalesced region, with characteristics derived
/// from each region's page protection — and writes it back into the dump's header so the image re-parses and can
/// be rebuilt/analyzed. Best-effort (Scylla "fix dump" in spirit): it recovers a layout, not the original names.
/// </summary>
public static class DumpRepair
{
    /// <summary>Max executable bytes kept around the entry when reconstructing a protector dump's sections; the
    /// rest of the all-executable body is re-marked as data so the analyzer's gap scan can't grind on it.</summary>
    private const uint ExecCap = 0x10000;   // 64 KiB — bounds the gap scan to a snappy open even on worst-case junk

    /// <summary>True when the dumped header's section table is unusable — zero/over-many sections, or no
    /// executable section with a sane VA (the protector cleared them). Signals a reconstruct is needed.</summary>
    public static bool NeedsReconstruction(PeView view, uint sizeOfImage)
    {
        if (view.NumberOfSections == 0 || view.NumberOfSections > 96) return true;
        bool anyExec = false, anySaneVa = false;
        foreach (var s in view.Sections)
        {
            if (s.VirtualAddress > 0 && s.VirtualAddress < sizeOfImage) anySaneVa = true;
            if (s.IsExecutable && s.VirtualAddress > 0 && s.VirtualAddress < sizeOfImage) anyExec = true;
        }
        return !anyExec || !anySaneVa;
    }

    /// <summary>Rebuild the section table in <paramref name="image"/>'s header from <paramref name="regions"/> and
    /// re-parse it into <paramref name="repaired"/>. Mutates the header bytes in place. False if it couldn't fit a
    /// table (caller then relies on the raw dump).</summary>
    public static bool TryReconstruct(byte[] image, PeView view, uint sizeOfImage, IReadOnlyList<MemRegion> regions,
        Action<string> log, out PeView repaired)
    {
        repaired = view;
        uint secAlign = view.SectionAlignment == 0 ? 0x1000u : view.SectionAlignment;
        uint fileAlign = view.FileAlignment == 0 ? 0x200u : view.FileAlignment;
        uint hdrEnd = Align(Math.Max(view.SizeOfHeaders, 0x200u), secAlign);   // first section starts here
        int secBase = view.PeOffset + PeConstants.OptHeaderFromSig + view.SizeOfOptionalHeader;

        // Coalesce the committed regions (sorted, header excluded) into candidate sections, tracking whether any
        // covered page was executable / writable so the section characteristics can reflect it.
        var cands = new List<(uint Rva, uint Size, bool Exec, bool Write)>();
        foreach (var r in regions.OrderBy(r => r.Rva))
        {
            uint rva = r.Rva, end = r.Rva + r.Size;
            if (end <= hdrEnd) continue;                 // wholly inside the header region
            if (rva < hdrEnd) rva = hdrEnd;              // clamp the header out of a region that spans into code
            if (rva >= sizeOfImage || end <= rva) continue;
            end = Math.Min(end, sizeOfImage);
            bool exec = (r.Protect & 0xF0) != 0;         // PAGE_EXECUTE* live in the high nibble
            bool write = (r.Protect & 0xCC) != 0;        // READWRITE/WRITECOPY/EXECUTE_READWRITE/EXECUTE_WRITECOPY
            if (cands.Count > 0 && rva <= cands[^1].Rva + cands[^1].Size)
            {
                var p = cands[^1];
                uint newEnd = Math.Max(p.Rva + p.Size, end);
                cands[^1] = (p.Rva, newEnd - p.Rva, p.Exec || exec, p.Write || write);
            }
            else cands.Add((rva, end - rva, exec, write));
        }
        if (cands.Count == 0) { log("Header reconstruction: no committed regions to map; relying on the raw dump."); return false; }

        // Bound the executable extent. A virtualizing protector maps its whole body executable, but almost all
        // of it is unreachable VM bytecode/junk — which makes the analyzer's gap scan (prologue-hunt + run
        // recovery on every unmarked byte) grind for minutes on these dumps. Keep a code window that contains
        // the entry executable and re-mark the overflow as DATA: still present and viewable, just not gap-scanned
        // as code. DumpRepair only runs when the in-memory header was wiped (a protector anti-dump tell), so this
        // never reshapes a normally-laid-out image; a clean unpack keeps its full .text.
        {
            uint entryRva = view.EntryRva;
            var bounded = new List<(uint Rva, uint Size, bool Exec, bool Write)>(cands.Count + 2);
            foreach (var c in cands)
            {
                if (c.Exec && c.Size > ExecCap)
                {
                    uint win = ExecCap;
                    if (entryRva >= c.Rva && entryRva < c.Rva + c.Size && entryRva - c.Rva >= win)
                        win = Math.Min(c.Size, entryRva - c.Rva + 0x10000);   // keep the entry inside the window
                    bounded.Add((c.Rva, win, true, c.Write));
                    bounded.Add((c.Rva + win, c.Size - win, false, c.Write));
                    log($"Header reconstruction: bounded executable extent to {ExecCap >> 10} KB at the entry; " +
                        $"0x{c.Size - win:X} byte(s) of the protected body re-marked as data (not gap-scanned).");
                }
                else bounded.Add(c);
            }
            cands = bounded;
        }

        // Keep the section table inside the header span (leave one slot for a PeBuilder-appended import section).
        int maxSections = Math.Min(48, (int)((hdrEnd - (uint)secBase) / PeConstants.SectionHeaderSize) - 1);
        if (maxSections < 1) { log("Header reconstruction: no room for a section table; relying on the raw dump."); return false; }
        while (cands.Count > maxSections)
        {
            int bestI = 0; long bestGap = long.MaxValue;
            for (int i = 0; i < cands.Count - 1; i++)
            {
                long gap = (long)cands[i + 1].Rva - (cands[i].Rva + cands[i].Size);
                if (gap < bestGap) { bestGap = gap; bestI = i; }
            }
            var a = cands[bestI]; var b = cands[bestI + 1];
            cands[bestI] = (a.Rva, b.Rva + b.Size - a.Rva, a.Exec || b.Exec, a.Write || b.Write);
            cands.RemoveAt(bestI + 1);
        }

        uint entry = view.EntryRva;
        for (int i = 0; i < cands.Count; i++)
        {
            var (rva, size, exec, write) = cands[i];
            bool hasEntry = entry >= rva && entry < rva + size;
            string name = hasEntry ? ".text" : $"seg{i:00}";
            uint chars = exec
                ? PeConstants.SCN_CNT_CODE | PeConstants.SCN_MEM_EXECUTE | PeConstants.SCN_MEM_READ | (write ? PeConstants.SCN_MEM_WRITE : 0)
                : PeConstants.SCN_CNT_INITIALIZED_DATA | PeConstants.SCN_MEM_READ | (write ? PeConstants.SCN_MEM_WRITE : 0);

            int sOff = secBase + i * PeConstants.SectionHeaderSize;
            if (sOff + PeConstants.SectionHeaderSize > image.Length) break;
            WriteName(image, sOff, name);
            WriteU32(image, sOff + PeConstants.Sec_VirtualSize, size);
            WriteU32(image, sOff + PeConstants.Sec_VirtualAddress, rva);
            WriteU32(image, sOff + PeConstants.Sec_SizeOfRawData, size);
            WriteU32(image, sOff + PeConstants.Sec_PointerToRawData, rva);   // dump is VA-indexed → raw == VA
            for (int z = 24; z < 36; z++) image[sOff + z] = 0;               // relocs/linenums
            WriteU32(image, sOff + PeConstants.Sec_Characteristics, chars);
        }

        // Fix the COFF section count and grow SizeOfHeaders to cover the new table (still below the first section).
        int coffOff = view.PeOffset + PeConstants.FileHeaderFromSig;
        WriteU16(image, coffOff + PeConstants.Coff_NumberOfSections, (ushort)cands.Count);
        uint tableEnd = (uint)(secBase + cands.Count * PeConstants.SectionHeaderSize);
        uint newSizeOfHeaders = Math.Min(Align(tableEnd, fileAlign), hdrEnd);
        WriteU32(image, view.PeOffset + PeConstants.OptHeaderFromSig + PeConstants.Opt_SizeOfHeaders, newSizeOfHeaders);

        if (!PeView.TryParse(image, out repaired)) { repaired = view; return false; }
        log($"Header reconstruction: rebuilt {cands.Count} section(s) from the memory region map " +
            $"({cands.Count(c => c.Exec)} executable). Names are synthetic (.text/seg##).");
        return true;
    }

    private static uint Align(uint v, uint a) => a == 0 ? v : (v + a - 1) & ~(a - 1);

    private static void WriteName(byte[] b, int off, string name)
    {
        for (int i = 0; i < 8; i++) b[off + i] = i < name.Length ? (byte)name[i] : (byte)0;
    }

    private static void WriteU16(byte[] b, int off, ushort v)
    {
        if (off < 0 || off + 2 > b.Length) return;
        b[off] = (byte)v; b[off + 1] = (byte)(v >> 8);
    }

    private static void WriteU32(byte[] b, int off, uint v)
    {
        if (off < 0 || off + 4 > b.Length) return;
        b[off] = (byte)v; b[off + 1] = (byte)(v >> 8); b[off + 2] = (byte)(v >> 16); b[off + 3] = (byte)(v >> 24);
    }
}

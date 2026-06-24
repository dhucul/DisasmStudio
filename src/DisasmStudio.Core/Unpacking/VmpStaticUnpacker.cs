using System.Text;
using DisasmStudio.Core.Unpacking.Lzma;

namespace DisasmStudio.Core.Unpacking;

/// <summary>The outcome of a static VMProtect "Pack the Output File" unpack.</summary>
/// <param name="Applicable">True when the file actually carries VMProtect's LZMA output-compression layer.
/// False means the static path doesn't apply (the caller should fall back to the dynamic strategies).</param>
/// <param name="Ok">True when an image was successfully reconstructed.</param>
/// <param name="Image">The reconstructed image in virtual layout (RVA-indexed), ready to write/open; null on failure.</param>
/// <param name="EntryRva">The image entry-point RVA (still the protector stub — the true OEP is not recovered).</param>
/// <param name="Blocks">Number of LZMA blocks decompressed.</param>
public sealed record VmpStaticResult(
    bool Applicable, bool Ok, byte[]? Image, uint EntryRva, int Blocks, string Log, string? Error);

/// <summary>
/// Static unpacker for VMProtect's optional <b>"Pack the Output File"</b> compression layer — no execution,
/// no debugger, so it sidesteps the anti-debug wall that defeats the dynamic run-to-OEP path entirely.
/// <para>
/// VMProtect's packer LZMA-compresses the original sections and leaves a <c>PACKER_INFO</c> table of
/// <c>{SrcRVA, DstRVA}</c> block descriptors (entry [0] points at the shared 5-byte LZMA props). A tiny
/// runtime stub replays those blocks into their destination RVAs. This reconstructs the same image
/// statically: lay the raw sections into a virtual-address buffer, locate <c>PACKER_INFO</c> by matching the
/// RVAs of the virtual-only (decompression-target) sections, then LZMA-decompress each block into its
/// destination.
/// </para>
/// <para>
/// Scope: this undoes <i>compression only</i>. Functions VMProtect virtualized stay as VM bytecode; the IAT
/// is left as the packer wrote it (no live module list exists without running); and the entry point stays at
/// the stub (the true OEP is not recovered). The result is a faithful, re-openable image — recovering all the
/// non-virtualized native code and giving the <c>Devirt</c> engine a decrypted image without a runtime dump.
/// </para>
/// Ported from a Go reference (the user's <c>unpackPE</c>), with a masked pattern matcher (fixing a
/// literal-<c>0xFF</c>-as-wildcard bug), per-block bounded decode sizing, and applicability gating.
/// </summary>
public static class VmpStaticUnpacker
{
    private const uint SCN_CNT_UNINITIALIZED_DATA = 0x0000_0080;
    private const uint MaxImageSize = 512u << 20;   // sanity cap on SizeOfImage (512 MiB)

    /// <summary>Cheap, non-throwing probe: does this file carry the VMProtect LZMA output-compression layer?
    /// Used to auto-select the static strategy. No decompression is performed.</summary>
    public static bool LooksApplicable(byte[] file)
    {
        try
        {
            if (!PeView.TryParse(file, out var pe) || pe.SizeOfImage == 0) return false;
            var (pattern, literal) = BuildPackerInfoPattern(pe);
            if (pattern.Length == 0) return false;
            return FindMasked(file, pattern, literal) >= 8;
        }
        catch { return false; }
    }

    /// <summary>Statically unpack the file. Returns <see cref="VmpStaticResult.Applicable"/> = false (with a
    /// reason) when the LZMA output layer isn't present.</summary>
    public static VmpStaticResult Unpack(byte[] file)
    {
        var log = new StringBuilder();
        try
        {
            return UnpackCore(file, log);
        }
        catch (NotApplicableException ex)
        {
            log.AppendLine(ex.Message);
            return new VmpStaticResult(false, false, null, 0, 0, log.ToString(), ex.Message);
        }
        catch (Exception ex)
        {
            // We got far enough to know it IS the packed variant, but reconstruction failed.
            log.AppendLine("ERROR: " + ex.Message);
            return new VmpStaticResult(true, false, null, 0, 0, log.ToString(), ex.Message);
        }
    }

    private static VmpStaticResult UnpackCore(byte[] file, StringBuilder log)
    {
        if (!PeView.TryParse(file, out var pe))
            throw new NotApplicableException("Not applicable: not a valid PE.");
        uint sizeOfImage = pe.SizeOfImage;
        if (sizeOfImage == 0 || sizeOfImage > MaxImageSize)
            throw new NotApplicableException($"Not applicable: implausible SizeOfImage (0x{sizeOfImage:X}).");
        if (pe.SizeOfHeaders > file.Length)
            throw new InvalidOperationException($"SizeOfHeaders (0x{pe.SizeOfHeaders:X}) exceeds file size.");

        log.AppendLine($"Reconstructing virtual image: SizeOfImage=0x{sizeOfImage:X}, {pe.Sections.Count} section(s), {(pe.Is64 ? "x64" : "x86")}.");
        var image = new byte[sizeOfImage];

        // Headers (1:1 on disk and in memory).
        int hdr = (int)Math.Min(Math.Min(pe.SizeOfHeaders, (uint)file.Length), sizeOfImage);
        Array.Copy(file, 0, image, 0, hdr);

        // Raw section bytes → their virtual addresses.
        foreach (var s in pe.Sections)
        {
            if (s.PointerToRawData == 0 || s.SizeOfRawData == 0) continue;
            long srcEnd = (long)s.PointerToRawData + s.SizeOfRawData;
            long dstEnd = (long)s.VirtualAddress + s.SizeOfRawData;
            if (srcEnd > file.Length || dstEnd > image.Length)
            {
                log.AppendLine($"  Warning: section '{s.Name}' raw data out of bounds — skipped.");
                continue;
            }
            Array.Copy(file, (int)s.PointerToRawData, image, (int)s.VirtualAddress, (int)s.SizeOfRawData);
        }

        // Re-shape the output's section table into virtual layout so it re-opens cleanly:
        // PointerToRawData = VirtualAddress, SizeOfRawData = VirtualSize, and FileAlignment = SectionAlignment.
        int secBase = pe.PeOffset + PeConstants.OptHeaderFromSig + pe.SizeOfOptionalHeader;
        for (int i = 0; i < pe.Sections.Count; i++)
        {
            int sOff = secBase + i * PeConstants.SectionHeaderSize;
            var s = pe.Sections[i];
            WriteU32(image, sOff + PeConstants.Sec_PointerToRawData, s.VirtualAddress);
            if (s.VirtualSize > 0)
                WriteU32(image, sOff + PeConstants.Sec_SizeOfRawData, s.VirtualSize);
        }
        if (pe.SectionAlignment != 0)
            WriteU32(image, pe.PeOffset + PeConstants.OptHeaderFromSig + PeConstants.Opt_FileAlignment, pe.SectionAlignment);

        // Locate PACKER_INFO via the RVA pattern of the virtual-only (decompression-target) sections.
        var (pattern, literal) = BuildPackerInfoPattern(pe);
        if (pattern.Length == 0)
            throw new NotApplicableException("Not applicable: no virtual-only target sections — not VMProtect's packed-output variant. " +
                                             "Reconstructed the section layout, but there is no LZMA layer to decompress.");

        int matchIdx = FindMasked(file, pattern, literal);
        if (matchIdx < 0)
            throw new NotApplicableException("Not applicable: PACKER_INFO RVA pattern not found. The file may be VMProtect-virtualized " +
                                             "but not output-packed, or uses an unrecognized packer layout — use a dynamic strategy.");
        if (matchIdx < 8)
            throw new InvalidOperationException("PACKER_INFO[0] would precede the start of the file.");

        int piBase = matchIdx - 8;
        int numBlocks = pattern.Length / 8;
        log.AppendLine($"Found PACKER_INFO at file offset 0x{piBase:X} ({numBlocks} block(s)).");

        uint propsSrc = ReadU32(file, piBase);
        if (!TryRvaToRaw(pe, file.Length, propsSrc, out uint propsRaw) || propsRaw + 5 > file.Length)
            throw new InvalidOperationException($"Could not resolve LZMA props at RVA 0x{propsSrc:X}.");
        var props = new ReadOnlySpan<byte>(file, (int)propsRaw, 5);
        log.AppendLine($"LZMA props: {Convert.ToHexString(props)} (RVA 0x{propsSrc:X}).");

        int decoded = 0;
        for (int i = 1; i <= numBlocks; i++)
        {
            int entryOff = piBase + i * 8;
            if (entryOff + 8 > file.Length)
                throw new InvalidOperationException($"PACKER_INFO[{i}] is out of file bounds.");
            uint src = ReadU32(file, entryOff);
            uint dst = ReadU32(file, entryOff + 4);
            if (!TryRvaToRaw(pe, file.Length, src, out uint compRaw))
                throw new InvalidOperationException($"Block {i}: could not resolve compressed RVA 0x{src:X}.");
            if (dst >= image.Length)
                throw new InvalidOperationException($"Block {i}: destination RVA 0x{dst:X} is outside the unpacked image.");

            long outHint = DestSize(pe, dst);
            byte[] decompressed = LzmaCodec.Decode(props, file, (int)compRaw, file.Length - (int)compRaw, outHint);

            int avail = image.Length - (int)dst;
            int n = Math.Min(decompressed.Length, avail);
            Array.Copy(decompressed, 0, image, (int)dst, n);
            decoded++;
            log.AppendLine($"  Block {i}: Src RVA 0x{src:X8} → Dst RVA 0x{dst:X8}, {n} bytes decompressed.");
        }

        log.AppendLine($"Done: {decoded} block(s) decompressed; entry RVA 0x{pe.EntryRva:X} (still the protector stub).");
        return new VmpStaticResult(true, true, image, pe.EntryRva, decoded, log.ToString(), null);
    }

    /// <summary>Build the PACKER_INFO locator: for each virtual-only (SizeOfRawData==0, PointerToRawData==0,
    /// not uninitialized-data) section, 4 wildcard bytes (the Src field) followed by the section's
    /// VirtualAddress as 4 literal little-endian bytes (the Dst field). The runtime PACKER_INFO entries carry
    /// exactly these Dst values, so the concatenation pinpoints the table.</summary>
    private static (byte[] Pattern, bool[] Literal) BuildPackerInfoPattern(PeView pe)
    {
        var pattern = new List<byte>();
        var literal = new List<bool>();
        foreach (var s in pe.Sections)
        {
            bool virtualOnly = s.SizeOfRawData == 0 && s.PointerToRawData == 0;
            bool notUninit = (s.Characteristics & SCN_CNT_UNINITIALIZED_DATA) == 0;
            if (!virtualOnly || !notUninit) continue;

            for (int k = 0; k < 4; k++) { pattern.Add(0); literal.Add(false); }      // Src — wildcard
            uint va = s.VirtualAddress;
            for (int k = 0; k < 4; k++) { pattern.Add((byte)(va >> (k * 8))); literal.Add(true); }  // Dst — literal VA
        }
        return (pattern.ToArray(), literal.ToArray());
    }

    /// <summary>First offset where <paramref name="pattern"/> matches, comparing only the bytes flagged in
    /// <paramref name="literal"/> (the rest are wildcards). Anchored on the first literal byte for speed.</summary>
    private static int FindMasked(byte[] data, byte[] pattern, bool[] literal)
    {
        int n = pattern.Length;
        if (n == 0 || data.Length < n) return -1;
        int anchor = Array.IndexOf(literal, true);
        if (anchor < 0) return -1;   // all-wildcard pattern would match anywhere — treat as no match
        byte anchorByte = pattern[anchor];
        int last = data.Length - n;
        for (int i = 0; i <= last; i++)
        {
            if (data[i + anchor] != anchorByte) continue;
            bool ok = true;
            for (int j = 0; j < n; j++)
                if (literal[j] && data[i + j] != pattern[j]) { ok = false; break; }
            if (ok) return i;
        }
        return -1;
    }

    /// <summary>Translate an RVA to a raw file offset (the file is on-disk, file-offset-indexed). Headers map
    /// 1:1; otherwise the containing section's PointerToRawData applies. False for BSS / out-of-bounds.</summary>
    private static bool TryRvaToRaw(PeView pe, int fileLen, uint rva, out uint raw)
    {
        raw = 0;
        if (rva < pe.SizeOfHeaders)
        {
            raw = rva;
            return rva < fileLen;
        }
        foreach (var s in pe.Sections)
        {
            if (rva < s.VirtualAddress || rva >= s.VirtualAddress + s.VirtualSize) continue;
            if (s.PointerToRawData == 0) return false;
            uint off = rva - s.VirtualAddress;
            if (off >= s.SizeOfRawData) return false;   // virtual-only / BSS tail
            uint candidate = s.PointerToRawData + off;
            if (candidate >= fileLen) return false;
            raw = candidate;
            return true;
        }
        return false;
    }

    /// <summary>The expected decompressed size for a block whose destination is <paramref name="dstRva"/> —
    /// the VirtualSize of the section that starts there — so the LZMA decoder stops precisely. -1 if unknown.</summary>
    private static long DestSize(PeView pe, uint dstRva)
    {
        foreach (var s in pe.Sections)
        {
            uint span = Math.Max(Math.Max(s.VirtualSize, s.SizeOfRawData), 1u);
            if (dstRva >= s.VirtualAddress && dstRva < s.VirtualAddress + span)
                return s.VirtualSize > 0 ? s.VirtualSize : -1;
        }
        return -1;
    }

    private static uint ReadU32(byte[] b, int off) =>
        (uint)(b[off] | (b[off + 1] << 8) | (b[off + 2] << 16) | (b[off + 3] << 24));

    private static void WriteU32(byte[] b, int off, uint v)
    {
        if (off < 0 || off + 4 > b.Length) return;
        b[off] = (byte)v; b[off + 1] = (byte)(v >> 8); b[off + 2] = (byte)(v >> 16); b[off + 3] = (byte)(v >> 24);
    }

    private sealed class NotApplicableException(string message) : Exception(message);
}

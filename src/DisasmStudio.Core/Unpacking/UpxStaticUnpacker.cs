using System.Text;
using DisasmStudio.Core.Unpacking.Lzma;

namespace DisasmStudio.Core.Unpacking;

/// <summary>
/// Static (no-execution) unpacker for UPX-packed PEs. UPX carries everything needed to reverse itself on disk:
/// a <c>PackHeader</c> ("UPX!" magic) records the compression method, the uncompressed length, and — crucially
/// — the <b>Adler-32 checksum of the uncompressed data</b>. That checksum makes decompression
/// <b>self-verifying</b>: it only accepts plaintext whose checksum matches the UPX header. Reconstructed PE
/// layout is validated separately. For PE images, the same post-decompression sequence as UPX's
/// <c>PeFile::unpack0</c> restores imports, relocations, and resources before the ordinary file layout is
/// written. Unsupported methods and metadata layouts remain analysis-only instead of being presented as
/// runnable.
///
/// Method-14 (UPX-framed LZMA) and PE filter 0x49 are verified against a real win64/PE UPX sample. The Adler-32
/// gate remains mandatory for every method and layout — a wrong decode is rejected, not written.
/// </summary>
public sealed class UpxStaticUnpacker : IStaticUnpacker
{
    public string Name => "UPX (static, checksum-verified PE rebuild)";

    // UPX method ids (packhead.h).
    private const byte M_NRV2B_LE32 = 2, M_NRV2B_8 = 3;
    private const byte M_NRV2D_LE32 = 5, M_NRV2D_8 = 6;
    private const byte M_NRV2E_LE32 = 8, M_NRV2E_8 = 9;
    private const byte M_LZMA = 14;

    private static readonly byte[] Magic = "UPX!"u8.ToArray();

    public bool LooksApplicable(byte[] file, CancellationToken cancellationToken = default)
    {
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!PeView.TryParse(file, out var pe)) return false;
            foreach (var s in pe.Sections)
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (s.Name.StartsWith("UPX", StringComparison.OrdinalIgnoreCase)) return true;
            }
            return IndexOf(file, Magic, 0, cancellationToken) >= 0;
        }
        catch (OperationCanceledException) { throw; }
        catch { return false; }
    }

    public StaticUnpackResult Unpack(byte[] file, CancellationToken cancellationToken = default)
    {
        var log = new StringBuilder();
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!PeView.TryParse(file, out var pe))
                return StaticUnpackResult.NotApplicable("Not applicable: not a valid PE.");
            if (!LooksApplicable(file, cancellationToken))
                return StaticUnpackResult.NotApplicable("Not applicable: no UPX section names or 'UPX!' PackHeader found.");

            // Parse every "UPX!" PackHeader and keep the ones that look like a real header (plausible sizes).
            var headers = FindPackHeaders(file, log, cancellationToken);
            if (headers.Count == 0)
                return StaticUnpackResult.Fail(log.ToString(),
                    "UPX detected but no parseable PackHeader (method/sizes/Adler) found. Use the dynamic unpacker (verified for UPX).");

            foreach (var h in headers)
            {
                cancellationToken.ThrowIfCancellationRequested();
                log.AppendLine($"PackHeader @0x{h.Offset:X}: method={h.Method}, u_len=0x{h.ULen:X}, c_len=0x{h.CLen:X}, u_adler=0x{h.UAdler:X8}, filter={h.Filter}.");
                if (h.ULen == 0 || h.ULen > (128u << 20)) { log.AppendLine("  implausible u_len — skipped."); continue; }

                // Locate the compressed data by trying candidate start offsets and accepting only the decode whose
                // Adler-32 matches the header — no reliance on exact block-structure knowledge, and false positives
                // are impossible (a 32-bit checksum must match exactly).
                if (TryDecodeVerified(file, pe, h, log, cancellationToken) is not { } plain) continue;

                log.AppendLine($"  Adler-32 VERIFIED (0x{h.UAdler:X8}) — decompression is provably correct ({plain.Length} bytes).");

                // PE-pack layouts store the original PE header and section table at the end of the decoded RVA
                // buffer. Rebuild an ordinary file-layout PE from those records.
                if (TryReconstructPe(
                        file, pe, h, plain, log, cancellationToken,
                        out byte[]? image, out uint entryRva, out bool canExecute) && image is not null)
                {
                    log.AppendLine("  Reconstructed a re-openable PE image from the verified plaintext.");
                    log.AppendLine(canExecute
                        ? "  Restored UPX imports, relocations, and resources; output is execution-ready."
                        : "  Runtime metadata uses an unsupported UPX layout; output is analysis-only.");
                    return new StaticUnpackResult(
                        true, true, image, entryRva, 1, log.ToString(), null, CanExecute: canExecute);
                }

                log.AppendLine("  Decompression verified, but a re-openable analysis PE couldn't be reconstructed from this layout.");
                return StaticUnpackResult.Fail(log.ToString(),
                    "UPX decompression verified (Adler-32 matched), but reconstructing an analysis PE from this UPX layout " +
                    "isn't supported statically in this build. Use the dynamic 'Unpack…' strategy (verified end-to-end for UPX) " +
                    "or 'Dump Process…'.");
            }

            return StaticUnpackResult.Fail(log.ToString(),
                "UPX detected, but no compressed block could be decoded and Adler-verified (unsupported method/variant, or a " +
                "layout this build doesn't handle). Use the dynamic unpacker — it's the verified route for UPX here.");
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex)
        {
            log.AppendLine("ERROR: " + ex.Message);
            return StaticUnpackResult.Fail(log.ToString(), ex.Message);
        }
    }

    // ---- PackHeader ----

    private readonly record struct PackHeader(
        int Offset, byte Version, byte Format, byte Method, byte Level,
        uint UAdler, uint CAdler, uint ULen, uint CLen, uint UFileSize, byte Filter, byte FilterCto);

    // Parse each "UPX!" occurrence as the common PackHeader layout; keep those whose sizes/method are plausible.
    private static List<PackHeader> FindPackHeaders(
        byte[] file, StringBuilder log, CancellationToken cancellationToken)
    {
        var list = new List<PackHeader>();
        for (int at = 0; (at = IndexOf(file, Magic, at, cancellationToken)) >= 0; at += 4)
        {
            // Common on-disk PackHeader after the 4-byte magic (little-endian, PE):
            //   version u8, format u8, method u8, level u8, u_adler u32, c_adler u32, u_len u32, c_len u32,
            //   u_file_size u32, filter u8, filter_cto u8, (mru/checksum u8), header_checksum u8.
            int p = at + 4;
            if (p + 28 > file.Length) continue;
            byte version = file[p + 0], format = file[p + 1], method = file[p + 2], level = file[p + 3];
            uint uAdler = U32(file, p + 4), cAdler = U32(file, p + 8);
            uint uLen = U32(file, p + 12), cLen = U32(file, p + 16), uFileSize = U32(file, p + 20);
            byte filter = file[p + 24], filterCto = file[p + 25];

            bool methodOk = method is M_NRV2B_LE32 or M_NRV2B_8 or M_NRV2D_LE32 or M_NRV2D_8
                                    or M_NRV2E_LE32 or M_NRV2E_8 or M_LZMA;
            bool sizesOk = uLen > 0 && uLen < (256u << 20) && cLen > 0 && cLen <= (uint)file.Length;
            if (methodOk && sizesOk) list.Add(new PackHeader(at, version, format, method, level, uAdler, cAdler, uLen, cLen, uFileSize, filter, filterCto));
        }
        return list;
    }

    // ---- decode + verify ----

    // Try candidate compressed-data start offsets; accept the first decode whose Adler-32 matches the header.
    private static byte[]? TryDecodeVerified(
        byte[] file, PeView pe, PackHeader h, StringBuilder log, CancellationToken cancellationToken)
    {
        foreach (int start in CandidateStarts(file, pe, h))
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (start < 0 || (long)start + h.CLen > file.Length) continue;
            if (Adler32(file, start, (int)h.CLen, cancellationToken) != h.CAdler) continue;
            log.AppendLine($"  Compressed payload checksum verified at file offset 0x{start:X}.");
            byte[]? plain = Decode(
                h.Method, file, start, (int)h.CLen, (int)h.ULen, cancellationToken);
            if (plain is null || plain.Length != h.ULen) continue;
            if (Adler32(plain, 0, plain.Length, cancellationToken) == h.UAdler) return plain;
        }
        return null;
    }

    // Compressed data usually lives in the packed section (UPX1) and starts at/after a small block header; the
    // Adler gate lets us just try a handful of offsets rather than model the exact block structure.
    private static IEnumerable<int> CandidateStarts(byte[] file, PeView pe, PackHeader h)
    {
        var seen = new HashSet<int>();
        int afterHeader = h.Offset + 32;
        if (afterHeader >= 0 && afterHeader < file.Length && seen.Add(afterHeader))
            yield return afterHeader;
        foreach (var s in pe.Sections)
        {
            if (s.PointerToRawData == 0 || s.SizeOfRawData == 0) continue;
            bool packed = s.Name.StartsWith("UPX", StringComparison.OrdinalIgnoreCase) || s.SizeOfRawData >= h.CLen;
            if (!packed) continue;
            int baseOff = (int)s.PointerToRawData;
            foreach (int delta in new[] { 0, 4, 8, 12, 16, 20, 24, 32 })
                if (seen.Add(baseOff + delta)) yield return baseOff + delta;
        }
        // Also just before the PackHeader (c_len bytes back), a common layout.
        int beforeHdr = h.Offset - (int)h.CLen;
        if (beforeHdr >= 0 && seen.Add(beforeHdr)) yield return beforeHdr;
    }

    private static byte[]? Decode(
        byte method, byte[] src, int off, int len, int uLen, CancellationToken cancellationToken)
    {
        try
        {
            return method switch
            {
                M_NRV2B_8 or M_NRV2B_LE32 => Nrv2b(src, off, len, uLen, cancellationToken),
                M_NRV2D_8 or M_NRV2D_LE32 => Nrv2d(src, off, len, uLen, cancellationToken),
                M_NRV2E_8 or M_NRV2E_LE32 => Nrv2e(src, off, len, uLen, cancellationToken),
                M_LZMA => DecodeUpxLzma(src, off, len, uLen, cancellationToken),
                _ => null,
            };
        }
        catch (OperationCanceledException) { throw; }
        catch { return null; }
    }

    // UPX replaces the standard 5-byte properties with two compact bytes:
    //   byte 0: (lc + lp) << 3 | pb
    //   byte 1: lp << 4 | lc
    // The in-place decoder uses the complete output buffer as its history window, so synthesize a standard
    // property record using u_len as the dictionary size.
    private static byte[]? DecodeUpxLzma(
        byte[] src, int off, int len, int uLen, CancellationToken cancellationToken = default)
    {
        if (len < 3 || off < 0 || (long)off + len > src.Length || uLen <= 0) return null;
        int pb = src[off] & 7;
        int lp = src[off + 1] >> 4;
        int lc = src[off + 1] & 15;
        if (pb >= 5 || lp >= 5 || lc >= 9 || (src[off] >> 3) != lc + lp) return null;

        byte[] props = new byte[5];
        props[0] = (byte)((pb * 5 + lp) * 9 + lc);
        WriteU32(props, 1, (uint)uLen);
        return LzmaCodec.Decode(
            props, src, off + 2, len - 2, uLen, cancellationToken,
            requireInputFullyConsumed: true);
    }

    // ---- PE reconstruction ----

    private readonly record struct OriginalSection(
        uint VirtualAddress, uint VirtualSize, uint RawOffset, uint RawSize, uint Characteristics);

    private static bool TryReconstructPe(
        byte[] packedFile, PeView packedPe, PackHeader h, byte[] plain, StringBuilder log,
        CancellationToken cancellationToken,
        out byte[]? image, out uint entryRva, out bool canExecute)
    {
        cancellationToken.ThrowIfCancellationRequested();
        image = null;
        entryRva = 0;
        canExecute = false;
        if (plain.Length < 8) return false;

        int storedHeader = checked((int)U32(plain, plain.Length - 4));
        if (storedHeader < 0 || storedHeader > plain.Length - 24 ||
            U32(plain, storedHeader) != PeConstants.PeSignature)
        {
            log.AppendLine("  Decoded data has no valid stored original PE header.");
            return false;
        }

        ushort sectionCount = U16(plain, storedHeader + 6);
        ushort optionalSize = U16(plain, storedHeader + 20);
        int headerBytes = PeConstants.OptHeaderFromSig + optionalSize;
        long sectionTableEnd = (long)storedHeader + headerBytes +
                               (long)sectionCount * PeConstants.SectionHeaderSize;
        if (sectionCount == 0 || sectionCount > 96 || optionalSize < 0x60 || sectionTableEnd > plain.Length)
            return false;

        int opt = storedHeader + PeConstants.OptHeaderFromSig;
        ushort magic = U16(plain, opt);
        if (magic is not PeConstants.Pe32Magic and not PeConstants.Pe32PlusMagic) return false;
        uint fileAlignment = U32(plain, opt + PeConstants.Opt_FileAlignment);
        uint sizeOfHeaders = U32(plain, opt + PeConstants.Opt_SizeOfHeaders);
        uint sizeOfImage = U32(plain, opt + PeConstants.Opt_SizeOfImage);
        if (!IsPowerOfTwo(fileAlignment) || fileAlignment > 0x10000 ||
            sizeOfImage == 0 || sizeOfImage > (512u << 20))
            return false;

        int sectionBase = storedHeader + headerBytes;
        uint rvaMin = U32(plain, sectionBase + PeConstants.Sec_VirtualAddress);
        if (rvaMin == 0) return false;

        // The PackHeader checksum covers the still-filtered bytes. Undo the executable-code transform only after
        // that checksum has passed.
        byte[] recovered = (byte[])plain.Clone();
        if (!Unfilter(recovered, storedHeader, rvaMin, h, log, cancellationToken)) return false;

        int tableEndInOutput = checked(
            packedPe.PeOffset + headerBytes + sectionCount * PeConstants.SectionHeaderSize);
        if (sizeOfHeaders < tableEndInOutput ||
            (h.UFileSize != 0 && sizeOfHeaders > h.UFileSize))
        {
            log.AppendLine("  Stored SizeOfHeaders is inconsistent with the original section table.");
            return false;
        }

        var sections = new List<OriginalSection>(sectionCount);
        var rawRanges = new List<(ulong Start, ulong End)>();
        ulong required = sizeOfHeaders;
        for (int i = 0; i < sectionCount; i++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            int sh = sectionBase + i * PeConstants.SectionHeaderSize;
            var section = new OriginalSection(
                U32(recovered, sh + PeConstants.Sec_VirtualAddress),
                U32(recovered, sh + PeConstants.Sec_VirtualSize),
                U32(recovered, sh + PeConstants.Sec_PointerToRawData),
                U32(recovered, sh + PeConstants.Sec_SizeOfRawData),
                U32(recovered, sh + PeConstants.Sec_Characteristics));
            sections.Add(section);

            ulong virtualSpan = Math.Max(section.VirtualSize, section.RawSize);
            if (section.VirtualAddress < rvaMin ||
                (ulong)section.VirtualAddress + virtualSpan > sizeOfImage)
            {
                log.AppendLine($"  Section {i} has an invalid virtual range.");
                return false;
            }

            if (section.RawOffset == 0 || section.RawSize == 0)
            {
                if (section.RawOffset != 0 || section.RawSize != 0)
                {
                    log.AppendLine($"  Section {i} has an incomplete raw-data range.");
                    return false;
                }
                continue;
            }

            if (section.RawOffset < sizeOfHeaders ||
                section.RawOffset % fileAlignment != 0 ||
                section.RawSize % fileAlignment != 0)
            {
                log.AppendLine($"  Section {i} has an invalid or unaligned raw-data range.");
                return false;
            }

            ulong src = (ulong)section.VirtualAddress - rvaMin;
            ulong srcEnd = src + section.RawSize;
            ulong rawEnd = (ulong)section.RawOffset + section.RawSize;
            if (srcEnd > (ulong)recovered.Length)
            {
                log.AppendLine($"  Section {i} exceeds the decoded RVA buffer.");
                return false;
            }
            foreach (var range in rawRanges)
            {
                if ((ulong)section.RawOffset < range.End && rawEnd > range.Start)
                {
                    log.AppendLine($"  Section {i} overlaps another raw section.");
                    return false;
                }
            }
            rawRanges.Add((section.RawOffset, rawEnd));
            required = Math.Max(required, rawEnd);
        }

        uint storedEntry = U32(recovered, opt + PeConstants.Opt_AddressOfEntryPoint);
        if (storedEntry != 0)
        {
            bool entryMapped = sections.Any(s =>
            {
                ulong span = Math.Max(s.VirtualSize, s.RawSize);
                bool executable = (s.Characteristics &
                    (PeConstants.SCN_MEM_EXECUTE | PeConstants.SCN_CNT_CODE)) != 0;
                return executable && storedEntry >= s.VirtualAddress &&
                       (ulong)storedEntry < (ulong)s.VirtualAddress + span;
            });
            if (!entryMapped)
            {
                log.AppendLine("  Stored entry point is not inside an executable section.");
                return false;
            }
        }
        if (h.UFileSize != 0)
        {
            if (required > h.UFileSize)
            {
                log.AppendLine("  Stored sections exceed the original UPX u_file_size.");
                return false;
            }
            required = h.UFileSize;
        }

        bool runtimeMetadataReady = false;
        byte[] runtimeRecovered = (byte[])recovered.Clone();
        if (TryRebuildRuntimeMetadata(
                packedFile, packedPe, runtimeRecovered, storedHeader, sectionTableEnd,
                rvaMin, sections, log, cancellationToken))
        {
            recovered = runtimeRecovered;
            runtimeMetadataReady = true;
        }

        // UPX's u_file_size excludes the overlay. Determine the latter before allocating so it is appended rather
        // than overwriting the tail of the reconstructed image.
        long packedImageEnd = 0;
        foreach (var s in packedPe.Sections)
            packedImageEnd = Math.Max(packedImageEnd, (long)s.PointerToRawData + s.SizeOfRawData);
        packedImageEnd = AlignUp(packedImageEnd, packedPe.FileAlignment);
        int overlaySize = packedImageEnd <= packedFile.Length ? packedFile.Length - (int)packedImageEnd : 0;
        ulong totalRequired = checked(required + (uint)overlaySize);
        if (totalRequired > 512u << 20) return false;

        var output = new byte[(int)totalRequired];
        int dosBytes = Math.Min(packedPe.PeOffset, packedFile.Length);
        Array.Copy(packedFile, 0, output, 0, dosBytes);
        Array.Copy(recovered, storedHeader, output, packedPe.PeOffset,
            headerBytes + sectionCount * PeConstants.SectionHeaderSize);

        for (int i = 0; i < sections.Count; i++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var section = sections[i];
            if (section.RawOffset == 0) continue;
            int src = checked((int)(section.VirtualAddress - rvaMin));
            Array.Copy(
                recovered, src, output, (int)section.RawOffset, (int)section.RawSize);
        }

        // UPX leaves the input overlay uncompressed. Preserve it at the end of the original-size output.
        if (overlaySize > 0 && overlaySize <= output.Length)
            Array.Copy(packedFile, (int)packedImageEnd, output, output.Length - overlaySize, overlaySize);

        cancellationToken.ThrowIfCancellationRequested();
        if (!PeView.TryParse(output, out var rebuilt) ||
            rebuilt.Sections.Count != sectionCount ||
            rebuilt.SizeOfImage != sizeOfImage ||
            rebuilt.EntryRva != storedEntry)
            return false;
        if (runtimeMetadataReady)
        {
            canExecute = ValidateSerializedDirectories(
                recovered, output, rebuilt, rvaMin, log, cancellationToken);
            if (!canExecute)
                log.AppendLine(
                    "  Runtime metadata did not survive the original raw-file layout; output is analysis-only.");
        }
        image = output;
        entryRva = rebuilt.EntryRva;
        return true;
    }

    private static bool ValidateSerializedDirectories(
        byte[] recovered, byte[] output, PeView outputPe, uint rvaMin,
        StringBuilder log, CancellationToken cancellationToken)
    {
        int opt = outputPe.PeOffset + PeConstants.OptHeaderFromSig;
        int directoryBase = opt + PeConstants.DataDirBaseOffset(outputPe.Is64);
        uint count = Math.Min(outputPe.NumberOfRvaAndSizes, 16);
        for (int index = 0; (uint)index < count; index++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!TryGetDirectory(
                    output, directoryBase, count, index, out uint address, out uint size))
                return false;
            if (address == 0 && size == 0) continue;
            if (address == 0 || size == 0 || size > int.MaxValue)
            {
                log.AppendLine($"  Data directory {index} has an incomplete or oversized range.");
                return false;
            }

            // IMAGE_DIRECTORY_ENTRY_SECURITY is the sole file-offset directory.
            if (index == 4)
            {
                if ((ulong)address + size > (ulong)output.Length)
                {
                    log.AppendLine("  Certificate directory is outside the reconstructed file.");
                    return false;
                }
                continue;
            }

            if (!TryPackedRvaToRaw(
                    outputPe, output.Length, address, (int)size, out int raw) ||
                !TryRvaIndex(address, rvaMin, recovered.Length, out int virtualOffset) ||
                (ulong)virtualOffset + size > (ulong)recovered.Length ||
                !output.AsSpan(raw, (int)size)
                    .SequenceEqual(recovered.AsSpan(virtualOffset, (int)size)))
            {
                log.AppendLine(
                    $"  Data directory {index} is not fully represented by the serialized raw sections.");
                return false;
            }
        }
        return true;
    }

    // Mirrors UPX PeFile::unpack0 after decompression. The compact extra-info record immediately following
    // the stored section table points at the preprocessed imports and relocations; resources that UPX kept
    // outside the compressed block live in the packed PE's last data section.
    private static bool TryRebuildRuntimeMetadata(
        byte[] packedFile, PeView packedPe, byte[] recovered, int storedHeader, long extraStart,
        uint rvaMin, IReadOnlyList<OriginalSection> originalSections,
        StringBuilder log, CancellationToken cancellationToken)
    {
        try
        {
            int extra = checked((int)extraStart);
            int opt = storedHeader + PeConstants.OptHeaderFromSig;
            bool is64 = U16(recovered, opt) == PeConstants.Pe32PlusMagic;
            int dataDirBase = opt + PeConstants.DataDirBaseOffset(is64);
            uint directoryCount = U32(
                recovered, opt + PeConstants.NumberOfRvaAndSizesOffset(is64));
            if (directoryCount > 16) directoryCount = 16;

            if (TryGetDirectory(recovered, dataDirBase, directoryCount, PeConstants.DirImport,
                    out uint importRva, out uint importSize) &&
                importRva != 0 && importSize > 20)
            {
                if (!TryRebuildImports(
                        packedFile, packedPe, recovered, ref extra, rvaMin, importRva, importSize,
                        is64, log, cancellationToken))
                    return false;
            }

            ushort coffFlags = U16(
                recovered, storedHeader + PeConstants.FileHeaderFromSig + PeConstants.Coff_Characteristics);
            if (TryGetDirectory(recovered, dataDirBase, directoryCount, PeConstants.DirBaseReloc,
                    out uint relocRva, out uint relocSize) &&
                relocRva != 0 && relocSize != 0 &&
                (coffFlags & PeConstants.IMAGE_FILE_RELOCS_STRIPPED) == 0)
            {
                ulong imageBase = is64
                    ? U64(recovered, opt + PeConstants.Opt_ImageBase64)
                    : U32(recovered, opt + PeConstants.Opt_ImageBase32);
                if (relocSize == 8)
                {
                    if (!TryRvaIndex(relocRva, rvaMin, recovered.Length, out int relocAt) ||
                        relocAt + 8 > recovered.Length)
                        return false;
                    Array.Clear(recovered, relocAt, 8);
                    WriteU32(recovered, relocAt + 4, 8);
                    log.AppendLine("  Restored UPX's empty eight-byte base-relocation block.");
                }
                else if (!TryRebuildRelocations(
                             recovered, ref extra, rvaMin, relocRva, relocSize, imageBase, is64,
                             dataDirBase, log, cancellationToken))
                {
                    return false;
                }
            }

            if (TryGetDirectory(recovered, dataDirBase, directoryCount, PeConstants.DirExport,
                    out uint exportRva, out uint exportSize) &&
                exportRva != 0 && exportSize != 0)
            {
                int packedOpt = packedPe.PeOffset + PeConstants.OptHeaderFromSig;
                int packedDirs = packedOpt + PeConstants.DataDirBaseOffset(packedPe.Is64);
                uint packedCount = Math.Min(packedPe.NumberOfRvaAndSizes, 16);
                TryGetDirectory(
                    packedFile, packedDirs, packedCount, PeConstants.DirExport,
                    out uint packedExportRva, out _);
                if (packedExportRva != exportRva)
                {
                    log.AppendLine("  UPX export reconstruction for this layout is not supported.");
                    return false;
                }
            }

            if (TryGetDirectory(recovered, dataDirBase, directoryCount, PeConstants.DirResource,
                    out uint resourceRva, out uint resourceSize) &&
                resourceRva != 0 && resourceSize != 0)
            {
                int packedOpt = packedPe.PeOffset + PeConstants.OptHeaderFromSig;
                int packedDirs = packedOpt + PeConstants.DataDirBaseOffset(packedPe.Is64);
                uint packedCount = Math.Min(packedPe.NumberOfRvaAndSizes, 16);
                if (!TryGetDirectory(
                        packedFile, packedDirs, packedCount, PeConstants.DirResource,
                        out uint packedResourceRva, out uint packedResourceSize) ||
                    packedResourceRva == 0 || packedResourceSize == 0 ||
                    !TryReadU16(recovered, ref extra, out ushort iconDirectoryCount) ||
                    !TryRebuildResources(
                        packedFile, packedPe, recovered, rvaMin, resourceRva, resourceSize,
                        packedResourceRva, packedResourceSize, iconDirectoryCount, log,
                        originalSections, cancellationToken))
                    return false;
            }

            // UPX deliberately clears these after rebuilding the import descriptors.
            ClearDirectory(recovered, dataDirBase, directoryCount, PeConstants.DirIat);
            ClearDirectory(recovered, dataDirBase, directoryCount, PeConstants.DirBoundImport);
            WriteU32(recovered, opt + PeConstants.Opt_CheckSum, 0);

            // Current UPX appends the stored-header offset as an extra-info integrity marker.
            if (extra + 4 > recovered.Length || U32(recovered, extra) != (uint)storedHeader)
            {
                log.AppendLine("  UPX extra-info trailer is missing or inconsistent.");
                return false;
            }

            return true;
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex)
        {
            log.AppendLine("  Runtime metadata rebuild declined: " + ex.Message);
            return false;
        }
    }

    private enum ImportKind { Name, Ordinal, PackedOrdinal }

    private sealed record ImportItem(ImportKind Kind, byte[]? Name, ushort Ordinal, uint PackedRva);

    private sealed record ImportDll(byte[] Name, uint IatRva, List<ImportItem> Items);

    private static bool TryRebuildImports(
        byte[] packedFile, PeView packedPe, byte[] recovered, ref int extra, uint rvaMin,
        uint importRva, uint importSize, bool is64, StringBuilder log,
        CancellationToken cancellationToken)
    {
        if (!TryReadU32(recovered, ref extra, out uint importDataOffset) ||
            !TryReadU32(recovered, ref extra, out uint namesRva) ||
            importDataOffset >= recovered.Length)
            return false;

        int packedOpt = packedPe.PeOffset + PeConstants.OptHeaderFromSig;
        int packedDirs = packedOpt + PeConstants.DataDirBaseOffset(packedPe.Is64);
        if (!TryGetDirectory(
                packedFile, packedDirs, Math.Min(packedPe.NumberOfRvaAndSizes, 16),
                PeConstants.DirImport, out uint packedImportRva, out _) ||
            packedImportRva == 0)
            return false;

        int p = (int)importDataOffset;
        var dlls = new List<ImportDll>();
        uint descriptorSlots = importSize / 20;
        if (descriptorSlots < 2) return false; // at least one DLL plus the null descriptor
        int maxDlls = (int)Math.Min(descriptorSlots - 1, 4096u);
        while (p + 4 <= recovered.Length && U32(recovered, p) != 0)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (dlls.Count >= maxDlls || p + 8 > recovered.Length) return false;
            uint dllNameRva = U32(recovered, p);
            uint iatRva = checked(U32(recovered, p + 4) + rvaMin);
            p += 8;
            if (!TryReadPackedAscii(
                    packedFile, packedPe, checked(packedImportRva + dllNameRva),
                    out byte[] dllName))
                return false;

            var items = new List<ImportItem>();
            while (p < recovered.Length && recovered[p] != 0)
            {
                byte kind = recovered[p];
                if (kind == 1)
                {
                    if (!TryReadAscii(recovered, p + 1, out byte[] name, out int next)) return false;
                    items.Add(new ImportItem(ImportKind.Name, name, 0, 0));
                    p = next;
                }
                else if (kind == 0xFF)
                {
                    if (p + 3 > recovered.Length) return false;
                    items.Add(new ImportItem(ImportKind.Ordinal, null, U16(recovered, p + 1), 0));
                    p += 3;
                }
                else
                {
                    if (p + 5 > recovered.Length) return false;
                    items.Add(new ImportItem(
                        ImportKind.PackedOrdinal, null, 0, U32(recovered, p + 1)));
                    p += 5;
                }
            }
            if (p >= recovered.Length) return false;
            p++; // per-DLL terminator
            dlls.Add(new ImportDll(dllName, iatRva, items));
        }
        if (p + 4 > recovered.Length) return false;

        int descriptor;
        if (!TryRvaIndex(importRva, rvaMin, recovered.Length, out descriptor)) return false;
        if (importSize > int.MaxValue ||
            (long)descriptor + importSize > recovered.Length)
            return false;
        int thunkSize = is64 ? 8 : 4;
        ulong ordinalMask = is64 ? 1UL << 63 : 1UL << 31;

        int dllNamesCursor = 0;
        int importedNamesStart = 0;
        int importedNamesCursor = 0;
        if (namesRva != 0)
        {
            if (!TryRvaIndex(namesRva, rvaMin, recovered.Length, out dllNamesCursor)) return false;
            long totalDllNameBytes = dlls.Sum(d => (long)d.Name.Length);
            if (totalDllNameBytes > int.MaxValue) return false;
            importedNamesStart = checked(dllNamesCursor + AlignUp((int)totalDllNameBytes, 2));
            importedNamesCursor = importedNamesStart;
        }

        for (int dllIndex = 0; dllIndex < dlls.Count; dllIndex++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ImportDll dll = dlls[dllIndex];
            int desc = checked(descriptor + dllIndex * 20);
            if (desc < 0 || desc + 20 > recovered.Length) return false;

            if (namesRva != 0)
            {
                if (!TryCopy(recovered, dllNamesCursor, dll.Name)) return false;
                WriteU32(recovered, desc + 12, checked((uint)(rvaMin + dllNamesCursor)));
                dllNamesCursor += dll.Name.Length;
            }
            else
            {
                uint existingNameRva = U32(recovered, desc + 12);
                if (!TryRvaIndex(existingNameRva, rvaMin, recovered.Length, out int nameIndex) ||
                    !TryCopy(recovered, nameIndex, dll.Name))
                    return false;
            }

            WriteU32(recovered, desc + 16, dll.IatRva);
            if (!is64) WriteU32(recovered, desc, dll.IatRva);
            if (!TryRvaIndex(dll.IatRva, rvaMin, recovered.Length, out int thunk)) return false;

            for (int itemIndex = 0; itemIndex < dll.Items.Count; itemIndex++)
            {
                ImportItem item = dll.Items[itemIndex];
                int thunkAt = checked(thunk + itemIndex * thunkSize);
                if (thunkAt < 0 || thunkAt + thunkSize > recovered.Length) return false;

                if (item.Kind == ImportKind.Name)
                {
                    byte[] name = item.Name!;
                    if (namesRva != 0)
                    {
                        if (((importedNamesCursor - importedNamesStart) & 1) != 0)
                            importedNamesCursor--;
                        if (importedNamesCursor < 0 ||
                            importedNamesCursor + 2 + name.Length > recovered.Length)
                            return false;
                        recovered[importedNamesCursor] = 0;
                        recovered[importedNamesCursor + 1] = 0;
                        Array.Copy(name, 0, recovered, importedNamesCursor + 2, name.Length);
                        WriteThunk(
                            recovered, thunkAt, checked((ulong)(rvaMin + importedNamesCursor)), is64);
                        importedNamesCursor += 2 + name.Length;
                    }
                    else
                    {
                        ulong nameRva = ReadThunk(recovered, thunkAt, is64);
                        if (nameRva > uint.MaxValue ||
                            !TryRvaIndex((uint)nameRva, rvaMin, recovered.Length, out int nameAt) ||
                            nameAt + 2 > recovered.Length ||
                            !TryCopy(recovered, nameAt + 2, name))
                            return false;
                    }
                }
                else if (item.Kind == ImportKind.Ordinal)
                {
                    WriteThunk(recovered, thunkAt, ordinalMask | item.Ordinal, is64);
                }
                else
                {
                    if (!TryPackedRvaToRaw(
                            packedPe, packedFile.Length,
                            checked(packedImportRva + item.PackedRva), thunkSize,
                            out int packedThunk))
                        return false;
                    WriteThunk(
                        recovered, thunkAt,
                        is64 ? U64(packedFile, packedThunk) : U32(packedFile, packedThunk), is64);
                }
            }

            int nullThunk = checked(thunk + dll.Items.Count * thunkSize);
            if (nullThunk < 0 || nullThunk + thunkSize > recovered.Length) return false;
            WriteThunk(recovered, nullThunk, 0, is64);
        }

        int finalDescriptor = checked(descriptor + dlls.Count * 20);
        if (finalDescriptor < descriptor ||
            (long)finalDescriptor + 20 > (long)descriptor + importSize ||
            finalDescriptor + 20 > recovered.Length)
            return false;
        Array.Clear(recovered, finalDescriptor, 20);
        log.AppendLine($"  Rebuilt {dlls.Count} UPX import descriptor(s).");
        return true;
    }

    private static bool TryRebuildRelocations(
        byte[] recovered, ref int extra, uint rvaMin, uint relocRva, uint relocCapacity,
        ulong imageBase, bool is64, int dataDirBase, StringBuilder log,
        CancellationToken cancellationToken)
    {
        if (!TryReadU32(recovered, ref extra, out uint compressedRelocs) ||
            compressedRelocs == 0 || compressedRelocs >= recovered.Length ||
            extra >= recovered.Length)
            return false;
        byte bigRelocs = recovered[extra++];
        if ((bigRelocs & 6) != 0) return false;

        int fix = (int)compressedRelocs;
        uint pc = unchecked((uint)-4);
        var relocations = new List<uint>();
        while (fix < recovered.Length && recovered[fix] != 0)
        {
            if ((relocations.Count & 0xFFF) == 0) cancellationToken.ThrowIfCancellationRequested();
            uint delta;
            byte first = recovered[fix];
            if (first < 0xF0)
            {
                delta = first;
                fix++;
            }
            else
            {
                if (fix + 3 > recovered.Length) return false;
                delta = (uint)((first & 0x0F) * 0x10000 + U16(recovered, fix + 1));
                fix += 3;
                if (delta == 0)
                {
                    if (fix + 4 > recovered.Length) return false;
                    delta = U32(recovered, fix);
                    fix += 4;
                }
            }
            if (delta < 4) return false;
            pc = unchecked(pc + delta);
            int valueSize = is64 ? 8 : 4;
            if ((ulong)pc + (uint)valueSize > (ulong)recovered.Length) return false;

            Array.Reverse(recovered, (int)pc, valueSize);
            if (is64)
                WriteU64(recovered, (int)pc, unchecked(U64(recovered, (int)pc) + imageBase + rvaMin));
            else
                WriteU32(recovered, (int)pc,
                    unchecked(U32(recovered, (int)pc) + (uint)imageBase + rvaMin));
            relocations.Add(checked(rvaMin + pc));
        }
        if (fix >= recovered.Length) return false;

        byte[] blocks = BuildRelocationBlocks(relocations, is64 ? 10 : 3);
        if (blocks.Length > relocCapacity ||
            !TryRvaIndex(relocRva, rvaMin, recovered.Length, out int relocAt) ||
            relocAt + blocks.Length > recovered.Length)
            return false;
        Array.Copy(blocks, 0, recovered, relocAt, blocks.Length);
        if (blocks.Length < relocCapacity &&
            (ulong)relocAt + relocCapacity <= (ulong)recovered.Length)
            Array.Clear(recovered, relocAt + blocks.Length, (int)relocCapacity - blocks.Length);
        WriteU32(recovered, dataDirBase + PeConstants.DirBaseReloc * 8 + 4, (uint)blocks.Length);
        log.AppendLine($"  Rebuilt {relocations.Count} base relocation(s) into 0x{blocks.Length:X} bytes.");
        return true;
    }

    private sealed record ResourceLeaf(int DataEntryOffset, uint PackedDataRva, uint Size, uint Type);

    private static bool TryRebuildResources(
        byte[] packedFile, PeView packedPe, byte[] recovered, uint rvaMin,
        uint resourceRva, uint resourceSize, uint packedResourceRva, uint packedResourceSize,
        ushort iconDirectoryCount, StringBuilder log,
        IReadOnlyList<OriginalSection> originalSections, CancellationToken cancellationToken)
    {
        if (!TryPackedRvaToRaw(
                packedPe, packedFile.Length, packedResourceRva, 16, out int packedResourceRaw))
            return false;

        var leaves = new List<ResourceLeaf>();
        var visited = new HashSet<int>();
        int directoryExtent = 0;
        if (!TryParseResourceDirectory(
                packedFile, packedResourceRaw, (int)Math.Min(packedResourceSize, int.MaxValue),
                0, 0, 0, visited, leaves, ref directoryExtent, cancellationToken))
            return false;
        directoryExtent = AlignUp(directoryExtent, 4);
        if (directoryExtent <= 0 ||
            directoryExtent > packedResourceSize ||
            (long)packedResourceRaw + directoryExtent > packedFile.Length ||
            !TryRvaIndex(resourceRva, rvaMin, recovered.Length, out int resourceAt) ||
            (long)resourceAt + directoryExtent > recovered.Length)
            return false;

        bool foundResourceSection = false;
        OriginalSection resourceSection = default;
        foreach (OriginalSection section in originalSections)
        {
            ulong span = Math.Max(section.VirtualSize, section.RawSize);
            if (resourceRva < section.VirtualAddress ||
                (ulong)resourceRva >= (ulong)section.VirtualAddress + span)
                continue;
            resourceSection = section;
            foundResourceSection = true;
            break;
        }
        if (!foundResourceSection || resourceSection.RawSize == 0 ||
            resourceRva < resourceSection.VirtualAddress)
            return false;
        ulong resourceDirectoryEnd = (ulong)resourceRva + resourceSize;
        ulong resourceVirtualEnd = (ulong)resourceSection.VirtualAddress +
                                   Math.Max(resourceSection.VirtualSize, resourceSection.RawSize);
        ulong resourceRawEnd = (ulong)resourceSection.VirtualAddress + resourceSection.RawSize;
        ulong restoredLimit = Math.Min(
            (ulong)resourceRva + AlignUp(resourceSize, 4), resourceRawEnd);
        if (resourceDirectoryEnd > resourceVirtualEnd ||
            (ulong)resourceRva + (uint)directoryExtent > resourceRawEnd)
            return false;

        byte[] directory = new byte[directoryExtent];
        Array.Copy(packedFile, packedResourceRaw, directory, 0, directory.Length);
        bool iconPatched = false;
        int restored = 0;
        var restoredRanges = new List<(ulong Start, ulong End, int PackedData, int Size)>();
        foreach (ResourceLeaf leaf in leaves)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (leaf.PackedDataRva <= packedResourceRva) continue;
            uint alignedSize = AlignUp(leaf.Size, 4);
            if (!TryPackedRvaToRawBounds(
                    packedPe, packedFile.Length, leaf.PackedDataRva, checked((int)alignedSize),
                    out int packedData, out int packedRawStart, out _) ||
                packedData - packedRawStart < 4)
                return false;
            uint originalRva = U32(packedFile, packedData - 4);
            ulong originalEnd = (ulong)originalRva + alignedSize;
            if (!TryRvaIndex(originalRva, rvaMin, recovered.Length, out int originalAt) ||
                (ulong)originalAt + alignedSize > (ulong)recovered.Length ||
                originalRva < resourceRva || originalEnd > restoredLimit ||
                ((ulong)originalRva < (ulong)resourceRva + (uint)directoryExtent &&
                 originalEnd > resourceRva) ||
                leaf.DataEntryOffset < 0 || leaf.DataEntryOffset + 4 > directory.Length)
                return false;
            foreach ((ulong Start, ulong End, int PackedData, int Size) range in restoredRanges)
            {
                bool exactAlias = range.Start == originalRva && range.End == originalEnd;
                if (exactAlias)
                {
                    if (range.Size != (int)alignedSize ||
                        !packedFile.AsSpan(range.PackedData, range.Size)
                            .SequenceEqual(packedFile.AsSpan(packedData, (int)alignedSize)))
                        return false;
                    continue;
                }
                if ((ulong)originalRva < range.End && originalEnd > range.Start)
                    return false;
            }
            restoredRanges.Add((originalRva, originalEnd, packedData, (int)alignedSize));
            Array.Copy(packedFile, packedData, recovered, originalAt, (int)alignedSize);
            WriteU32(directory, leaf.DataEntryOffset, originalRva);
            if (!iconPatched && iconDirectoryCount != 0 && leaf.Type == 14 &&
                originalAt + 6 <= recovered.Length)
            {
                WriteU16(recovered, originalAt + 4, iconDirectoryCount);
                iconPatched = true;
            }
            restored++;
        }

        Array.Copy(directory, 0, recovered, resourceAt, directory.Length);
        log.AppendLine(
            $"  Rebuilt the resource directory and restored {restored} non-compressed resource payload(s).");
        return true;
    }

    private static bool TryParseResourceDirectory(
        byte[] file, int baseRaw, int available, int relative, int level, uint rootType,
        HashSet<int> visited, List<ResourceLeaf> leaves, ref int extent,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (level > 2 || relative < 0 || relative > available - 16 || !visited.Add(relative))
            return false;
        int at = baseRaw + relative;
        int count = U16(file, at + 12) + U16(file, at + 14);
        long directoryEnd = (long)relative + 16L + count * 8L;
        if (count > 0x10000 || directoryEnd > available) return false;
        extent = Math.Max(extent, (int)directoryEnd);

        for (int i = 0; i < count; i++)
        {
            int entry = at + 16 + i * 8;
            uint name = U32(file, entry);
            uint child = U32(file, entry + 4);
            uint type = level == 0 && (name & 0x8000_0000) == 0 ? name : rootType;
            if ((name & 0x8000_0000) != 0)
            {
                int nameOffset = checked((int)(name & 0x7FFF_FFFF));
                if (nameOffset < 0 || nameOffset > available - 2) return false;
                int nameBytes = checked(2 + U16(file, baseRaw + nameOffset) * 2);
                if (nameOffset + nameBytes > available) return false;
                extent = Math.Max(extent, nameOffset + nameBytes);
            }

            bool isDirectory = (child & 0x8000_0000) != 0;
            int childOffset = checked((int)(child & 0x7FFF_FFFF));
            if (level < 2)
            {
                if (!isDirectory ||
                    !TryParseResourceDirectory(
                        file, baseRaw, available, childOffset, level + 1, type,
                        visited, leaves, ref extent, cancellationToken))
                    return false;
            }
            else
            {
                if (isDirectory || childOffset < 0 || childOffset > available - 16) return false;
                extent = Math.Max(extent, childOffset + 16);
                int dataEntry = baseRaw + childOffset;
                leaves.Add(new ResourceLeaf(
                    childOffset, U32(file, dataEntry), U32(file, dataEntry + 4), type));
            }
        }
        return true;
    }

    private static byte[] BuildRelocationBlocks(List<uint> relocations, int type)
    {
        relocations.Sort();
        using var output = new MemoryStream();
        int index = 0;
        while (index < relocations.Count)
        {
            uint page = relocations[index] & 0xFFFFF000;
            int first = index;
            while (index < relocations.Count && (relocations[index] & 0xFFFFF000) == page)
                index++;
            int entries = index - first;
            int size = AlignUp(8 + entries * 2, 4);
            byte[] block = new byte[size];
            WriteU32(block, 0, page);
            WriteU32(block, 4, (uint)size);
            for (int i = 0; i < entries; i++)
                WriteU16(block, 8 + i * 2,
                    checked((ushort)(((uint)type << 12) | (relocations[first + i] & 0xFFF))));
            output.Write(block);
        }
        return output.ToArray();
    }

    private static bool TryGetDirectory(
        byte[] data, int directoryBase, uint count, int index, out uint rva, out uint size)
    {
        rva = size = 0;
        if (index < 0 || (uint)index >= count) return false;
        int at = checked(directoryBase + index * 8);
        if (at < 0 || at + 8 > data.Length) return false;
        rva = U32(data, at);
        size = U32(data, at + 4);
        return true;
    }

    private static void ClearDirectory(byte[] data, int directoryBase, uint count, int index)
    {
        if ((uint)index >= count) return;
        int at = directoryBase + index * 8;
        if (at >= 0 && at + 8 <= data.Length) Array.Clear(data, at, 8);
    }

    private static bool TryPackedRvaToRaw(
        PeView pe, int fileLength, uint rva, int size, out int raw)
    {
        return TryPackedRvaToRawBounds(
            pe, fileLength, rva, size, out raw, out _, out _);
    }

    private static bool TryPackedRvaToRawBounds(
        PeView pe, int fileLength, uint rva, int size,
        out int raw, out int rawStart, out int rawEnd)
    {
        raw = rawStart = rawEnd = 0;
        if (size < 0) return false;
        if (rva < pe.SizeOfHeaders)
        {
            if ((ulong)rva + (uint)size > (ulong)fileLength) return false;
            raw = (int)rva;
            rawStart = 0;
            rawEnd = (int)Math.Min(pe.SizeOfHeaders, (uint)fileLength);
            return true;
        }
        foreach (SectionHeader section in pe.Sections)
        {
            ulong span = Math.Max(section.VirtualSize, section.SizeOfRawData);
            if (rva < section.VirtualAddress ||
                (ulong)rva + (uint)size > (ulong)section.VirtualAddress + span)
                continue;
            ulong candidate = (ulong)section.PointerToRawData + rva - section.VirtualAddress;
            if (candidate + (uint)size > (ulong)fileLength ||
                candidate + (uint)size >
                (ulong)section.PointerToRawData + section.SizeOfRawData)
                return false;
            raw = (int)candidate;
            rawStart = (int)section.PointerToRawData;
            rawEnd = (int)Math.Min(
                (ulong)fileLength,
                (ulong)section.PointerToRawData + section.SizeOfRawData);
            return true;
        }
        return false;
    }

    private static bool TryReadPackedAscii(
        byte[] packedFile, PeView packedPe, uint rva, out byte[] value)
    {
        value = [];
        if (!TryPackedRvaToRawBounds(
                packedPe, packedFile.Length, rva, 1,
                out int raw, out _, out int rawEnd) ||
            !TryReadAscii(packedFile, raw, rawEnd, out value, out _))
            return false;
        return true;
    }

    private static bool TryReadAscii(byte[] data, int start, out byte[] value, out int next)
        => TryReadAscii(data, start, data.Length, out value, out next);

    private static bool TryReadAscii(
        byte[] data, int start, int endExclusive, out byte[] value, out int next)
    {
        value = [];
        next = start;
        if (start < 0 || start >= data.Length ||
            endExclusive <= start || endExclusive > data.Length)
            return false;
        int end = start;
        while (end < endExclusive && data[end] != 0 && end - start <= 0x10000) end++;
        if (end >= endExclusive || end - start > 0x10000) return false;
        value = new byte[end - start + 1];
        Array.Copy(data, start, value, 0, value.Length);
        next = end + 1;
        return true;
    }

    private static bool TryCopy(byte[] destination, int offset, byte[] source)
    {
        if (offset < 0 || (long)offset + source.Length > destination.Length) return false;
        Array.Copy(source, 0, destination, offset, source.Length);
        return true;
    }

    private static bool TryRvaIndex(uint rva, uint rvaMin, int length, out int index)
    {
        index = 0;
        if (rva < rvaMin || (ulong)rva - rvaMin >= (ulong)length) return false;
        index = (int)(rva - rvaMin);
        return true;
    }

    private static bool TryReadU16(byte[] data, ref int offset, out ushort value)
    {
        value = 0;
        if (offset < 0 || offset + 2 > data.Length) return false;
        value = U16(data, offset);
        offset += 2;
        return true;
    }

    private static bool TryReadU32(byte[] data, ref int offset, out uint value)
    {
        value = 0;
        if (offset < 0 || offset + 4 > data.Length) return false;
        value = U32(data, offset);
        offset += 4;
        return true;
    }

    private static ulong ReadThunk(byte[] data, int offset, bool is64) =>
        is64 ? U64(data, offset) : U32(data, offset);

    private static void WriteThunk(byte[] data, int offset, ulong value, bool is64)
    {
        if (is64) WriteU64(data, offset, value);
        else WriteU32(data, offset, (uint)value);
    }

    private static bool Unfilter(
        byte[] data, int storedHeader, uint rvaMin, PackHeader h, StringBuilder log,
        CancellationToken cancellationToken)
    {
        if (h.Filter == 0) return true;
        if (h.Filter != 0x49)
        {
            log.AppendLine($"  UPX filter 0x{h.Filter:X2} is not supported by the PE reconstructor.");
            return false;
        }

        int opt = storedHeader + PeConstants.OptHeaderFromSig;
        uint codeSize = U32(data, opt + 4);
        uint codeBase = U32(data, opt + 20);
        if (codeBase < rvaMin || codeSize < 6) return false;
        long start64 = (long)codeBase - rvaMin;
        if (start64 < 0 || start64 + codeSize > data.Length || codeSize > int.MaxValue) return false;

        int start = (int)start64;
        int size = (int)codeSize;
        uint addValue = (uint)start;
        uint cto = (uint)h.FilterCto << 24;
        int lastCall = 0;
        for (int i = 0; i < size - 5; i++)
        {
            if ((i & 0xFFF) == 0) cancellationToken.ThrowIfCancellationRequested();
            int p = start + i;
            bool branch = data[p] is 0xE8 or 0xE9;
            bool conditional = i != lastCall && i > 0 && data[p - 1] == 0x0F &&
                               data[p] is >= 0x80 and <= 0x8F;
            if (!branch && !conditional) continue;

            uint target = U32Be(data, p + 1);
            if (data[p + 1] != h.FilterCto) continue;
            WriteU32(data, p + 1, unchecked(target - (uint)i - 1 - addValue - cto));
            i += 4;
            lastCall = i + 1;
        }
        log.AppendLine($"  Reversed UPX filter 0x49 over 0x{codeSize:X} code bytes.");
        return true;
    }

    // ---- NRV decompressors (canonical UCL, byte-wise "_8" getbit; LE32 files fail the Adler gate and decline) ----

    // Canonical UCL bit reader: a sentinel bit rides the buffer; refills one byte at a time, MSB first.
    private sealed class BitIn
    {
        private uint _bb;
        public int Ip;
        private readonly byte[] _s;
        private readonly int _end;
        private readonly CancellationToken _cancellationToken;

        public BitIn(byte[] src, int off, int len, CancellationToken cancellationToken)
        {
            if (off < 0 || len < 0 || (long)off + len > src.Length)
                throw new ArgumentOutOfRangeException(nameof(len), "NRV input range is outside the source buffer.");
            _s = src;
            Ip = off;
            _end = off + len;
            _cancellationToken = cancellationToken;
        }

        public int GetBit()
        {
            if ((_bb & 0x7f) == 0 && Ip >= _end)
                throw new EndOfStreamException("Truncated NRV stream.");
            if ((Ip & 0xFFF) == 0) _cancellationToken.ThrowIfCancellationRequested();
            _bb = (_bb & 0x7f) != 0 ? _bb << 1 : (uint)(_s[Ip++] << 1) | 1;
            return (int)((_bb >> 8) & 1);
        }
        public byte NextByte()
        {
            if (Ip >= _end) throw new EndOfStreamException("Truncated NRV stream.");
            if ((Ip & 0xFFF) == 0) _cancellationToken.ThrowIfCancellationRequested();
            return _s[Ip++];
        }
    }

    private static byte[]? Nrv2b(
        byte[] src, int off, int len, int uLen, CancellationToken cancellationToken)
    {
        var dst = new byte[uLen];
        var b = new BitIn(src, off, len, cancellationToken);
        int op = 0; uint lastOff = 1;
        while (op < uLen)
        {
            if ((op & 0xFFF) == 0) cancellationToken.ThrowIfCancellationRequested();
            while (b.GetBit() != 0) { if (op >= uLen) return dst; dst[op++] = b.NextByte(); }
            uint mOff = 1;
            do { mOff = mOff * 2 + (uint)b.GetBit(); } while (b.GetBit() == 0);
            if (mOff == 2) mOff = lastOff;
            else
            {
                mOff = (mOff - 3) * 256 + b.NextByte();
                if (mOff == 0xffffffff) break;
                lastOff = ++mOff;
            }
            uint mLen = (uint)b.GetBit();
            mLen = mLen * 2 + (uint)b.GetBit();
            if (mLen == 0)
            {
                mLen = 1;
                do { mLen = mLen * 2 + (uint)b.GetBit(); } while (b.GetBit() == 0);
                mLen += 2;
            }
            mLen += mOff > 0xd00 ? 1u : 0u;
            if (!CopyMatch(dst, ref op, mOff, mLen + 1, uLen, cancellationToken)) return null;
        }
        return dst;
    }

    private static byte[]? Nrv2d(
        byte[] src, int off, int len, int uLen, CancellationToken cancellationToken)
    {
        var dst = new byte[uLen];
        var b = new BitIn(src, off, len, cancellationToken);
        int op = 0; uint lastOff = 1;
        while (op < uLen)
        {
            if ((op & 0xFFF) == 0) cancellationToken.ThrowIfCancellationRequested();
            while (b.GetBit() != 0) { if (op >= uLen) return dst; dst[op++] = b.NextByte(); }
            uint mOff = 1;
            for (; ; )
            {
                mOff = mOff * 2 + (uint)b.GetBit();
                if (b.GetBit() != 0) break;
                mOff = (mOff - 1) * 2 + (uint)b.GetBit();
            }
            uint mLen;
            if (mOff == 2) { mOff = lastOff; mLen = (uint)b.GetBit(); }
            else
            {
                mOff = (mOff - 3) * 256 + b.NextByte();
                if (mOff == 0xffffffff) break;
                mLen = (uint)(mOff & 1); mOff >>= 1; lastOff = ++mOff;
            }
            mLen = mLen * 2 + (uint)b.GetBit();
            if (mLen == 0)
            {
                mLen = 1;
                do { mLen = mLen * 2 + (uint)b.GetBit(); } while (b.GetBit() == 0);
                mLen += 2;
            }
            mLen += (mOff > 0x500 ? 1u : 0u) + (mOff > 0xd00 ? 1u : 0u);
            if (!CopyMatch(dst, ref op, mOff, mLen + 1, uLen, cancellationToken)) return null;
        }
        return dst;
    }

    private static byte[]? Nrv2e(
        byte[] src, int off, int len, int uLen, CancellationToken cancellationToken)
    {
        var dst = new byte[uLen];
        var b = new BitIn(src, off, len, cancellationToken);
        int op = 0; uint lastOff = 1;
        while (op < uLen)
        {
            if ((op & 0xFFF) == 0) cancellationToken.ThrowIfCancellationRequested();
            while (b.GetBit() != 0) { if (op >= uLen) return dst; dst[op++] = b.NextByte(); }
            uint mOff = 1;
            for (; ; )
            {
                mOff = mOff * 2 + (uint)b.GetBit();
                if (b.GetBit() != 0) break;
                mOff = (mOff - 1) * 2 + (uint)b.GetBit();
            }
            uint mLen;
            if (mOff == 2) { mOff = lastOff; mLen = (uint)b.GetBit(); }
            else
            {
                mOff = (mOff - 3) * 256 + b.NextByte();
                if (mOff == 0xffffffff) break;
                mLen = (uint)(mOff & 1); mOff >>= 1; lastOff = ++mOff;
            }
            if (mLen != 0) mLen = (uint)(1 + b.GetBit());
            else if (b.GetBit() != 0) mLen = (uint)(3 + b.GetBit());
            else
            {
                mLen = 3;
                do { mLen = mLen * 2 + (uint)b.GetBit(); } while (b.GetBit() == 0);
                mLen += 3;
            }
            mLen += mOff > 0x500 ? 1u : 0u;
            if (!CopyMatch(dst, ref op, mOff, mLen + 1, uLen, cancellationToken)) return null;
        }
        return dst;
    }

    private static bool CopyMatch(
        byte[] dst, ref int op, uint mOff, uint count, int uLen,
        CancellationToken cancellationToken)
    {
        if (count > (uint)(uLen - op)) return false;
        int mPos = op - (int)mOff;
        if (mPos < 0) return false;
        for (uint i = 0; i < count; i++)
        {
            if ((i & 0xFFF) == 0) cancellationToken.ThrowIfCancellationRequested();
            dst[op++] = dst[mPos++];
        }
        return true;
    }

    // ---- checksums / helpers ----

    private static uint Adler32(
        byte[] data, int offset, int count, CancellationToken cancellationToken)
    {
        const uint mod = 65521;
        uint a = 1, s = 0;
        int end = checked(offset + count);
        for (int i = offset; i < end; i++)
        {
            if (((i - offset) & 0xFFF) == 0) cancellationToken.ThrowIfCancellationRequested();
            a += data[i];
            s += a;
            if ((i - offset) % 5552 == 5551) { a %= mod; s %= mod; }
        }
        a %= mod;
        s %= mod;
        return (s << 16) | a;
    }

    private static int IndexOf(
        byte[] hay, byte[] needle, int start, CancellationToken cancellationToken = default)
    {
        int last = hay.Length - needle.Length;
        for (int i = Math.Max(0, start); i <= last; i++)
        {
            if ((i & 0xFFF) == 0) cancellationToken.ThrowIfCancellationRequested();
            bool ok = true;
            for (int j = 0; j < needle.Length; j++) if (hay[i + j] != needle[j]) { ok = false; break; }
            if (ok) return i;
        }
        return -1;
    }

    private static ushort U16(byte[] b, int o) =>
        o >= 0 && o + 2 <= b.Length ? BitConverter.ToUInt16(b, o) : (ushort)0;

    private static uint U32(byte[] b, int o) =>
        o >= 0 && o + 4 <= b.Length ? BitConverter.ToUInt32(b, o) : 0;

    private static ulong U64(byte[] b, int o) =>
        o >= 0 && o + 8 <= b.Length ? BitConverter.ToUInt64(b, o) : 0;

    private static uint U32Be(byte[] b, int o) =>
        o >= 0 && o + 4 <= b.Length
            ? ((uint)b[o] << 24) | ((uint)b[o + 1] << 16) | ((uint)b[o + 2] << 8) | b[o + 3]
            : 0;

    private static bool IsPowerOfTwo(uint value) => value != 0 && (value & (value - 1)) == 0;

    private static int AlignUp(int value, int alignment) =>
        checked((int)AlignUp((long)value, (uint)alignment));

    private static uint AlignUp(uint value, uint alignment) =>
        checked((uint)AlignUp((long)value, alignment));

    private static long AlignUp(long value, uint alignment)
    {
        if (!IsPowerOfTwo(alignment)) return value;
        long mask = alignment - 1L;
        return checked((value + mask) & ~mask);
    }

    private static void WriteU32(byte[] b, int off, uint v)
    {
        if (off < 0 || off + 4 > b.Length) return;
        b[off] = (byte)v; b[off + 1] = (byte)(v >> 8); b[off + 2] = (byte)(v >> 16); b[off + 3] = (byte)(v >> 24);
    }

    private static void WriteU16(byte[] b, int off, ushort v)
    {
        if (off < 0 || off + 2 > b.Length) return;
        b[off] = (byte)v;
        b[off + 1] = (byte)(v >> 8);
    }

    private static void WriteU64(byte[] b, int off, ulong v)
    {
        if (off < 0 || off + 8 > b.Length) return;
        WriteU32(b, off, (uint)v);
        WriteU32(b, off + 4, (uint)(v >> 32));
    }
}

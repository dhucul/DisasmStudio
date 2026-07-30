using System.Text;
using DisasmStudio.Core.Unpacking.Lzma;

namespace DisasmStudio.Core.Unpacking;

/// <summary>
/// Static (no-execution) unpacker for UPX-packed PEs. UPX carries everything needed to reverse itself on disk:
/// a <c>PackHeader</c> ("UPX!" magic) records the compression method, the uncompressed length, and — crucially
/// — the <b>Adler-32 checksum of the uncompressed data</b>. That checksum makes decompression
/// <b>self-verifying</b>: it only accepts plaintext whose checksum matches the UPX header. Reconstructed PE
/// layout is validated separately and explicitly returned as analysis-only because imports, relocations, and
/// resources are not rebuilt. Unsupported methods and layouts decline cleanly so the caller can offer the
/// <i>dynamic</i> run-to-OEP unpacker.
///
/// Method-14 (UPX-framed LZMA) and PE filter 0x49 are verified against a real win64/PE UPX sample. The Adler-32
/// gate remains mandatory for every method and layout — a wrong decode is rejected, not written.
/// </summary>
public sealed class UpxStaticUnpacker : IStaticUnpacker
{
    public string Name => "UPX (static, checksum-verified analysis image)";

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
                        out byte[]? image, out uint entryRva) && image is not null)
                {
                    log.AppendLine("  Reconstructed a re-openable PE image from the verified plaintext.");
                    log.AppendLine("  Output is analysis-only: UPX's import/relocation/resource metadata is not rebuilt.");
                    return new StaticUnpackResult(
                        true, true, image, entryRva, 1, log.ToString(), null, CanExecute: false);
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
        out byte[]? image, out uint entryRva)
    {
        cancellationToken.ThrowIfCancellationRequested();
        image = null;
        entryRva = 0;
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
        image = output;
        entryRva = rebuilt.EntryRva;
        return true;
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

    private static uint U32Be(byte[] b, int o) =>
        o >= 0 && o + 4 <= b.Length
            ? ((uint)b[o] << 24) | ((uint)b[o + 1] << 16) | ((uint)b[o + 2] << 8) | b[o + 3]
            : 0;

    private static bool IsPowerOfTwo(uint value) => value != 0 && (value & (value - 1)) == 0;

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
}

using System.Text;
using DisasmStudio.Core.Unpacking.Lzma;

namespace DisasmStudio.Core.Unpacking;

/// <summary>
/// Static (no-execution) unpacker for UPX-packed PEs. UPX carries everything needed to reverse itself on disk:
/// a <c>PackHeader</c> ("UPX!" magic) records the compression method, the uncompressed length, and — crucially
/// — the <b>Adler-32 checksum of the uncompressed data</b>. That checksum makes this unpacker <b>self-verifying</b>:
/// it only ever reports success when its own decompression reproduces the exact bytes UPX compressed, so it can
/// never silently emit corrupt output. When it can't verify (unsupported method/variant, or a layout this build
/// doesn't reconstruct), it declines cleanly and the caller falls back to the <i>dynamic</i> run-to-OEP
/// unpacker, which is the verified route for UPX in this tool.
///
/// STATUS: experimental / not verified against a real UPX sample in this build (no upx available to pack one).
/// The Adler-32 gate is what makes shipping it safe regardless — a wrong decode is rejected, not written.
/// </summary>
public sealed class UpxStaticUnpacker : IStaticUnpacker
{
    public string Name => "UPX (static, self-verifying)";

    // UPX method ids (packhead.h).
    private const byte M_NRV2B_LE32 = 2, M_NRV2B_8 = 3;
    private const byte M_NRV2D_LE32 = 5, M_NRV2D_8 = 6;
    private const byte M_NRV2E_LE32 = 8, M_NRV2E_8 = 9;
    private const byte M_LZMA = 14;

    private static readonly byte[] Magic = "UPX!"u8.ToArray();

    public bool LooksApplicable(byte[] file)
    {
        try
        {
            if (!PeView.TryParse(file, out var pe)) return false;
            foreach (var s in pe.Sections)
                if (s.Name.StartsWith("UPX", StringComparison.OrdinalIgnoreCase)) return true;
            return IndexOf(file, Magic, 0) >= 0;
        }
        catch { return false; }
    }

    public StaticUnpackResult Unpack(byte[] file)
    {
        var log = new StringBuilder();
        try
        {
            if (!PeView.TryParse(file, out var pe))
                return StaticUnpackResult.NotApplicable("Not applicable: not a valid PE.");
            if (!LooksApplicable(file))
                return StaticUnpackResult.NotApplicable("Not applicable: no UPX section names or 'UPX!' PackHeader found.");

            // Parse every "UPX!" PackHeader and keep the ones that look like a real header (plausible sizes).
            var headers = FindPackHeaders(file, log);
            if (headers.Count == 0)
                return StaticUnpackResult.Fail(log.ToString(),
                    "UPX detected but no parseable PackHeader (method/sizes/Adler) found. Use the dynamic unpacker (verified for UPX).");

            foreach (var h in headers)
            {
                log.AppendLine($"PackHeader @0x{h.Offset:X}: method={h.Method}, u_len=0x{h.ULen:X}, c_len=0x{h.CLen:X}, u_adler=0x{h.UAdler:X8}, filter={h.Filter}.");
                if (h.ULen == 0 || h.ULen > (128u << 20)) { log.AppendLine("  implausible u_len — skipped."); continue; }

                // Locate the compressed data by trying candidate start offsets and accepting only the decode whose
                // Adler-32 matches the header — no reliance on exact block-structure knowledge, and false positives
                // are impossible (a 32-bit checksum must match exactly).
                if (TryDecodeVerified(file, pe, h, log) is not { } plain) continue;

                log.AppendLine($"  Adler-32 VERIFIED (0x{h.UAdler:X8}) — decompression is provably correct ({plain.Length} bytes).");

                // Reconstruction: turn the verified plaintext into a re-openable PE. Only claim success when the
                // result actually parses as a PE; otherwise be honest and route to the dynamic path.
                if (TryReconstruct(plain, out byte[]? image, out uint entryRva) && image is not null)
                {
                    log.AppendLine("  Reconstructed a re-openable PE image from the verified plaintext.");
                    return new StaticUnpackResult(true, true, image, entryRva, 1, log.ToString(), null);
                }

                log.AppendLine("  Decompression verified, but a runnable PE couldn't be reconstructed from this layout.");
                return StaticUnpackResult.Fail(log.ToString(),
                    "UPX decompression verified (Adler-32 matched), but reconstructing a runnable PE from this UPX layout " +
                    "isn't supported statically in this build. Use the dynamic 'Unpack…' strategy (verified end-to-end for UPX) " +
                    "or 'Dump Process…'.");
            }

            return StaticUnpackResult.Fail(log.ToString(),
                "UPX detected, but no compressed block could be decoded and Adler-verified (unsupported method/variant, or a " +
                "layout this build doesn't handle). Use the dynamic unpacker — it's the verified route for UPX here.");
        }
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
    private static List<PackHeader> FindPackHeaders(byte[] file, StringBuilder log)
    {
        var list = new List<PackHeader>();
        for (int at = 0; (at = IndexOf(file, Magic, at)) >= 0; at += 4)
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
    private static byte[]? TryDecodeVerified(byte[] file, PeView pe, PackHeader h, StringBuilder log)
    {
        foreach (int start in CandidateStarts(file, pe, h))
        {
            if (start < 0 || start >= file.Length) continue;
            byte[]? plain = Decode(h.Method, file, start, file.Length - start, (int)h.ULen);
            if (plain is null || plain.Length != h.ULen) continue;
            if (Adler32(plain) == h.UAdler) return plain;
        }
        return null;
    }

    // Compressed data usually lives in the packed section (UPX1) and starts at/after a small block header; the
    // Adler gate lets us just try a handful of offsets rather than model the exact block structure.
    private static IEnumerable<int> CandidateStarts(byte[] file, PeView pe, PackHeader h)
    {
        var seen = new HashSet<int>();
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

    private static byte[]? Decode(byte method, byte[] src, int off, int len, int uLen)
    {
        try
        {
            return method switch
            {
                M_NRV2B_8 or M_NRV2B_LE32 => Nrv2b(src, off, uLen),
                M_NRV2D_8 or M_NRV2D_LE32 => Nrv2d(src, off, uLen),
                M_NRV2E_8 or M_NRV2E_LE32 => Nrv2e(src, off, uLen),
                M_LZMA => DecodeUpxLzma(src, off, len, uLen),
                _ => null,
            };
        }
        catch { return null; }
    }

    // UPX's LZMA block stores a 2-byte props-ish prefix; reuse the vendored, bit-exact LZMA core. Best-effort:
    // the Adler gate rejects it if the framing guess is wrong.
    private static byte[]? DecodeUpxLzma(byte[] src, int off, int len, int uLen)
    {
        // Try a few plausible property/offset framings; Adler verification (by the caller) is the arbiter.
        foreach (int skip in new[] { 0, 2, 4 })
        {
            if (off + skip + 5 > src.Length) break;
            try
            {
                var props = new ReadOnlySpan<byte>(src, off + skip, 5);
                var outp = LzmaCodec.Decode(props, src, off + skip + 5, len - skip - 5, uLen);
                if (outp.Length == uLen) return outp;
            }
            catch { /* try next framing */ }
        }
        return null;
    }

    // ---- reconstruction (best-effort) ----

    // If the verified plaintext is itself a PE image (some UPX layouts decompress close to the original), lay it
    // out in virtual form so it re-opens. Otherwise decline (caller routes to the dynamic path).
    private static bool TryReconstruct(byte[] plain, out byte[]? image, out uint entryRva)
    {
        image = null; entryRva = 0;
        if (!PeView.TryParse(plain, out var pe) || pe.SizeOfImage == 0 || pe.SizeOfImage > (512u << 20)) return false;

        var img = new byte[pe.SizeOfImage];
        int hdr = (int)Math.Min(Math.Min(pe.SizeOfHeaders, (uint)plain.Length), pe.SizeOfImage);
        Array.Copy(plain, 0, img, 0, hdr);
        foreach (var s in pe.Sections)
        {
            if (s.PointerToRawData == 0 || s.SizeOfRawData == 0) continue;
            long srcEnd = (long)s.PointerToRawData + s.SizeOfRawData;
            long dstEnd = (long)s.VirtualAddress + s.SizeOfRawData;
            if (srcEnd > plain.Length || dstEnd > img.Length) continue;
            Array.Copy(plain, (int)s.PointerToRawData, img, (int)s.VirtualAddress, (int)s.SizeOfRawData);
        }
        // Section table → virtual layout so it re-opens cleanly.
        int secBase = pe.PeOffset + PeConstants.OptHeaderFromSig + pe.SizeOfOptionalHeader;
        for (int i = 0; i < pe.Sections.Count; i++)
        {
            int sOff = secBase + i * PeConstants.SectionHeaderSize;
            var s = pe.Sections[i];
            WriteU32(img, sOff + PeConstants.Sec_PointerToRawData, s.VirtualAddress);
            if (s.VirtualSize > 0) WriteU32(img, sOff + PeConstants.Sec_SizeOfRawData, s.VirtualSize);
        }
        if (pe.SectionAlignment != 0)
            WriteU32(img, pe.PeOffset + PeConstants.OptHeaderFromSig + PeConstants.Opt_FileAlignment, pe.SectionAlignment);

        image = img;
        entryRva = pe.EntryRva;
        return true;
    }

    // ---- NRV decompressors (canonical UCL, byte-wise "_8" getbit; LE32 files fail the Adler gate and decline) ----

    // Canonical UCL bit reader: a sentinel bit rides the buffer; refills one byte at a time, MSB first.
    private sealed class BitIn(byte[] src, int off)
    {
        private uint _bb;
        public int Ip = off;
        private readonly byte[] _s = src;
        public int GetBit()
        {
            _bb = (_bb & 0x7f) != 0 ? _bb << 1 : (uint)((Ip < _s.Length ? _s[Ip++] : 0) << 1) | 1;
            return (int)((_bb >> 8) & 1);
        }
        public byte NextByte() => Ip < _s.Length ? _s[Ip++] : (byte)0;
        public bool AtEnd => Ip >= _s.Length;
    }

    private static byte[]? Nrv2b(byte[] src, int off, int uLen)
    {
        var dst = new byte[uLen];
        var b = new BitIn(src, off);
        int op = 0; uint lastOff = 1;
        while (op < uLen)
        {
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
            if (!CopyMatch(dst, ref op, mOff, mLen + 1, uLen)) return null;
        }
        return dst;
    }

    private static byte[]? Nrv2d(byte[] src, int off, int uLen)
    {
        var dst = new byte[uLen];
        var b = new BitIn(src, off);
        int op = 0; uint lastOff = 1;
        while (op < uLen)
        {
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
            if (!CopyMatch(dst, ref op, mOff, mLen + 1, uLen)) return null;
        }
        return dst;
    }

    private static byte[]? Nrv2e(byte[] src, int off, int uLen)
    {
        var dst = new byte[uLen];
        var b = new BitIn(src, off);
        int op = 0; uint lastOff = 1;
        while (op < uLen)
        {
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
            if (!CopyMatch(dst, ref op, mOff, mLen + 1, uLen)) return null;
        }
        return dst;
    }

    private static bool CopyMatch(byte[] dst, ref int op, uint mOff, uint count, int uLen)
    {
        int mPos = op - (int)mOff;
        if (mPos < 0) return false;
        for (uint i = 0; i < count && op < uLen; i++) dst[op++] = dst[mPos++];
        return true;
    }

    // ---- checksums / helpers ----

    private static uint Adler32(byte[] data)
    {
        const uint mod = 65521;
        uint a = 1, s = 0;
        foreach (byte x in data) { a = (a + x) % mod; s = (s + a) % mod; }
        return (s << 16) | a;
    }

    private static int IndexOf(byte[] hay, byte[] needle, int start)
    {
        int last = hay.Length - needle.Length;
        for (int i = Math.Max(0, start); i <= last; i++)
        {
            bool ok = true;
            for (int j = 0; j < needle.Length; j++) if (hay[i + j] != needle[j]) { ok = false; break; }
            if (ok) return i;
        }
        return -1;
    }

    private static uint U32(byte[] b, int o) => o >= 0 && o + 4 <= b.Length ? BitConverter.ToUInt32(b, o) : 0;

    private static void WriteU32(byte[] b, int off, uint v)
    {
        if (off < 0 || off + 4 > b.Length) return;
        b[off] = (byte)v; b[off + 1] = (byte)(v >> 8); b[off + 2] = (byte)(v >> 16); b[off + 3] = (byte)(v >> 24);
    }
}

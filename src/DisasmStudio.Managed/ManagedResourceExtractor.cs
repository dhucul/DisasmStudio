using System.Collections;
using System.IO.Compression;
using System.Resources;
using ICSharpCode.Decompiler.Metadata;

namespace DisasmStudio.Managed;

/// <summary>
/// Enumerates a managed assembly's embedded manifest resources and makes them extractable. It recognises the
/// two ways .NET apps hide sub-files: Costura/Fody-style compressed assemblies (deflate blobs named
/// <c>*.compressed</c> / <c>*.exe.single</c>) which it inflates, and classic ResX/<c>.g.resources</c> blobs
/// whose inner entries (byte[]/Stream — e.g. native plugin DLLs, a nested EXE) it walks out via
/// <see cref="ResourceReader"/> without invoking BinaryFormatter.
/// </summary>
public static class ManagedResourceExtractor
{
    public static List<ManagedResourceEntry> Enumerate(MetadataFile pe)
    {
        var list = new List<ManagedResourceEntry>();
        foreach (var r in pe.Resources)
        {
            if (r.ResourceType != ResourceType.Embedded)
            {
                list.Add(new ManagedResourceEntry(r.Name, ManagedResourceKind.Raw, 0, () => []));
                continue;
            }

            byte[] raw;
            try
            {
                using var s = r.TryOpenStream();
                if (s is null) continue;
                if (s.CanSeek) s.Position = 0;
                raw = ReadAll(s);
            }
            catch { continue; }

            var kind = Classify(r.Name, raw, out byte[] payload);
            byte[] captured = payload;   // already inflated for CompressedAssembly
            list.Add(new ManagedResourceEntry(r.Name, kind, captured.Length, () => captured));

            if (kind == ManagedResourceKind.ResourcesBlob)
                AddInnerResources(list, r.Name, raw);
        }
        return list;
    }

    // Decide the kind and produce the ready-to-write bytes (inflating a compressed blob).
    private static ManagedResourceKind Classify(string name, byte[] raw, out byte[] payload)
    {
        payload = raw;
        string lower = name.ToLowerInvariant();

        bool compressedName = lower.EndsWith(".compressed") || lower.EndsWith(".exe.single")
            || lower.EndsWith(".dll.compressed") || lower.Contains("costura") || lower.EndsWith(".gz");
        if (compressedName && TryInflate(raw) is { } inflated) { payload = inflated; return ManagedResourceKind.CompressedAssembly; }

        if (StartsWithMz(raw)) return IsManagedImage(raw) ? ManagedResourceKind.EmbeddedAssembly : ManagedResourceKind.NativeImage;

        if (lower.EndsWith(".resources")) return ManagedResourceKind.ResourcesBlob;

        // Last resort: a blob that inflates to an MZ image was compressed even without a tell-tale name.
        if (TryInflate(raw) is { } inf && StartsWithMz(inf)) { payload = inf; return ManagedResourceKind.CompressedAssembly; }

        return ManagedResourceKind.Raw;
    }

    // Walk a .resources container's inner byte[]/Stream entries (native DLLs, nested EXEs, etc.) without
    // deserializing objects — GetResourceData returns the raw serialized bytes and a type code.
    private static void AddInnerResources(List<ManagedResourceEntry> list, string blobName, byte[] raw)
    {
        try
        {
            using var ms = new MemoryStream(raw, writable: false);
            using var reader = new ResourceReader(ms);
            var it = reader.GetEnumerator();          // reading .Key alone does not load/deserialize .Value
            while (it.MoveNext())
            {
                if (it.Key is not string key) continue;
                byte[]? bytes;
                try
                {
                    reader.GetResourceData(key, out string type, out byte[] data);
                    bytes = ExtractPayload(type, data);
                }
                catch { continue; }
                if (bytes is null || bytes.Length == 0) continue;

                var kind = StartsWithMz(bytes)
                    ? (IsManagedImage(bytes) ? ManagedResourceKind.EmbeddedAssembly : ManagedResourceKind.NativeImage)
                    : (TryInflate(bytes) is { } inf && StartsWithMz(inf))
                        ? ManagedResourceKind.CompressedAssembly
                        : ManagedResourceKind.Raw;
                byte[] outBytes = kind == ManagedResourceKind.CompressedAssembly ? TryInflate(bytes)! : bytes;
                byte[] captured = outBytes;
                list.Add(new ManagedResourceEntry($"{blobName} :: {key}", kind, captured.Length, () => captured));
            }
        }
        catch { /* not a readable .resources container — the top-level blob entry is still extractable */ }
    }

    // ResourceReader.GetResourceData returns the value bytes after the type code. For ByteArray/Stream the
    // payload is a 4-byte little-endian length followed by the bytes; other types we pass through unchanged
    // (so an MZ blob stored under an odd type is still recoverable) or skip if clearly textual.
    private static byte[]? ExtractPayload(string type, byte[] data)
    {
        bool lengthPrefixed = type is "ResourceTypeCode.ByteArray" or "ResourceTypeCode.Stream";
        if (lengthPrefixed && data.Length >= 4)
        {
            int len = BitConverter.ToInt32(data, 0);
            if (len >= 0 && len <= data.Length - 4) return data[4..(4 + len)];
            return data;
        }
        // Other type codes (bool/int/string/serialized design-time objects) are noise unless the raw bytes are
        // themselves a recognizable file — an image, archive, or PE. This drops the 1-byte ResX scalars.
        return HasFileMagic(data) ? data : null;
    }

    private static bool HasFileMagic(byte[] b)
        => StartsWithMz(b)
        || (b.Length >= 4 && b[0] == (byte)'P' && b[1] == (byte)'K' && b[2] == 3 && b[3] == 4)   // zip
        || (b.Length >= 2 && b[0] == 0x1F && b[1] == 0x8B);                                       // gzip

    private static byte[]? TryInflate(byte[] raw)
    {
        // Costura writes raw DEFLATE; some tools use GZIP. Try both, reject implausible results.
        foreach (bool gzip in new[] { false, true })
        {
            try
            {
                using var input = new MemoryStream(raw, writable: false);
                Stream ds = gzip ? new GZipStream(input, CompressionMode.Decompress)
                                 : new DeflateStream(input, CompressionMode.Decompress);
                using (ds)
                using (var outMs = new MemoryStream())
                {
                    ds.CopyTo(outMs);
                    if (outMs.Length > 0) return outMs.ToArray();
                }
            }
            catch { /* try next codec */ }
        }
        return null;
    }

    private static bool StartsWithMz(byte[] b) => b.Length >= 2 && b[0] == (byte)'M' && b[1] == (byte)'Z';

    // Cheap check: does this MZ image carry a CLR header (data directory 14)? Tells a managed sub-assembly
    // from a native DLL for labelling only.
    private static bool IsManagedImage(byte[] b)
    {
        try
        {
            if (!StartsWithMz(b) || b.Length < 0x40) return false;
            int e = BitConverter.ToInt32(b, 0x3C);
            if (e <= 0 || e + 0x108 > b.Length) return false;
            if (BitConverter.ToUInt32(b, e) != 0x00004550) return false;   // 'PE\0\0'
            int opt = e + 24;
            ushort magic = BitConverter.ToUInt16(b, opt);
            bool is64 = magic == 0x20B;
            int ddBase = opt + (is64 ? 112 : 96);
            int comOff = ddBase + 14 * 8;
            if (comOff + 8 > b.Length) return false;
            uint comRva = BitConverter.ToUInt32(b, comOff);
            return comRva != 0;
        }
        catch { return false; }
    }

    private static byte[] ReadAll(Stream s)
    {
        if (s is MemoryStream ms) return ms.ToArray();
        using var outMs = new MemoryStream();
        s.CopyTo(outMs);
        return outMs.ToArray();
    }
}

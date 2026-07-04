using System.Text;

namespace DisasmStudio.Core.Formats;

/// <summary>
/// Minimal reader for the CLR header (IMAGE_COR20_HEADER at data-directory index 14) that tells the app a PE
/// is a .NET managed assembly. This is the cheap <em>detection</em> half of the managed path and deliberately
/// lives in Core with no decompiler dependency — full C# decompilation and resource extraction live in the
/// separate <c>DisasmStudio.Managed</c> project. A managed image is still a valid PE, so it keeps loading as a
/// <see cref="PeImage"/>; managed-ness is an orthogonal attribute discovered here, not a separate
/// <see cref="BinaryFormat"/> (which would ripple through the many <c>Format == Pe</c> guards).
/// </summary>
public sealed record ManagedPeInfo(
    bool IsILOnly,
    bool Is32BitRequired,
    ushort RuntimeMajor,
    ushort RuntimeMinor,
    string? RuntimeVersion,
    uint EntryPointToken,
    uint ManagedResourcesRva,
    uint ManagedResourcesSize)
{
    /// <summary>Human label for the header/detector/status views, e.g. ".NET (IL-only, v4.0.30319)".</summary>
    public string Describe()
    {
        string kind = IsILOnly ? "IL-only" : "mixed-mode";
        string ver = string.IsNullOrEmpty(RuntimeVersion) ? $"CLR {RuntimeMajor}.{RuntimeMinor}" : RuntimeVersion;
        return $".NET ({kind}, {ver})";
    }

    /// <summary>Read the CLR header when <paramref name="img"/> is a managed PE; null for native or non-PE images.</summary>
    public static ManagedPeInfo? TryRead(IBinaryImage img)
    {
        // Managed-ness is a PE concept, and only PeImage exposes the data directories; skip everything else.
        if (img is not PeImage pe) return null;

        var (rva, size) = pe.DataDirectory(14);   // IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR
        if (rva == 0 || size < 0x48) return null;  // a real IMAGE_COR20_HEADER is 0x48 bytes

        byte[] hdr = img.ReadBytesAtVa(img.ImageBase + rva, 0x48);
        if (hdr.Length < 0x48) return null;

        ushort major = BitConverter.ToUInt16(hdr, 4);
        ushort minor = BitConverter.ToUInt16(hdr, 6);
        uint mdRva = BitConverter.ToUInt32(hdr, 8);
        uint mdSize = BitConverter.ToUInt32(hdr, 12);
        uint flags = BitConverter.ToUInt32(hdr, 16);
        uint epTok = BitConverter.ToUInt32(hdr, 20);
        uint resRva = BitConverter.ToUInt32(hdr, 24);
        uint resSize = BitConverter.ToUInt32(hdr, 28);

        // Validate against the metadata root: a genuine managed image points at a "BSJB"-signed metadata stream.
        // This rejects a bogus/overlapping COM descriptor before we advertise the file as .NET.
        string? ver = ReadMetadataVersion(img, mdRva, mdSize);
        if (ver is null) return null;

        return new ManagedPeInfo(
            IsILOnly: (flags & 0x1) != 0,       // COMIMAGE_FLAGS_ILONLY
            Is32BitRequired: (flags & 0x2) != 0, // COMIMAGE_FLAGS_32BITREQUIRED
            RuntimeMajor: major,
            RuntimeMinor: minor,
            RuntimeVersion: ver,
            EntryPointToken: epTok,
            ManagedResourcesRva: resRva,
            ManagedResourcesSize: resSize);
    }

    // The metadata root: "BSJB" signature (u32), MajorVersion (u16), MinorVersion (u16), Reserved (u32),
    // then a length-prefixed UTF-8 runtime-version string ("v4.0.30319"), 4-byte aligned.
    private static string? ReadMetadataVersion(IBinaryImage img, uint mdRva, uint mdSize)
    {
        if (mdRva == 0 || mdSize < 20) return null;
        byte[] head = img.ReadBytesAtVa(img.ImageBase + mdRva, 20);
        if (head.Length < 20 || BitConverter.ToUInt32(head, 0) != 0x424A5342) return null;  // 'BSJB' little-endian
        int verLen = BitConverter.ToInt32(head, 12);
        if (verLen <= 0 || verLen > 255) return null;
        byte[] verBytes = img.ReadBytesAtVa(img.ImageBase + mdRva + 16, verLen);
        if (verBytes.Length == 0) return null;
        int z = Array.IndexOf(verBytes, (byte)0);
        return Encoding.ASCII.GetString(verBytes, 0, z >= 0 ? z : verBytes.Length);
    }
}

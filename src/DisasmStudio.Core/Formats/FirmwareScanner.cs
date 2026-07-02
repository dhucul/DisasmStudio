using Iced.Intel;

namespace DisasmStudio.Core.Formats;

/// <summary>Which x86 firmware convention a flat blob matches.</summary>
public enum FirmwareKind
{
    None,
    /// <summary>A BIOS / UEFI SPI-flash image: the CPU begins at the reset vector 16 bytes below the top of
    /// the address space (0xFFFFFFF0, or 0xFFFF0 for a small legacy BIOS shadowed into the F-segment).</summary>
    ResetVector,
    /// <summary>A PCI / PnP expansion (option) ROM: signature 55 AA, and the INIT routine is entered at offset 3.</summary>
    OptionRom,
}

/// <summary>
/// The result of sniffing a flat blob for firmware conventions. The important part is <see cref="EntryVa"/>:
/// where the CPU actually begins executing (the reset vector, or an option ROM's INIT field), which is almost
/// never the start of the file. <see cref="BaseVa"/>/<see cref="Bitness"/> are the mapping that puts that entry
/// at its architectural address, and <see cref="Symbols"/> are navigation markers (reset_vector, boot_entry,
/// firmware-volume bases) fed into analysis as code/data seeds. All fields are suggestions the user can override.
/// </summary>
public sealed record FirmwareScan(
    FirmwareKind Kind,
    string Summary,
    ulong BaseVa,
    int Bitness,
    ulong EntryVa,
    IReadOnlyList<NamedSymbol> Symbols)
{
    public bool IsFirmware => Kind != FirmwareKind.None;

    /// <summary>The "not firmware" result — the caller should fall back to a plain raw load.</summary>
    public static readonly FirmwareScan NotFirmware = new(FirmwareKind.None, "", 0, 0, 0, []);
}

/// <summary>
/// Sniffs a headerless blob for x86 firmware layouts and, crucially, finds its entry point. Two conventions are
/// recognised: the <b>reset vector</b> of a BIOS / UEFI SPI-flash image (execution starts 16 bytes below the top
/// of the mapped image — 0xFFFFFFF0 for a modern flash, 0xFFFF0 for a legacy BIOS) and a <b>PCI option ROM</b>
/// (55 AA header, INIT entered at offset 3). The reset / init jump is decoded in 16-bit real mode to resolve the
/// boot entry, and Intel Flash Descriptor + UEFI firmware-volume signatures corroborate the guess so an arbitrary
/// blob that merely ends in a jump byte isn't mistaken for firmware.
/// </summary>
public static class FirmwareScanner
{
    // UEFI firmware-volume header: the 4-byte signature "_FVH" sits at offset 0x28 within the volume,
    // with the volume length at 0x20 and the header revision (1 or 2) at 0x37.
    private static readonly byte[] FvhSignature = "_FVH"u8.ToArray();
    private const int FvSignatureOffset = 0x28;
    private const int FvLengthOffset = 0x20;
    private const int FvRevisionOffset = 0x37;
    private const ulong MinFvLength = 0x48;   // the fixed EFI_FIRMWARE_VOLUME_HEADER size

    // Intel Flash Descriptor validation signature (0x0FF0A55A) at file offset 0x10.
    private const uint IntelDescriptorSignature = 0x0FF0A55A;

    /// <summary>Open <paramref name="path"/> and scan it; returns <see cref="FirmwareScan.NotFirmware"/> for
    /// anything that doesn't match a known layout.</summary>
    public static FirmwareScan Scan(string path)
    {
        using var f = MappedFile.Open(path);
        return Scan(f);
    }

    public static FirmwareScan Scan(MappedFile f)
    {
        int len = f.Length;
        if (len < 0x40) return FirmwareScan.NotFirmware;

        // A PCI/PnP option ROM is unambiguous from its 55 AA magic; try it first.
        if (f.ReadByte(0) == 0x55 && f.ReadByte(1) == 0xAA)
        {
            var rom = ScanOptionRom(f, len);
            if (rom is not null) return rom;
        }

        return ScanResetVector(f, len) ?? FirmwareScan.NotFirmware;
    }

    // ---- reset vector (BIOS / UEFI SPI flash) ----

    private static FirmwareScan? ScanResetVector(MappedFile f, int len)
    {
        if (len < 0x2000) return null;   // too small to be a flash image

        // Map so the reset vector lands at its architectural address: the top of 1 MB for a small legacy BIOS
        // that shadows into the E/F-segment, the top of 4 GB for a modern SPI-flash image.
        bool legacy1Mb = len <= 0x20000;
        ulong top = legacy1Mb ? 0x100000UL : 0x100000000UL;
        ulong baseVa = top - (ulong)len;
        ulong segBase = top - 0x10000;             // CS base held at reset: F000:xxxx (1 MB) or FFFF:xxxx (4 GB)
        int rvOff = len - 16;
        ulong resetVa = baseVa + (ulong)rvOff;      // == top − 16 (0xFFFF0 or 0xFFFFFFF0)

        // The reset vector must decode (16-bit real mode) to an unconditional jump, possibly behind a little
        // NOP/CLI padding. Absent that, this isn't a reset vector — let the caller open it as a plain blob.
        if (!TryDecodeResetJump(f, rvOff, segBase, out ulong target, out bool isFar)) return null;

        // Corroborate before committing: a real flash image carries an Intel descriptor, UEFI firmware volumes,
        // or at least a whole-64-KB size. This keeps an arbitrary blob that happens to end in a jump from
        // masquerading as firmware.
        bool ifd = f.ReadU32(0x10) == IntelDescriptorSignature;
        var fvs = FindFirmwareVolumes(f, len);
        bool flashSized = (len & 0xFFFF) == 0;
        if (!ifd && fvs.Count == 0 && !flashSized) return null;

        var markers = new List<NamedSymbol> { new(resetVa, "reset_vector", NamedSymbolKind.Function) };
        bool targetMapped = target >= baseVa && target < baseVa + (ulong)len;
        if (targetMapped) markers.Add(new(target, "boot_entry", NamedSymbolKind.Function));
        for (int i = 0; i < fvs.Count; i++)
            markers.Add(new(baseVa + (ulong)fvs[i], $"fv_{i}", NamedSymbolKind.Data));

        string jump = isFar ? $"far jmp → 0x{target:X}" : $"jmp → 0x{target:X}";
        if (!targetMapped) jump += " (outside this mapping)";
        string corroboration =
            (ifd ? "Intel flash descriptor; " : "") +
            (fvs.Count > 0 ? $"{fvs.Count} UEFI firmware volume{(fvs.Count == 1 ? "" : "s")}; " : "");
        string summary =
            $"x86 reset vector at 0x{resetVa:X} — {corroboration}reset {jump}. " +
            $"Mapped at 0x{baseVa:X} (top of {(legacy1Mb ? "1 MB" : "4 GB")}) so the entry sits at its architectural address.";

        return new FirmwareScan(FirmwareKind.ResetVector, summary, baseVa, 16, resetVa, markers);
    }

    /// <summary>Decode the 16 bytes at the reset vector as 16-bit real mode; on success yields the linear
    /// target of the first unconditional jump (skipping NOP/CLI/CLD/STI padding). <paramref name="segBase"/> is
    /// the CS base held at reset, added to a near target to form a linear address; a far jump forms its own.</summary>
    private static bool TryDecodeResetJump(MappedFile f, int rvOff, ulong segBase, out ulong target, out bool isFar)
    {
        target = 0;
        isFar = false;
        byte[] window = f.ReadBytes(rvOff, 16);
        if (window.Length < 2) return false;

        var dec = Decoder.Create(16, new ByteArrayCodeReader(window), DecoderOptions.None);
        dec.IP = 0xFFF0;   // the real-mode offset of the reset vector, so near targets wrap correctly
        for (int i = 0; i < 4; i++)
        {
            dec.Decode(out var ins);
            if (ins.IsInvalid || ins.Length == 0) return false;
            if (ins.FlowControl == FlowControl.UnconditionalBranch)
            {
                if (ins.Op0Kind == OpKind.FarBranch16)
                {
                    target = (ulong)ins.FarBranchSelector * 16 + ins.FarBranch16;
                    isFar = true;
                    return true;
                }
                if (ins.Op0Kind == OpKind.NearBranch16)
                {
                    target = segBase + ins.NearBranch16;
                    return true;
                }
                return false;   // an indirect reset jump can't be resolved statically
            }
            // Tolerate the odd padding/setup instruction ahead of the jump; anything else means "not a jump table".
            if (ins.Mnemonic is not (Mnemonic.Nop or Mnemonic.Cli or Mnemonic.Cld or Mnemonic.Sti)) return false;
        }
        return false;
    }

    // ---- PCI / PnP option ROM ----

    private static FirmwareScan? ScanOptionRom(MappedFile f, int len)
    {
        // 0xC0000 is the conventional shadow segment for an option ROM (video BIOS et al.); the absolute base
        // only shifts the marker addresses — the entry is always the INIT field 3 bytes in.
        const ulong Base = 0xC0000;
        ulong entry = Base + 3;
        int blocks = f.ReadByte(2);
        int romSize = blocks * 512;

        // The INIT field is a far-callable entry point that (near-)jumps to the real routine. Requiring it to
        // decode to a jump (or a PCIR structure to be present) keeps a stray 55 AA prefix from being misread.
        byte[] window = f.ReadBytes(3, 16);
        bool hasJump = false;
        ulong initTarget = 0;
        var dec = Decoder.Create(16, new ByteArrayCodeReader(window), DecoderOptions.None);
        dec.IP = 3;
        dec.Decode(out var ins);
        if (!ins.IsInvalid && ins.FlowControl == FlowControl.UnconditionalBranch)
        {
            if (ins.Op0Kind == OpKind.NearBranch16) { initTarget = Base + ins.NearBranch16; hasJump = true; }
            else if (ins.Op0Kind == OpKind.FarBranch16) { initTarget = (ulong)ins.FarBranchSelector * 16 + ins.FarBranch16; hasJump = true; }
        }

        string pcir = ReadPcirNote(f, len);
        if (!hasJump && pcir.Length == 0) return null;

        var markers = new List<NamedSymbol>
        {
            new(Base, "rom_header", NamedSymbolKind.Data),
            new(entry, "rom_init", NamedSymbolKind.Function),
        };
        if (hasJump && initTarget >= Base && initTarget < Base + (ulong)len)
            markers.Add(new(initTarget, "rom_entry", NamedSymbolKind.Function));

        string sizeNote = romSize > 0 ? $"{blocks} × 512 B = {romSize} bytes" : "size byte 0";
        string jumpNote = hasJump ? $", INIT jmp → 0x{initTarget:X}" : "";
        string summary =
            $"PCI option ROM ({sizeNote}){pcir}. Execution enters the INIT field at 0x{entry:X} (offset 3){jumpNote}.";

        return new FirmwareScan(FirmwareKind.OptionRom, summary, Base, 16, entry, markers);
    }

    /// <summary>Read the optional PCI Data Structure (pointed to at offset 0x18) for a class/vendor note; empty
    /// string if absent or malformed.</summary>
    private static string ReadPcirNote(MappedFile f, int len)
    {
        int ptr = f.ReadU16(0x18);
        if (ptr <= 0 || ptr + 0x18 > len) return "";
        if (!(f.ReadByte(ptr) == (byte)'P' && f.ReadByte(ptr + 1) == (byte)'C'
              && f.ReadByte(ptr + 2) == (byte)'I' && f.ReadByte(ptr + 3) == (byte)'R')) return "";
        ushort vendor = f.ReadU16(ptr + 4);
        ushort device = f.ReadU16(ptr + 6);
        // Class code is 3 bytes at PCIR+0x0D (base class in the high byte).
        byte baseClass = f.ReadByte(ptr + 0x0D + 2);
        string cls = baseClass switch
        {
            0x03 => "display",
            0x02 => "network",
            0x01 => "storage",
            0x00 => "legacy",
            _ => $"class 0x{baseClass:X2}",
        };
        return $", PCIR {cls} {vendor:X4}:{device:X4}";
    }

    // ---- UEFI firmware volumes ----

    /// <summary>File offsets of UEFI firmware-volume headers (identified by the "_FVH" signature at volume+0x28,
    /// with a self-consistent length). Bounded in scan span and count so a huge dump can't stall the open.</summary>
    private static List<int> FindFirmwareVolumes(MappedFile f, int len)
    {
        const int MaxScan = 64 * 1024 * 1024;
        const int Chunk = 1 << 20;
        const int MaxVolumes = 64;

        var bases = new List<int>();
        var seen = new HashSet<int>();
        int cap = Math.Min(len, MaxScan);
        for (int pos = 0; pos < cap && bases.Count < MaxVolumes; pos += Chunk)
        {
            int want = Math.Min(Chunk + FvhSignature.Length - 1, cap - pos);
            byte[] buf = f.ReadBytes(pos, want);
            var span = buf.AsSpan();
            int idx = 0;
            while (bases.Count < MaxVolumes)
            {
                int at = span[idx..].IndexOf(FvhSignature);
                if (at < 0) break;
                idx += at + 1;
                int fvBase = pos + (idx - 1) - FvSignatureOffset;
                if (fvBase < 0 || !seen.Add(fvBase)) continue;
                // Validate against the file's true remaining space (unsigned, so a garbage huge length can't
                // pass via a negative signed cast) and a plausible header revision — "_FVH" alone is only 4 bytes.
                ulong fvLen = f.ReadU64(fvBase + FvLengthOffset);
                byte revision = f.ReadByte(fvBase + FvRevisionOffset);
                if (revision is 1 or 2 && fvLen >= MinFvLength && fvLen <= (ulong)(len - fvBase))
                    bases.Add(fvBase);
            }
        }
        bases.Sort();
        return bases;
    }
}

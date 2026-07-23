namespace DisasmStudio.Core.Formats;

/// <summary>
/// A loaded binary, normalised so the disassembler and UI never care whether it came from a
/// PE, an ELF, or a flat blob. Everything is addressed in absolute virtual addresses (VAs);
/// each format maps VA↔file-offset its own way. Reads are cheap, on-demand slices over a
/// memory-mapped backing, which is what keeps large files usable.
/// </summary>
public interface IBinaryImage
{
    string FilePath { get; }
    BinaryFormat Format { get; }
    string FormatName { get; }

    /// <summary>16 for x86, 64 for x64 — fed straight to Iced's decoder bitness.</summary>
    int Bitness { get; }
    string ArchName { get; }

    /// <summary>The instruction set to decode with. Defaults to x86/x64 by bitness; only <see cref="RawImage"/>
    /// overrides it to an ARM-family architecture (chosen in the raw-load dialog). This is the single signal
    /// that routes an image to the Iced (x86/x64) or Capstone (ARM) decoder + analysis path.</summary>
    Architecture Arch => Bitness == 64 ? Architecture.X64 : Architecture.X86;

    /// <summary>True when this image decodes as ARM/Thumb/AArch64 — x86-only features (decompiler, debugger,
    /// devirt, unpack, C export) are gated off for these.</summary>
    bool IsArm => Arch is Architecture.Arm or Architecture.Thumb or Architecture.Arm64;

    /// <summary>True when this image decodes as Intel 8051/MCS-51. Like ARM it's a non-x86 arch: it routes to
    /// its own decoder + analyzer and the x86-only features (decompiler/IL, debugger, devirt, unpack, C
    /// export) are gated off.</summary>
    bool Is8051 => Arch is Architecture.I8051;

    /// <summary>Any non-x86 architecture — the shared test for gating off the x86-only feature set.</summary>
    bool IsNonX86 => IsArm || Is8051;

    ulong ImageBase { get; }

    /// <summary>Entry point VA, or 0 if the format has none.</summary>
    ulong EntryVa { get; }

    /// <summary>True if this is a DLL (PE IMAGE_FILE_DLL characteristic). DLLs can't be launched
    /// directly; the debugger hosts them in an EXE. Always false for ELF/Raw.</summary>
    bool IsDll { get; }

    IReadOnlyList<Section> Sections { get; }
    IReadOnlyList<NamedSymbol> Symbols { get; }
    IReadOnlyList<ImportEntry> Imports { get; }

    /// <summary>The header region (PE: the MZ/PE headers up to the first section), exposed so it can be
    /// optionally folded into the listing as data. Null for formats without a distinct header region.</summary>
    Section? HeaderRegion { get; }

    /// <summary>The parsed resource (.rsrc) directory tree, or null when the format/file has none.</summary>
    ResourceTree? Resources { get; }

    /// <summary>Function start VAs from format metadata (PE x64 .pdata RUNTIME_FUNCTIONs); empty otherwise.
    /// The authoritative function list for x64 — used to seed code discovery and classification.</summary>
    IReadOnlyList<ulong> FunctionStarts { get; }

    /// <summary>IAT slot VA → import, so an indirect <c>call [slot]</c> can be named.</summary>
    IReadOnlyDictionary<ulong, ImportEntry> ImportsByIatVa { get; }

    /// <summary>Lowest / highest mapped VA (drives the hex view's scroll range).</summary>
    ulong MinVa { get; }
    ulong MaxVa { get; }

    /// <summary>Map a VA to a backing file offset, or -1 when the VA is not file-backed.</summary>
    int VaToOffset(ulong va);

    bool IsMappedVa(ulong va);
    bool IsExecutableVa(ulong va);

    /// <summary>The section containing <paramref name="va"/>, or null.</summary>
    Section? SectionAt(ulong va);

    /// <summary>Read a single backing byte by file offset (used by the decoder's window reader).</summary>
    byte ReadByteAtOffset(int offset);
    int BackingLength { get; }

    byte[] ReadBytesAtVa(ulong va, int count);

    /// <summary>Fill <paramref name="dest"/> from <paramref name="va"/>; unmapped bytes are left 0. Returns the contiguous mapped count.</summary>
    int ReadVa(ulong va, Span<byte> dest);

    // ---- patching: in-memory byte edits overlaid on every read, persisted via SavePatchedAs ----
    /// <summary>Overlay <paramref name="bytes"/> at file <paramref name="offset"/>.</summary>
    void Patch(int offset, ReadOnlySpan<byte> bytes);
    /// <summary>Patch starting at a VA; returns false if the VA isn't file-backed.</summary>
    bool PatchVa(ulong va, ReadOnlySpan<byte> bytes);
    void RevertPatch(int offset, int count);
    bool IsPatchedAt(int offset);
    bool IsDirty { get; }
    int PatchCount { get; }
    /// <summary>The current in-memory byte edits as (file offset → new value), so a project can persist them and
    /// re-apply via <see cref="Patch(int, ReadOnlySpan{byte})"/> on reload. Empty when clean. File-backed,
    /// PE-memory, and process-snapshot images all report their current edits.</summary>
    IReadOnlyDictionary<int, byte> Patches { get; }
    /// <summary>Undo the most recent patch; false if nothing to undo.</summary>
    bool Undo();
    bool CanUndo { get; }
    /// <summary>Write the original bytes plus all edits to a new file.</summary>
    void SavePatchedAs(string path);
}

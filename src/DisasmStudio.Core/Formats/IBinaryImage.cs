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

    ulong ImageBase { get; }

    /// <summary>Entry point VA, or 0 if the format has none.</summary>
    ulong EntryVa { get; }

    /// <summary>True if this is a DLL (PE IMAGE_FILE_DLL characteristic). DLLs can't be launched
    /// directly; the debugger hosts them in an EXE. Always false for ELF/Raw.</summary>
    bool IsDll { get; }

    IReadOnlyList<Section> Sections { get; }
    IReadOnlyList<NamedSymbol> Symbols { get; }
    IReadOnlyList<ImportEntry> Imports { get; }

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
    /// <summary>Undo the most recent patch; false if nothing to undo.</summary>
    bool Undo();
    bool CanUndo { get; }
    /// <summary>Write the original bytes plus all edits to a new file.</summary>
    void SavePatchedAs(string path);
}

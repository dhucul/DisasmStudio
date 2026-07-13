using DisasmStudio.Core.Formats;

namespace DisasmStudio.Debug;

/// <summary>
/// The debuggee's whole address space as an <see cref="IBinaryImage"/> for the memory dump: reads and
/// writes go to process memory and the VA range spans 0..max so any address (code, stack, heap) can be
/// viewed and edited. Unmapped regions simply read short (shown as <c>??</c>). No file backing.
/// </summary>
public sealed class FullMemoryImage(DebuggerEngine eng) : IBinaryImage
{
    private static readonly Dictionary<ulong, ImportEntry> NoImports = new();

    public string FilePath => "";
    public BinaryFormat Format => BinaryFormat.Pe;
    public string FormatName => "live";
    public int Bitness => eng.Is32 ? 32 : 64;
    public string ArchName => eng.Is32 ? "x86" : "x64";
    public ulong ImageBase => 0;
    public ulong EntryVa => 0;
    public bool IsDll => false;   // the whole address space, not a single module
    public IReadOnlyList<Section> Sections => [];
    public IReadOnlyList<NamedSymbol> Symbols => [];
    public IReadOnlyList<ImportEntry> Imports => [];
    public Section? HeaderRegion => null;
    public ResourceTree? Resources => null;
    public IReadOnlyList<ulong> FunctionStarts => [];
    public IReadOnlyDictionary<ulong, ImportEntry> ImportsByIatVa => NoImports;
    public int BackingLength => 0;
    public ulong MinVa => 0;
    public ulong MaxVa => eng.Is32 ? 0xFFFF_FFFFUL : 0x0000_7FFF_FFFF_FFFFUL;

    public byte ReadByteAtOffset(int offset) => 0;
    public void Patch(int offset, ReadOnlySpan<byte> bytes) { }
    public bool PatchVa(ulong va, ReadOnlySpan<byte> bytes) => eng.WriteMemory(va, bytes.ToArray());
    public void RevertPatch(int offset, int count) { }
    public bool IsPatchedAt(int offset) => false;
    public bool IsDirty => false;
    public int PatchCount => 0;
    public IReadOnlyDictionary<int, byte> Patches => System.Collections.Immutable.ImmutableDictionary<int, byte>.Empty;
    public bool Undo() => false;
    public bool CanUndo => false;
    public void SavePatchedAs(string path) { }

    public Section? SectionAt(ulong va) => null;
    public int VaToOffset(ulong va) => -1;
    public bool IsMappedVa(ulong va) => eng.ReadMemory(va, 1).Length == 1;
    public bool IsExecutableVa(ulong va) => eng.IsExecutable(va);
    public byte[] ReadBytesAtVa(ulong va, int count) => eng.ReadMemory(va, count);

    public int ReadVa(ulong va, Span<byte> dest)
    {
        var b = eng.ReadMemory(va, dest.Length);
        b.CopyTo(dest);
        return b.Length;
    }
}

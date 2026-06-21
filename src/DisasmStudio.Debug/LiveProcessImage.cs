using DisasmStudio.Core.Formats;

namespace DisasmStudio.Debug;

/// <summary>
/// Presents the live debuggee as an <see cref="IBinaryImage"/>: byte reads go to process memory, while
/// structure (sections, symbols, imports, function starts) is the loaded static image rebased by the
/// ASLR slide (<c>liveBase − preferredBase</c>). This lets the existing linear view / panels work over
/// the running process. File-offset access and patching-to-file are disabled (no file backing).
/// </summary>
public sealed class LiveProcessImage : IBinaryImage
{
    private readonly DebuggerEngine _eng;
    private readonly IBinaryImage _static;
    private readonly List<Section> _sections;
    private readonly List<NamedSymbol> _symbols;
    private readonly List<ImportEntry> _imports;
    private readonly Dictionary<ulong, ImportEntry> _iat;
    private readonly List<ulong> _funcs;

    public ulong Slide { get; }

    public LiveProcessImage(DebuggerEngine eng, IBinaryImage staticImage)
    {
        _eng = eng; _static = staticImage;
        Slide = eng.ImageBase - staticImage.ImageBase;
        ulong slide = Slide;
        _sections = staticImage.Sections.Select(s => new Section
        {
            Name = s.Name, StartVa = s.StartVa + slide, VirtualSize = s.VirtualSize,
            FileOffset = s.FileOffset, FileSize = s.FileSize,
            IsExecutable = s.IsExecutable, IsReadable = s.IsReadable, IsWritable = s.IsWritable,
        }).ToList();
        _symbols = staticImage.Symbols.Select(s => s with { Va = s.Va + slide }).ToList();
        _imports = staticImage.Imports.Select(i => i with { IatVa = i.IatVa + slide }).ToList();
        _iat = new Dictionary<ulong, ImportEntry>();
        foreach (var i in _imports) _iat[i.IatVa] = i;
        _funcs = staticImage.FunctionStarts.Select(f => f + slide).ToList();
    }

    public string FilePath => _static.FilePath;
    public BinaryFormat Format => _static.Format;
    public string FormatName => _static.FormatName;
    public int Bitness => _eng.Is32 ? 32 : 64;
    public string ArchName => _eng.Is32 ? "x86" : "x64";
    public ulong ImageBase => _eng.ImageBase;
    public ulong EntryVa => _static.EntryVa + Slide;
    public bool IsDll => _static.IsDll;
    public IReadOnlyList<Section> Sections => _sections;
    public IReadOnlyList<NamedSymbol> Symbols => _symbols;
    public IReadOnlyList<ImportEntry> Imports => _imports;
    public IReadOnlyList<ulong> FunctionStarts => _funcs;
    public IReadOnlyDictionary<ulong, ImportEntry> ImportsByIatVa => _iat;
    public int BackingLength => _static.BackingLength;
    public ulong MinVa => ImageBase;
    public ulong MaxVa => ImageBase + (_static.MaxVa - _static.ImageBase);

    public byte ReadByteAtOffset(int offset) => 0;
    public void Patch(int offset, ReadOnlySpan<byte> bytes) { }
    public bool PatchVa(ulong va, ReadOnlySpan<byte> bytes) => false;   // live patching goes through the memory panel
    public void RevertPatch(int offset, int count) { }
    public bool IsPatchedAt(int offset) => false;
    public bool IsDirty => false;
    public int PatchCount => 0;
    public bool Undo() => false;
    public bool CanUndo => false;
    public void SavePatchedAs(string path) { }

    public Section? SectionAt(ulong va) { foreach (var s in _sections) if (s.ContainsVa(va)) return s; return null; }
    public int VaToOffset(ulong va) => -1;
    public bool IsMappedVa(ulong va) => SectionAt(va) is not null || _eng.ReadMemory(va, 1).Length == 1;
    public bool IsExecutableVa(ulong va) => SectionAt(va) is { IsExecutable: true } || (SectionAt(va) is null && _eng.IsExecutable(va));
    public byte[] ReadBytesAtVa(ulong va, int count) => _eng.ReadMemory(va, count);

    public int ReadVa(ulong va, Span<byte> dest)
    {
        var b = _eng.ReadMemory(va, dest.Length);
        b.CopyTo(dest);
        return b.Length;
    }
}

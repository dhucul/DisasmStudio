using DisasmStudio.Core.Formats;

namespace DisasmStudio.Core.Analysis;

/// <summary>
/// A read-only analysis view over a packed image. Packers commonly mark a multi-megabyte compressed
/// payload executable even though only the small loader stub around the entry point is code on disk.
/// Exposing that payload as an ordinary code section makes every static pass decode compressed bytes.
///
/// The underlying image remains the result/UI image (and is never modified). This view only narrows the
/// executable sections seen by static analysis to the entry stub and any already-small executable sections.
/// </summary>
internal sealed class PackedAnalysisImage : IBinaryImage
{
    private const ulong EntryLookBehind = 0x10_000;
    private const ulong EntryLookAhead = 0x40_000;
    private const int SmallExecutableSection = 0x40_000;

    private readonly IBinaryImage _inner;
    private readonly IReadOnlyList<Section> _sections;

    private PackedAnalysisImage(IBinaryImage inner, IReadOnlyList<Section> sections)
    {
        _inner = inner;
        _sections = sections;
    }

    public static bool TryCreate(IBinaryImage image, out IBinaryImage analysisImage)
    {
        analysisImage = image;
        if (image.Format != BinaryFormat.Pe) return false;

        // Do not discard anything until a file-backed executable section containing the entry point has
        // been proven. AddressOfEntryPoint may legitimately be zero (for example a resource-only DLL), and
        // malformed/dumped images can point into a virtual-only tail. In either case there is no safe stub
        // window to infer, so ordinary full-image analysis is the conservative fallback.
        Section? entrySection = null;
        int entrySectionIndex = -1;
        ulong entrySectionEnd = 0;
        for (int i = 0; i < image.Sections.Count; i++)
        {
            var section = image.Sections[i];
            if (!section.IsExecutable || section.FileSize <= 0) continue;
            ulong fileSpan = FileSpan(section);
            if (section.StartVa > ulong.MaxValue - fileSpan) continue;
            ulong end = section.StartVa + fileSpan;
            if (image.EntryVa >= section.StartVa && image.EntryVa < end)
            {
                entrySection = section;
                entrySectionIndex = i;
                entrySectionEnd = end;
                break;
            }
        }
        if (entrySection is null) return false;

        Section? entryWindow = null;
        if (entrySection.FileSize > SmallExecutableSection)
        {
            ulong start = image.EntryVa > EntryLookBehind ? image.EntryVa - EntryLookBehind : entrySection.StartVa;
            start = Math.Max(entrySection.StartVa, start & ~0xFFFUL);
            ulong end = Math.Min(entrySectionEnd,
                image.EntryVa > ulong.MaxValue - EntryLookAhead ? ulong.MaxValue : image.EntryVa + EntryLookAhead);
            int fileOffset = image.VaToOffset(start);
            if (fileOffset < 0 || end <= start) return false;

            int fileSize = (int)Math.Min(end - start, int.MaxValue);
            entryWindow = new Section
            {
                Name = entrySection.Name,
                StartVa = start,
                VirtualSize = (ulong)fileSize,
                FileOffset = fileOffset,
                FileSize = fileSize,
                IsExecutable = true,
                IsReadable = entrySection.IsReadable,
                IsWritable = entrySection.IsWritable,
            };
        }

        bool narrowed = false;
        var sections = new List<Section>(image.Sections.Count);
        for (int i = 0; i < image.Sections.Count; i++)
        {
            var section = image.Sections[i];
            if (!section.IsExecutable || section.FileSize <= SmallExecutableSection)
            {
                sections.Add(section);
                continue;
            }

            if (i != entrySectionIndex)
            {
                narrowed = true; // compressed executable payload outside the loader-stub section
                continue;
            }

            sections.Add(entryWindow!);
            narrowed |= entryWindow!.StartVa != section.StartVa || entryWindow.EndVa != entrySectionEnd;
        }

        if (!narrowed) return false;
        analysisImage = new PackedAnalysisImage(image, sections);
        return true;
    }

    private static ulong FileSpan(Section section) => section.VirtualSize > 0
        ? Math.Min(section.VirtualSize, (ulong)section.FileSize)
        : (ulong)section.FileSize;

    public string FilePath => _inner.FilePath;
    public BinaryFormat Format => _inner.Format;
    public string FormatName => _inner.FormatName;
    public int Bitness => _inner.Bitness;
    public string ArchName => _inner.ArchName;
    public Architecture Arch => _inner.Arch;
    public ulong ImageBase => _inner.ImageBase;
    public ulong EntryVa => _inner.EntryVa;
    public bool IsDll => _inner.IsDll;
    public IReadOnlyList<Section> Sections => _sections;
    public IReadOnlyList<NamedSymbol> Symbols => _inner.Symbols;
    public IReadOnlyList<ImportEntry> Imports => _inner.Imports;
    public Section? HeaderRegion => _inner.HeaderRegion;
    public ResourceTree? Resources => _inner.Resources;
    public IReadOnlyList<ulong> FunctionStarts => _inner.FunctionStarts;
    public IReadOnlyDictionary<ulong, ImportEntry> ImportsByIatVa => _inner.ImportsByIatVa;
    public ulong MinVa => _inner.MinVa;
    public ulong MaxVa => _inner.MaxVa;
    public int BackingLength => _inner.BackingLength;

    public int VaToOffset(ulong va) => _inner.VaToOffset(va);
    public bool IsMappedVa(ulong va) => _inner.IsMappedVa(va);
    public bool IsExecutableVa(ulong va) =>
        _sections.Any(section => section.IsExecutable && section.ContainsVa(va));
    public Section? SectionAt(ulong va) => _sections.FirstOrDefault(section => section.ContainsVa(va));
    public byte ReadByteAtOffset(int offset) => _inner.ReadByteAtOffset(offset);
    public byte[] ReadBytesAtVa(ulong va, int count) => _inner.ReadBytesAtVa(va, count);
    public int ReadVa(ulong va, Span<byte> dest) => _inner.ReadVa(va, dest);
    public void Patch(int offset, ReadOnlySpan<byte> bytes) => _inner.Patch(offset, bytes);
    public bool PatchVa(ulong va, ReadOnlySpan<byte> bytes) => _inner.PatchVa(va, bytes);
    public void RevertPatch(int offset, int count) => _inner.RevertPatch(offset, count);
    public bool IsPatchedAt(int offset) => _inner.IsPatchedAt(offset);
    public bool IsDirty => _inner.IsDirty;
    public int PatchCount => _inner.PatchCount;
    public IReadOnlyDictionary<int, byte> Patches => _inner.Patches;
    public bool Undo() => _inner.Undo();
    public bool CanUndo => _inner.CanUndo;
    public void SavePatchedAs(string path) => _inner.SavePatchedAs(path);
}

using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;
using DisasmStudio.Core.Analysis;
using DisasmStudio.Wpf.ViewModels;

namespace DisasmStudio.Wpf;

/// <summary>
/// A saved DisasmStudio session (<c>.dsproj</c>). It references the binary by path and records how to
/// load it (format + raw base/bitness) plus the current view state, then re-analyses on open — fast,
/// and always consistent with the current engine. Versioned so it can later carry user edits
/// (renames, comments) without breaking older files.
/// </summary>
public sealed record ProjectFile
{
    public int Version { get; init; } = 8;
    public long MachSliceOffset { get; init; }   // v8: selected slice in a fat/universal Mach-O (0 for a thin file)
    public string BinaryPath { get; init; } = "";
    public string Format { get; init; } = "";   // "PE" / "ELF" / "Raw"
    public ulong RawBaseVa { get; init; }        // raw blobs only
    public int RawBitness { get; init; }         // raw blobs only
    public ulong RawEntryVa { get; init; }       // v3: raw/firmware entry point (0 ⇒ entry at base, legacy behaviour)
    public string? RawArch { get; init; }        // v4: raw ISA ("Arm"/"Thumb"/"Arm64"); null ⇒ x86/x64 by bitness (legacy)
    public ulong CurrentVa { get; init; }        // navigation state
    public int CenterTab { get; init; }          // active center tab (Linear/Graph/Hex)
    public List<string>? LoadedSections { get; init; }   // v2: non-code sections folded into the listing
    public bool LoadHeader { get; init; }                // v2: PE header folded into the listing
    public Markup? Markup { get; init; }                 // v5: user renames / comments / bookmarks; v6: + user-defined function starts (null on older files)

    // v7: live-session state, so reopening a project resumes where you left off. All keyed in STATIC (unslid)
    // VA space — the same space the project's re-analysis produces — except Patches, which are keyed by file
    // offset (stable for the same binary and re-applied directly). All null on older files / when unused.
    public Dictionary<ulong, BpDef>? Breakpoints { get; init; }   // static VA → breakpoint definition (sw/hw/mem + condition/hit-count)
    public List<ulong>? Trace { get; init; }                      // executed-instruction trace (coverage), static VAs
    public List<PatchRun>? Patches { get; init; }                 // byte edits, coalesced into contiguous file-offset runs
    public Dictionary<ulong, bool>? JumpAssumptions { get; init; } // static "toggle jump" what-ifs: VA → assumed-taken

    // Fields (BpDef uses public fields) + enums-as-strings so BpDef's HwKind/MemAccess/HitCountMode round-trip
    // robustly; byte[] in PatchRun serialises as base64.
    private static readonly JsonSerializerOptions Opts = new()
    {
        WriteIndented = true,
        IncludeFields = true,
        Converters = { new JsonStringEnumConverter() },
    };

    public void Save(string path) => File.WriteAllText(path, JsonSerializer.Serialize(this, Opts));

    public static ProjectFile Load(string path) =>
        JsonSerializer.Deserialize<ProjectFile>(File.ReadAllText(path), Opts)
        ?? throw new InvalidDataException("Not a valid DisasmStudio project file.");
}

/// <summary>A contiguous run of patched bytes at file <paramref name="Offset"/> — how a project stores byte edits,
/// re-applied verbatim via <see cref="DisasmStudio.Core.Formats.IBinaryImage.Patch"/> on reload.</summary>
public sealed record PatchRun(int Offset, byte[] Bytes);

using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using DisasmStudio.Core.Analysis;
using DisasmStudio.ManagedDebug;
using DisasmStudio.Wpf.Services;
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
    public int Version { get; init; } = 10;
    public long MachSliceOffset { get; init; }   // v8: selected slice in a fat/universal Mach-O (0 for a thin file)
    public string BinaryPath { get; init; } = "";
    public string? BinarySha256 { get; init; }   // v9: pristine backing-file identity before offset-based state is restored
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
    public List<BpLoc>? ManagedBreakpoints { get; init; }         // v10: source breakpoints (module + metadata token + IL offset)
    public DllDebugState? DllDebug { get; init; }                 // v10: exact DLL host/export selection for restart/elevation

    // Fields (BpDef uses public fields) + enums-as-strings so BpDef's HwKind/MemAccess/HitCountMode round-trip
    // robustly; byte[] in PatchRun serialises as base64.
    private static readonly JsonSerializerOptions Opts = new()
    {
        WriteIndented = true,
        IncludeFields = true,
        Converters = { new JsonStringEnumConverter() },
    };

    public string ToJson() => JsonSerializer.Serialize(this, Opts);

    public void Save(string path) => AtomicFile.WriteAllText(path, ToJson());

    public static ProjectFile FromJson(string json)
    {
        using var doc = JsonDocument.Parse(json);
        if (doc.RootElement.ValueKind != JsonValueKind.Object
            || !doc.RootElement.TryGetProperty(nameof(Version), out var version)
            || version.ValueKind != JsonValueKind.Number
            || !version.TryGetInt32(out int v)
            || v is < 1 or > 10)
            throw new InvalidDataException("Not a valid versioned DisasmStudio project file.");
        var project = JsonSerializer.Deserialize<ProjectFile>(json, Opts)
            ?? throw new InvalidDataException("Not a valid DisasmStudio project file.");
        if (string.IsNullOrWhiteSpace(project.BinaryPath) || string.IsNullOrWhiteSpace(project.Format))
            throw new InvalidDataException("The project is missing its binary path or format.");
        return project;
    }

    public static ProjectFile Load(string path) => FromJson(File.ReadAllText(path));

    public static string ComputeJsonSha256(string json)
        => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(json)));

    public static string ComputeBinarySha256(string path)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read,
            FileShare.ReadWrite | FileShare.Delete);
        return Convert.ToHexString(SHA256.HashData(stream));
    }
}

/// <summary>A contiguous run of patched bytes at file <paramref name="Offset"/> — how a project stores byte edits,
/// re-applied verbatim via <see cref="DisasmStudio.Core.Formats.IBinaryImage.Patch"/> on reload.</summary>
public sealed record PatchRun(int Offset, byte[] Bytes);

/// <summary>The host and stop location selected for a native DLL debug launch.</summary>
public sealed record DllDebugState(
    string HostExe,
    string CommandLine,
    string? WorkingDir,
    string DllPath,
    uint BreakRva,
    bool BreakIsEntry);

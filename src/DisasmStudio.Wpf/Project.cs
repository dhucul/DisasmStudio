using System.IO;
using System.Text.Json;

namespace DisasmStudio.Wpf;

/// <summary>
/// A saved DisasmStudio session (<c>.dsproj</c>). It references the binary by path and records how to
/// load it (format + raw base/bitness) plus the current view state, then re-analyses on open — fast,
/// and always consistent with the current engine. Versioned so it can later carry user edits
/// (renames, comments) without breaking older files.
/// </summary>
public sealed record ProjectFile
{
    public int Version { get; init; } = 2;
    public string BinaryPath { get; init; } = "";
    public string Format { get; init; } = "";   // "PE" / "ELF" / "Raw"
    public ulong RawBaseVa { get; init; }        // raw blobs only
    public int RawBitness { get; init; }         // raw blobs only
    public ulong CurrentVa { get; init; }        // navigation state
    public int CenterTab { get; init; }          // active center tab (Linear/Graph/Hex)
    public List<string>? LoadedSections { get; init; }   // v2: non-code sections folded into the listing
    public bool LoadHeader { get; init; }                // v2: PE header folded into the listing

    private static readonly JsonSerializerOptions Opts = new() { WriteIndented = true };

    public void Save(string path) => File.WriteAllText(path, JsonSerializer.Serialize(this, Opts));

    public static ProjectFile Load(string path) =>
        JsonSerializer.Deserialize<ProjectFile>(File.ReadAllText(path))
        ?? throw new InvalidDataException("Not a valid DisasmStudio project file.");
}

namespace DisasmStudio.Core.Formats;

/// <summary>A leaf resource's bytes: where they live (RVA + VA) and how big, plus the code page.</summary>
public sealed record ResourceDataEntry(uint DataRva, ulong DataVa, int Size, uint CodePage);

/// <summary>
/// A node in the PE resource (.rsrc) directory tree. The standard layout is three levels —
/// type → name/id → language — so an interior node carries <see cref="Children"/> and a leaf carries
/// <see cref="Data"/>. <see cref="Name"/> is a friendly label (e.g. "RT_ICON", a named resource's
/// string, or "#7"); <see cref="Id"/> is the numeric id when the entry is identified by number.
/// </summary>
public sealed class ResourceNode
{
    public required string Name { get; init; }
    public uint? Id { get; init; }
    public IReadOnlyList<ResourceNode> Children { get; init; } = [];
    public ResourceDataEntry? Data { get; init; }

    /// <summary>A leaf (has bytes) vs. an interior directory node.</summary>
    public bool IsLeaf => Data is not null;
}

/// <summary>The parsed PE resource directory, rooted at the top-level resource types.</summary>
public sealed class ResourceTree
{
    public IReadOnlyList<ResourceNode> Roots { get; init; } = [];

    /// <summary>Well-known top-level resource type ids → their RT_* names.</summary>
    public static string TypeName(uint id) => id switch
    {
        1 => "RT_CURSOR",
        2 => "RT_BITMAP",
        3 => "RT_ICON",
        4 => "RT_MENU",
        5 => "RT_DIALOG",
        6 => "RT_STRING",
        7 => "RT_FONTDIR",
        8 => "RT_FONT",
        9 => "RT_ACCELERATOR",
        10 => "RT_RCDATA",
        11 => "RT_MESSAGETABLE",
        12 => "RT_GROUP_CURSOR",
        14 => "RT_GROUP_ICON",
        16 => "RT_VERSION",
        17 => "RT_DLGINCLUDE",
        19 => "RT_PLUGPLAY",
        20 => "RT_VXD",
        21 => "RT_ANICURSOR",
        22 => "RT_ANIICON",
        23 => "RT_HTML",
        24 => "RT_MANIFEST",
        _ => $"#{id}",
    };

    /// <summary>Well-known resource type ids (used by the UI to choose a preview renderer).</summary>
    public const uint RT_BITMAP = 2, RT_ICON = 3, RT_STRING = 6, RT_GROUP_ICON = 14,
                      RT_VERSION = 16, RT_HTML = 23, RT_MANIFEST = 24;
}

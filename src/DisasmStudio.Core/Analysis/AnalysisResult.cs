using DisasmStudio.Core.Formats;

namespace DisasmStudio.Core.Analysis;

/// <summary>An immutable snapshot of everything the analysis discovered, handed to the UI.</summary>
public sealed class AnalysisResult
{
    public required IBinaryImage Image { get; init; }

    /// <summary>Every instruction's VA in image order — the spine of the linear view.
    /// Settable so a local patch repair can splice in a re-decoded region without a full re-analysis.</summary>
    public required LinearIndex Linear { get; set; }

    /// <summary>Discovered functions (entry, exports, call targets), CFG built lazily per function.</summary>
    public required IReadOnlyList<Function> Functions { get; init; }
    public required IReadOnlyDictionary<ulong, Function> FunctionByVa { get; init; }

    public required XrefDatabase Xrefs { get; init; }
    public required IReadOnlyList<FoundString> Strings { get; init; }

    /// <summary>Indirect-jmp VA → recovered switch/jump-table case targets (so the CFG can follow them).</summary>
    public required IReadOnlyDictionary<ulong, ulong[]> JumpTables { get; init; }

    /// <summary>String VA → a data slot pointing at it (a pointer-table entry), for resolving strings
    /// reached only through a pointer. Precomputed so a double-click never scans on the UI thread.</summary>
    public required IReadOnlyDictionary<ulong, ulong> StringPointerSlots { get; init; }

    public required IReadOnlyList<string> Warnings { get; init; }

    // ---- names / comments (machine layer + user markup overlay) --------------------------------

    private Dictionary<ulong, string> _machineNames = [];
    private Dictionary<ulong, string> _machineComments = [];
    private OverlayMap<string>? _names;
    private OverlayMap<string>? _comments;
    private Markup _markup = new();

    /// <summary>User markup (renames / comments / bookmarks) overlaid on the machine analysis. Bind the
    /// session's shared instance with <see cref="UseMarkup"/> after (re-)analysis so edits persist.</summary>
    public Markup Markup => _markup;

    /// <summary>VA → display name (function / loc_ / import / export), with user renames overlaid on top
    /// of the machine-generated names. The <c>init</c> takes the machine layer from the analysis engine.</summary>
    public required IReadOnlyDictionary<ulong, string> Names
    {
        get => _names ??= new OverlayMap<string>(_machineNames, _markup.Names);
        init => _machineNames = value as Dictionary<ulong, string> ?? new Dictionary<ulong, string>(value);
    }

    /// <summary>Instruction VA → inline comment (e.g. the string it references), with user comments
    /// overlaid on top of the machine-generated ones.</summary>
    public required IReadOnlyDictionary<ulong, string> Comments
    {
        get => _comments ??= new OverlayMap<string>(_machineComments, _markup.Comments);
        init => _machineComments = value as Dictionary<ulong, string> ?? new Dictionary<ulong, string>(value);
    }

    /// <summary>Bind this result to the session's shared <see cref="Markup"/> so user edits overlay the
    /// machine names/comments and survive a re-analysis that produced a fresh result. Resets the overlay
    /// caches so subsequent reads see the bound markup. Also re-applies any function-start renames to the
    /// live <see cref="Function"/> objects (whose <c>Name</c> feeds the function list and decompiler header).</summary>
    public void UseMarkup(Markup markup)
    {
        _markup = markup;
        _names = null;
        _comments = null;
        foreach (var (va, name) in markup.Names)
            if (FunctionByVa.TryGetValue(va, out var fn)) fn.Name = name;
    }

    /// <summary>Apply a user rename at <paramref name="va"/> (blank clears it back to the machine name).
    /// Updates the overlay and, when the VA is a function start, the <see cref="Function.Name"/> shown in
    /// the function list / decompiler header.</summary>
    public void SetName(ulong va, string? name)
    {
        string effective;
        if (string.IsNullOrWhiteSpace(name))
        {
            _markup.Names.Remove(va);
            effective = _machineNames.TryGetValue(va, out var m) ? m : $"sub_{va:X}";
        }
        else
        {
            effective = name.Trim();
            _markup.Names[va] = effective;
        }
        if (FunctionByVa.TryGetValue(va, out var fn)) fn.Name = effective;
    }

    /// <summary>Set (or, when blank, clear) a user comment at <paramref name="va"/>.</summary>
    public void SetComment(ulong va, string? text)
    {
        if (string.IsNullOrWhiteSpace(text)) _markup.Comments.Remove(va);
        else _markup.Comments[va] = text.Trim();
    }

    /// <summary>Toggle a bookmark at <paramref name="va"/>; returns the new state (true = now bookmarked).</summary>
    public bool ToggleBookmark(ulong va) => _markup.Bookmarks.Add(va) || !_markup.Bookmarks.Remove(va);

    public bool IsBookmarked(ulong va) => _markup.Bookmarks.Contains(va);

    /// <summary>Add a machine-generated comment (e.g. a live capture's recovered arguments) to the base
    /// layer, beneath any user comment. Post-construction machine writes go here — not through the overlay.</summary>
    public void AddMachineComment(ulong va, string text) => _machineComments[va] = text;

    /// <summary>Best display name for a VA: an exact symbol (user or machine), else null.</summary>
    public string? NameFor(ulong va) => Names.TryGetValue(va, out var n) ? n : null;
}

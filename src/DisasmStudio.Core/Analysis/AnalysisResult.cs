using DisasmStudio.Core.Formats;

namespace DisasmStudio.Core.Analysis;

/// <summary>An immutable snapshot of everything the analysis discovered, handed to the UI.</summary>
public sealed class AnalysisResult
{
    public required IBinaryImage Image { get; init; }

    /// <summary>Every instruction's VA in image order — the spine of the linear view.
    /// Settable so a local patch repair can splice in a re-decoded region without a full re-analysis.</summary>
    public required LinearIndex Linear { get; set; }

    private List<Function> _functions = [];
    private Dictionary<ulong, Function> _functionByVa = [];

    /// <summary>Discovered functions (entry, exports, call targets), CFG built lazily per function. Kept
    /// sorted by <see cref="Function.Va"/> so <c>FindFunction</c> can binary-search by address. The backing
    /// store is a concrete mutable list so <see cref="AddFunction"/> (user "create function") can splice in.</summary>
    public required IReadOnlyList<Function> Functions
    {
        get => _functions;
        init => _functions = value as List<Function> ?? [.. value];
    }
    public required IReadOnlyDictionary<ulong, Function> FunctionByVa
    {
        get => _functionByVa;
        init => _functionByVa = value as Dictionary<ulong, Function> ?? new(value);
    }

    public required XrefDatabase Xrefs { get; init; }

    private IReadOnlyList<FoundString> _strings = [];
    public required IReadOnlyList<FoundString> Strings
    {
        get => _strings;
        init => _strings = value;
    }

    /// <summary>Indirect-jmp VA → recovered switch/jump-table case targets (so the CFG can follow them).</summary>
    public required IReadOnlyDictionary<ulong, ulong[]> JumpTables { get; init; }

    /// <summary>String VA → a data slot pointing at it (a pointer-table entry), for resolving strings
    /// reached only through a pointer. Precomputed so a double-click never scans on the UI thread.</summary>
    private IReadOnlyDictionary<ulong, ulong> _stringPointerSlots = new Dictionary<ulong, ulong>();
    public required IReadOnlyDictionary<ulong, ulong> StringPointerSlots
    {
        get => _stringPointerSlots;
        init => _stringPointerSlots = value;
    }

    public required IReadOnlyList<string> Warnings { get; init; }

    /// <summary>Replace the byte-derived string snapshot after an in-memory patch and refresh its pointer-table
    /// lookup in the same UI-thread operation. Cross-references and analysis comments intentionally remain the
    /// original analysis snapshot; only string browsing/search state is refreshed.</summary>
    public void ReplaceStrings(IReadOnlyList<FoundString> strings, IReadOnlyDictionary<ulong, ulong> pointerSlots)
    {
        _strings = strings;
        _stringPointerSlots = pointerSlots;
    }

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
        foreach (var va in markup.Functions) AddFunction(va);   // re-materialize user-defined function starts
        foreach (var (va, name) in markup.Names)
            if (FunctionByVa.TryGetValue(va, out var fn)) fn.Name = name;
    }

    /// <summary>Register a user-defined function starting at <paramref name="va"/> so it appears in the
    /// function list / linear header and can be navigated and decompiled (its CFG/extent is built lazily by
    /// <c>CfgBuilder</c> on first view). Idempotent: if a function already starts there it is returned as-is
    /// with <c>AddedName == false</c>. Inserts in <see cref="Function.Va"/> order so <see cref="Functions"/>
    /// stays sorted. When the address had no name a <c>sub_XXXX</c> machine name is added so a label line
    /// renders; <c>AddedName</c> reports that, so an undo can strip exactly what this added.</summary>
    public (Function Fn, bool AddedName) AddFunction(ulong va)
    {
        if (_functionByVa.TryGetValue(va, out var existing)) return (existing, false);
        bool hadName = Names.ContainsKey(va);
        string name = hadName ? Names[va] : $"sub_{va:X}";
        var fn = new Function { Va = va, Name = name };
        _functionByVa[va] = fn;
        int pos = _functions.FindIndex(f => f.Va > va);
        if (pos < 0) _functions.Add(fn); else _functions.Insert(pos, fn);
        if (!hadName)
        {
            _machineNames[va] = name;
            _names = null;   // rebuild the overlay so the new label shows
        }
        return (fn, !hadName);
    }

    /// <summary>Remove a user-defined function (undo of <see cref="AddFunction"/>). When
    /// <paramref name="removeName"/> the <c>sub_XXXX</c> machine name that <see cref="AddFunction"/> added is
    /// stripped too, restoring the prior label state. Returns false if no function started at <paramref name="va"/>.</summary>
    public bool RemoveFunction(ulong va, bool removeName)
    {
        if (!_functionByVa.Remove(va, out var fn)) return false;
        _functions.Remove(fn);
        if (removeName && _machineNames.Remove(va)) _names = null;
        return true;
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

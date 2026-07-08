namespace DisasmStudio.Core.Analysis;

/// <summary>What kind of reference one address makes to another.</summary>
public enum XrefKind { Call, Jump, CondJump, Data }

/// <summary>A reference from one VA to another (a call/branch target or a data access).</summary>
public readonly record struct Xref(ulong From, ulong To, XrefKind Kind);

/// <summary>
/// Cross-references indexed by target VA, so "who references this address?" is a dictionary lookup.
/// Populated during the single linear sweep, so it covers the whole image, not just one function.
/// </summary>
public sealed class XrefDatabase
{
    private readonly Dictionary<ulong, List<Xref>> _toTarget = [];
    private ulong[]? _sortedKeys;   // target VAs in order, built lazily for ToRange; invalidated on Add

    public void Add(ulong from, ulong to, XrefKind kind)
    {
        if (!_toTarget.TryGetValue(to, out var list)) _toTarget[to] = list = [];
        list.Add(new Xref(from, to, kind));
        _sortedKeys = null;
    }

    /// <summary>Every reference that targets <paramref name="va"/>.</summary>
    public IReadOnlyList<Xref> To(ulong va) =>
        _toTarget.TryGetValue(va, out var list) ? list : (IReadOnlyList<Xref>)[];

    /// <summary>
    /// Every reference that targets any address in <c>[lo, hiExclusive)</c>. Used to catch code that
    /// points into the middle of a string (e.g. a suffix-merged literal) rather than its first byte.
    /// Binary-searches a sorted key array (built once after the sweep), so it covers the whole span in
    /// O(log n + k) — no per-byte probe and no length cap that would silently drop tail references.
    /// </summary>
    public List<Xref> ToRange(ulong lo, ulong hiExclusive)
    {
        var result = new List<Xref>();
        if (lo >= hiExclusive || _toTarget.Count == 0) return result;
        var keys = _sortedKeys ??= BuildSortedKeys();
        int lo2 = 0, hi2 = keys.Length;                       // lower-bound: first key >= lo
        while (lo2 < hi2) { int mid = (lo2 + hi2) >> 1; if (keys[mid] < lo) lo2 = mid + 1; else hi2 = mid; }
        for (int i = lo2; i < keys.Length && keys[i] < hiExclusive; i++)
            result.AddRange(_toTarget[keys[i]]);
        return result;
    }

    private ulong[] BuildSortedKeys()
    {
        var keys = new ulong[_toTarget.Count];
        _toTarget.Keys.CopyTo(keys, 0);
        Array.Sort(keys);
        return keys;
    }

    public bool HasRefsTo(ulong va) => _toTarget.ContainsKey(va);
    public int TargetCount => _toTarget.Count;

    /// <summary>Every reference of a given kind across the whole image (target order not guaranteed). Used to
    /// build the static call graph from the <see cref="XrefKind.Call"/> edges collected during the sweep.</summary>
    public IEnumerable<Xref> AllOfKind(XrefKind kind)
    {
        foreach (var list in _toTarget.Values)
            foreach (var x in list)
                if (x.Kind == kind) yield return x;
    }

    /// <summary>A copy with every reference's from/to shifted by <paramref name="slide"/> — lets the live
    /// (ASLR-rebased) analysis reuse the static cross-references instead of starting empty.</summary>
    public XrefDatabase Rebased(ulong slide)
    {
        var db = new XrefDatabase();
        if (slide == 0) { foreach (var list in _toTarget.Values) foreach (var x in list) db.Add(x.From, x.To, x.Kind); return db; }
        foreach (var list in _toTarget.Values)
            foreach (var x in list)
                db.Add(x.From + slide, x.To + slide, x.Kind);
        return db;
    }
}

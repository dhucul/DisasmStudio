namespace DisasmStudio.Core.Analysis;

/// <summary>
/// User-authored markup that survives re-analysis and is persisted in the project file: renamed
/// addresses, per-address comments, and bookmarks. Keyed by static (unslid) VA. Held by an
/// <see cref="AnalysisResult"/> and overlaid on the machine-generated names/comments at read time (see
/// <see cref="OverlayMap{TValue}"/>), so the machine layer stays pristine — clearing a rename reverts to
/// the original <c>sub_/loc_/</c>symbol name with no re-analysis.
/// </summary>
public sealed class Markup
{
    /// <summary>VA → user display name (overrides the machine name at that address).</summary>
    public Dictionary<ulong, string> Names { get; init; } = [];

    /// <summary>VA → user comment (overrides any machine comment at that address).</summary>
    public Dictionary<ulong, string> Comments { get; init; } = [];

    /// <summary>Bookmarked addresses.</summary>
    public HashSet<ulong> Bookmarks { get; init; } = [];

    /// <summary>User-defined function start addresses (created via "Create function here"). Re-materialized
    /// onto each analysis by <see cref="AnalysisResult.UseMarkup"/> so they survive re-analysis and reload.</summary>
    public HashSet<ulong> Functions { get; init; } = [];

    [System.Text.Json.Serialization.JsonIgnore]
    public bool IsEmpty => Names.Count == 0 && Comments.Count == 0 && Bookmarks.Count == 0 && Functions.Count == 0;

    /// <summary>A deep copy — used to snapshot the loaded project markup so the live session can't alias it.</summary>
    public Markup Clone() => new()
    {
        Names = new(Names),
        Comments = new(Comments),
        Bookmarks = new(Bookmarks),
        Functions = new(Functions),
    };
}

/// <summary>
/// A read-only dictionary that layers an <paramref name="overrides"/> map over a <paramref name="baseMap"/>:
/// a key present in the overrides wins; otherwise the base value shows. Both maps are read live, so
/// mutating either is reflected on the next lookup. Used to overlay user renames / comments on the
/// analysis's machine-generated maps without copying or disturbing the base.
/// </summary>
public sealed class OverlayMap<TValue>(
    IReadOnlyDictionary<ulong, TValue> baseMap,
    IReadOnlyDictionary<ulong, TValue> overrides) : IReadOnlyDictionary<ulong, TValue>
{
    public bool TryGetValue(ulong key, [System.Diagnostics.CodeAnalysis.MaybeNullWhen(false)] out TValue value) =>
        overrides.TryGetValue(key, out value) || baseMap.TryGetValue(key, out value);

    public bool ContainsKey(ulong key) => overrides.ContainsKey(key) || baseMap.ContainsKey(key);

    public TValue this[ulong key] => TryGetValue(key, out var v) ? v : throw new KeyNotFoundException();

    public IEnumerable<ulong> Keys => EnumerateKeys();
    public IEnumerable<TValue> Values { get { foreach (var k in EnumerateKeys()) yield return this[k]; } }
    public int Count => CountKeys();

    private IEnumerable<ulong> EnumerateKeys()
    {
        foreach (var k in overrides.Keys) yield return k;
        foreach (var k in baseMap.Keys) if (!overrides.ContainsKey(k)) yield return k;
    }

    private int CountKeys()
    {
        int n = overrides.Count;
        foreach (var k in baseMap.Keys) if (!overrides.ContainsKey(k)) n++;
        return n;
    }

    public IEnumerator<KeyValuePair<ulong, TValue>> GetEnumerator()
    {
        foreach (var k in EnumerateKeys()) yield return new KeyValuePair<ulong, TValue>(k, this[k]);
    }

    System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator() => GetEnumerator();
}

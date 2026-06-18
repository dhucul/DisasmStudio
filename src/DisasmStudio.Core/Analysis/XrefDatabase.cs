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

    public void Add(ulong from, ulong to, XrefKind kind)
    {
        if (!_toTarget.TryGetValue(to, out var list)) _toTarget[to] = list = [];
        list.Add(new Xref(from, to, kind));
    }

    /// <summary>Every reference that targets <paramref name="va"/>.</summary>
    public IReadOnlyList<Xref> To(ulong va) =>
        _toTarget.TryGetValue(va, out var list) ? list : (IReadOnlyList<Xref>)[];

    /// <summary>
    /// Every reference that targets any address in <c>[lo, hiExclusive)</c>. Used to catch code that
    /// points into the middle of a string (e.g. a suffix-merged literal) rather than its first byte.
    /// The scan is capped so a very long span can't stall a click.
    /// </summary>
    public List<Xref> ToRange(ulong lo, ulong hiExclusive)
    {
        var result = new List<Xref>();
        ulong cap = Math.Min(hiExclusive, lo + 4096);
        for (ulong va = lo; va < cap; va++)
            if (_toTarget.TryGetValue(va, out var list)) result.AddRange(list);
        return result;
    }

    public bool HasRefsTo(ulong va) => _toTarget.ContainsKey(va);
    public int TargetCount => _toTarget.Count;
}

namespace DisasmStudio.Core.Analysis;

/// <summary>
/// A whole-program static call graph, built from the analysis's <see cref="XrefKind.Call"/> cross-references:
/// for every function, which functions it calls (callees) and which call it (callers). A call site is
/// attributed to the function that contains it (the nearest function start at or before the call address);
/// the callee is the call target. Keys are VAs — a callee that isn't itself a discovered function start (an
/// import thunk / IAT slot) is kept as-is and resolves to its name through the analysis's name map.
///
/// Note: only <i>direct</i> calls (<c>call rel32</c>) are recorded, matching what the sweep collects as Call
/// xrefs; indirect API calls (<c>call [iat]</c>) are annotated at their sites but are not graph edges here.
/// </summary>
public sealed class CallGraph
{
    private readonly Dictionary<ulong, SortedSet<ulong>> _callees = [];
    private readonly Dictionary<ulong, SortedSet<ulong>> _callers = [];
    private readonly ulong[] _starts;   // sorted function-start VAs, for containing-function lookup

    private CallGraph(ulong[] starts) => _starts = starts;

    /// <summary>Functions called directly from <paramref name="fnVa"/> (empty if it's a leaf).</summary>
    public IReadOnlyCollection<ulong> Callees(ulong fnVa) =>
        _callees.TryGetValue(fnVa, out var s) ? s : (IReadOnlyCollection<ulong>)[];

    /// <summary>Functions that directly call <paramref name="fnVa"/> (empty if nothing calls it).</summary>
    public IReadOnlyCollection<ulong> Callers(ulong fnVa) =>
        _callers.TryGetValue(fnVa, out var s) ? s : (IReadOnlyCollection<ulong>)[];

    /// <summary>The number of recorded call edges (for the header / diagnostics).</summary>
    public int EdgeCount { get; private set; }

    /// <summary>The function start at or before <paramref name="va"/> (0 if <paramref name="va"/> precedes the
    /// first function) — maps a call site, or a mid-function caret, to the function that encloses it.</summary>
    public ulong ContainingFunction(ulong va)
    {
        int lo = 0, hi = _starts.Length;
        while (lo < hi) { int m = (lo + hi) >> 1; if (_starts[m] <= va) lo = m + 1; else hi = m; }
        return lo > 0 ? _starts[lo - 1] : 0;
    }

    public static CallGraph Build(AnalysisResult result)
    {
        var starts = result.Functions.Select(f => f.Va)
            .Where(result.Image.IsExecutableVa).Distinct().OrderBy(x => x).ToArray();
        var g = new CallGraph(starts);

        foreach (var x in result.Xrefs.AllOfKind(XrefKind.Call))
        {
            ulong caller = g.ContainingFunction(x.From);
            if (caller == 0) continue;              // a call from outside any known function
            g.Add(caller, x.To);
        }
        return g;
    }

    private void Add(ulong caller, ulong callee)
    {
        if (!_callees.TryGetValue(caller, out var cs)) _callees[caller] = cs = [];
        if (cs.Add(callee)) EdgeCount++;
        if (!_callers.TryGetValue(callee, out var rs)) _callers[callee] = rs = [];
        rs.Add(caller);
    }
}

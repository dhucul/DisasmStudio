namespace DisasmStudio.Core.Analysis;

/// <summary>
/// A whole-program static call graph, built from the analysis's <see cref="XrefKind.Call"/> cross-references:
/// for every function, which functions it calls (callees) and which call it (callers). A call site is
/// attributed to the function whose control-flow graph actually contains it;
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
    private readonly AnalysisResult _result;

    private CallGraph(AnalysisResult result) => _result = result;

    /// <summary>Functions called directly from <paramref name="fnVa"/> (empty if it's a leaf).</summary>
    public IReadOnlyCollection<ulong> Callees(ulong fnVa) =>
        _callees.TryGetValue(fnVa, out var s) ? s : (IReadOnlyCollection<ulong>)[];

    /// <summary>Functions that directly call <paramref name="fnVa"/> (empty if nothing calls it).</summary>
    public IReadOnlyCollection<ulong> Callers(ulong fnVa) =>
        _callers.TryGetValue(fnVa, out var s) ? s : (IReadOnlyCollection<ulong>)[];

    /// <summary>The number of recorded call edges (for the header / diagnostics).</summary>
    public int EdgeCount { get; private set; }

    /// <summary>The function whose actual CFG contains <paramref name="va"/>, or <see langword="null"/> when the
    /// address is padding, data, or otherwise outside every discovered function.</summary>
    public ulong? ContainingFunction(ulong va)
    {
        return _result.FunctionContaining(va)?.Va;
    }

    public static CallGraph Build(AnalysisResult result)
    {
        var g = new CallGraph(result);

        foreach (var x in result.Xrefs.AllOfKind(XrefKind.Call))
        {
            if (result.FunctionContaining(x.From)?.Va is not ulong caller) continue;
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

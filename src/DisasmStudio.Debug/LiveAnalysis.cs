using DisasmStudio.Core.Analysis;

namespace DisasmStudio.Debug;

/// <summary>
/// Produces an <see cref="AnalysisResult"/> for the live debuggee by rebasing the loaded static analysis
/// by the ASLR slide: the linear index, names, comments, functions, strings and jump tables are shifted
/// to live addresses (reusing all the static intelligence), while bytes are read from process memory.
/// </summary>
public static class LiveAnalysis
{
    public static (AnalysisResult Result, LiveProcessImage Image) Build(DebuggerEngine eng, AnalysisResult staticResult)
    {
        var img = new LiveProcessImage(eng, staticResult.Image);
        ulong slide = img.Slide;

        var idx = new LinearIndex();
        long n = staticResult.Linear.Count;
        for (long i = 0; i < n; i++) idx.Add(staticResult.Linear.VaAt(i) + slide, staticResult.Linear.IsDataAt(i));

        var names = new Dictionary<ulong, string>();
        foreach (var kv in staticResult.Names) names[kv.Key + slide] = kv.Value;
        var comments = new Dictionary<ulong, string>();
        foreach (var kv in staticResult.Comments) comments[kv.Key + slide] = kv.Value;

        var funcs = staticResult.Functions.Select(f => new Function { Va = f.Va + slide, Name = f.Name }).ToList();
        var byVa = new Dictionary<ulong, Function>();
        foreach (var f in funcs) byVa[f.Va] = f;

        var strings = staticResult.Strings.Select(s => s with { Va = s.Va + slide }).ToList();
        var jt = new Dictionary<ulong, ulong[]>();
        foreach (var kv in staticResult.JumpTables) jt[kv.Key + slide] = kv.Value.Select(x => x + slide).ToArray();

        // Reuse the static cross-references (and string-pointer slots), rebased — so during a session a clicked
        // string still resolves to the code that references it (shown in the linear view) instead of falling
        // back to the hex dump, and the Xrefs panel works live.
        var sps = new Dictionary<ulong, ulong>();
        foreach (var kv in staticResult.StringPointerSlots) sps[kv.Key + slide] = kv.Value + slide;

        var result = new AnalysisResult
        {
            Image = img,
            Linear = idx,
            Functions = funcs,
            FunctionByVa = byVa,
            Xrefs = staticResult.Xrefs.Rebased(slide),
            Strings = strings,
            JumpTables = jt,
            StringPointerSlots = sps,
            Names = names,
            Comments = comments,
            Warnings = [],
        };
        return (result, img);
    }
}

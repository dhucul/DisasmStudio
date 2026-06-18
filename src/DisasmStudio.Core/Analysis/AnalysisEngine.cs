using System.Text;
using DisasmStudio.Core.Disasm;
using DisasmStudio.Core.Formats;
using Iced.Intel;

namespace DisasmStudio.Core.Analysis;

/// <summary>
/// Runs the static analysis passes over a loaded image and returns an immutable
/// <see cref="AnalysisResult"/>. Designed to run on a background thread (it only reads the image):
///   1. scan strings,
///   2. one linear sweep of the executable sections → instruction index, xrefs, call/branch targets,
///   3. build the name map and the (lazily-expanded) function list.
/// Per-function CFGs are built on demand by the graph view, so this stays fast even on huge files.
/// </summary>
public static class AnalysisEngine
{
    /// <summary>Cap the linear index so a pathological image can't exhaust memory (~8 bytes each).</summary>
    private const long MaxInstructions = 60_000_000;

    public static AnalysisResult Analyze(IBinaryImage image, IProgress<string>? progress = null,
        CancellationToken token = default)
    {
        var warnings = new List<string>();

        progress?.Report("Disassembling (linear sweep)…");
        var linear = new LinearIndex();
        var xrefs = new XrefDatabase();
        var callTargets = new HashSet<ulong>();
        var branchTargets = new HashSet<ulong>();
        var dataTargets = new HashSet<ulong>();   // every address referenced as data (gates exec-section strings)
        var comments = new Dictionary<ulong, string>();
        var dis = new Disassembler(image);
        var dataRefs = new List<ulong>();
        bool capped = false;

        foreach (var sec in image.Sections)
        {
            if (!sec.IsExecutable || sec.FileSize <= 0) continue;
            ulong va = sec.StartVa;
            // Sweep the real code span, not the file-alignment padding past VirtualSize (which would
            // disassemble as junk). VirtualSize can be 0 on object-style sections — fall back to FileSize.
            ulong span = sec.VirtualSize > 0 ? Math.Min(sec.VirtualSize, (ulong)sec.FileSize) : (ulong)sec.FileSize;
            ulong end = sec.StartVa + span;

            while (va < end)
            {
                if ((linear.Count & 0x3FFFF) == 0 && token.IsCancellationRequested)
                {
                    warnings.Add("Analysis cancelled — partial result.");
                    goto done;
                }
                if (linear.Count >= MaxInstructions) { capped = true; goto done; }

                if (!dis.TryDecodeAt(va, out var instr)) { va++; continue; }
                linear.Add(va);
                ulong ip = instr.IP;

                if (FlowAnalysis.IsDirectCall(instr))
                {
                    ulong t = instr.NearBranchTarget;
                    if (image.IsExecutableVa(t)) callTargets.Add(t);
                    xrefs.Add(ip, t, XrefKind.Call);
                }
                else if (FlowAnalysis.DirectBranchTarget(instr) is ulong bt)
                {
                    if (image.IsExecutableVa(bt)) branchTargets.Add(bt);
                    xrefs.Add(ip, bt, instr.FlowControl == FlowControl.ConditionalBranch ? XrefKind.CondJump : XrefKind.Jump);
                }

                dataRefs.Clear();
                FlowAnalysis.CollectDataRefs(instr, image, dataRefs);
                foreach (var d in dataRefs)
                {
                    xrefs.Add(ip, d, XrefKind.Data);
                    dataTargets.Add(d);
                }

                va += (ulong)instr.Length;
            }
        }
    done:
        if (capped) warnings.Add($"Instruction cap ({MaxInstructions:N0}) reached — linear view truncated.");

        // Scan strings now that data-reference targets are known, so executable sections (where some
        // builds keep read-only literals merged into .text) yield only the strings code points at.
        progress?.Report("Scanning strings…");
        var strings = StringScanner.Scan(image, dataTargets, token: token);

        // Attach a "; \"…\"" comment to each instruction that references a string.
        foreach (var s in strings)
            foreach (var x in xrefs.To(s.Va))
                comments.TryAdd(x.From, Preview(s));

        // Precompute string→pointer-slot map (background) so jumping a pointer-referenced string to
        // its code is an O(1) lookup at click time instead of a UI-thread disk scan.
        progress?.Report("Indexing pointer tables…");
        var stringStarts = new HashSet<ulong>(strings.Count);
        foreach (var s in strings) stringStarts.Add(s.Va);
        var stringPointerSlots = PointerScanner.BuildStringPointerMap(image, stringStarts, token: token);

        progress?.Report("Resolving symbols…");
        var names = BuildNames(image, callTargets, branchTargets);

        progress?.Report("Identifying functions…");
        var (functions, byVa) = BuildFunctions(image, names, callTargets);

        progress?.Report($"Done — {linear.Count:N0} instructions, {functions.Count:N0} functions, {strings.Count:N0} strings.");

        return new AnalysisResult
        {
            Image = image,
            Linear = linear,
            Functions = functions,
            FunctionByVa = byVa,
            Xrefs = xrefs,
            Strings = strings,
            StringPointerSlots = stringPointerSlots,
            Names = names,
            Comments = comments,
            Warnings = warnings,
        };
    }

    private static Dictionary<ulong, string> BuildNames(IBinaryImage image,
        HashSet<ulong> callTargets, HashSet<ulong> branchTargets)
    {
        var names = new Dictionary<ulong, string>();
        foreach (var sym in image.Symbols) names[sym.Va] = sym.Name;      // imports, exports, ELF funcs
        if (image.EntryVa != 0 && image.IsExecutableVa(image.EntryVa)) names.TryAdd(image.EntryVa, "start");
        foreach (var t in callTargets) names.TryAdd(t, $"sub_{t:X}");
        foreach (var t in branchTargets) names.TryAdd(t, $"loc_{t:X}");
        return names;
    }

    private static (List<Function>, Dictionary<ulong, Function>) BuildFunctions(IBinaryImage image,
        IReadOnlyDictionary<ulong, string> names, HashSet<ulong> callTargets)
    {
        var seeds = new SortedSet<ulong>();
        if (image.EntryVa != 0 && image.IsExecutableVa(image.EntryVa)) seeds.Add(image.EntryVa);
        foreach (var sym in image.Symbols)
            if (sym.Kind is NamedSymbolKind.Function or NamedSymbolKind.Export && image.IsExecutableVa(sym.Va))
                seeds.Add(sym.Va);
        foreach (var t in callTargets) seeds.Add(t);

        var functions = new List<Function>(seeds.Count);
        var byVa = new Dictionary<ulong, Function>(seeds.Count);
        foreach (var va in seeds)
        {
            var fn = new Function { Va = va, Name = names.TryGetValue(va, out var n) ? n : $"sub_{va:X}" };
            functions.Add(fn);
            byVa[va] = fn;
        }
        return (functions, byVa);
    }

    private static string Preview(FoundString fs)
    {
        const int max = 48;
        string t = fs.Text.Length > max ? fs.Text[..max] + "…" : fs.Text;
        var sb = new StringBuilder(t.Length + 4);
        if (fs.Wide) sb.Append('L');
        sb.Append('"');
        foreach (char c in t) sb.Append(c is '\t' ? ' ' : c < 0x20 ? '.' : c);
        sb.Append('"');
        return sb.ToString();
    }
}

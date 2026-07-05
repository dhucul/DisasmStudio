using System.Text;
using DisasmStudio.Core.Disasm;
using DisasmStudio.Core.Formats;

namespace DisasmStudio.Core.Analysis;

/// <summary>
/// Analysis for Intel 8051/MCS-51 raw images, parallel to <see cref="AnalysisEngine"/> and
/// <see cref="ArmAnalyzer"/> but self-contained so the x86 (Iced) and ARM (Capstone) pipelines are
/// untouched. Recursive descent over the hand-written <see cref="I8051Disassembler"/> (routed through
/// <see cref="NeutralDisasm.For"/>) from legitimate roots — the entry, any symbols, and every executable
/// section start (a raw blob has one, so the code is always reached even with no user-set entry) — marks
/// reachable instructions in a <see cref="CodeBitmap"/>; whatever it leaves unmarked is data (zero padding,
/// parameter tables, string blocks). Direct LCALL/ACALL targets seed functions (<c>sub_</c>) and branch
/// targets name locations (<c>loc_</c>). No IL / jump-table / API passes (those are x86-only). Produces the
/// same <see cref="AnalysisResult"/> shape the views consume.
/// </summary>
public static class I8051Analyzer
{
    private const long Budget = 40_000_000;

    public static AnalysisResult Analyze(IBinaryImage image, IProgress<string>? progress = null,
        CancellationToken token = default)
    {
        var warnings = new List<string>();
        var dis = NeutralDisasm.For(image, null);   // -> I8051Disassembler (flow-only; no name substitution)
        var code = new CodeBitmap(image);
        var xrefs = new XrefDatabase();
        var callTargets = new HashSet<ulong>();
        var branchTargets = new HashSet<ulong>();

        // 1. Recursive descent from the entry, any symbols, and each executable section start. Following
        //    LCALL/ACALL/LJMP/AJMP/SJMP/Jcc targets marks reachable code + collects call/branch targets.
        progress?.Report("Disassembling (recursive descent)…");
        var roots = new List<ulong>();
        if (image.EntryVa != 0 && image.IsExecutableVa(image.EntryVa)) roots.Add(image.EntryVa);
        foreach (var s in image.Symbols) if (image.IsExecutableVa(s.Va)) roots.Add(s.Va);
        foreach (var sec in image.Sections)
            if (sec.IsExecutable && sec.FileSize > 0) roots.Add(sec.StartVa);
        Descend(image, dis, code, roots, callTargets, branchTargets, xrefs, token);

        // 2. Strings: scan the whole blob (8051 firmware keeps its parameter/string tables inside the one
        //    executable section), then keep only those starting in a data region so code isn't mined for
        //    false strings.
        progress?.Report("Scanning strings…");
        var strings = StringScanner.Scan(image, includeExecutable: true, token: token)
            .Where(s => !code.IsCode(s.Va)).ToList();
        var comments = new Dictionary<ulong, string>();
        foreach (var s in strings)
            foreach (var x in xrefs.To(s.Va))
                comments.TryAdd(x.From, Preview(s));
        var stringByVa = new Dictionary<ulong, FoundString>(strings.Count);
        foreach (var s in strings) stringByVa.TryAdd(s.Va, s);

        // 3. Names: symbols, entry, call targets (sub_), branch targets (loc_), section starts.
        progress?.Report("Resolving symbols…");
        var funcStarts = new SortedSet<ulong>();
        if (image.EntryVa != 0 && image.IsExecutableVa(image.EntryVa)) funcStarts.Add(image.EntryVa);
        foreach (var s in image.Symbols) if (image.IsExecutableVa(s.Va)) funcStarts.Add(s.Va);
        foreach (var t in callTargets) funcStarts.Add(t);

        var names = new Dictionary<ulong, string>();
        foreach (var sym in image.Symbols) names[sym.Va] = sym.Name;
        if (image.EntryVa != 0 && image.IsExecutableVa(image.EntryVa)) names.TryAdd(image.EntryVa, "start");
        foreach (var t in funcStarts) names.TryAdd(t, $"sub_{t:X}");
        foreach (var t in branchTargets) names.TryAdd(t, $"loc_{t:X}");
        foreach (var sec in image.Sections) if (sec.FileSize > 0) names.TryAdd(sec.StartVa, sec.Name);

        // 4. Classified linear index: a code line per marked instruction, gaps collapsed into data.
        progress?.Report("Classifying code vs data…");
        var linear = BuildIndex(image, dis, code, stringByVa, token);

        // 5. Function list.
        var functions = new List<Function>(funcStarts.Count);
        var byVa = new Dictionary<ulong, Function>(funcStarts.Count);
        foreach (var va in funcStarts)
        {
            var fn = new Function { Va = va, Name = names.TryGetValue(va, out var n) ? n : $"sub_{va:X}" };
            functions.Add(fn);
            byVa[va] = fn;
        }

        progress?.Report($"Done — {functions.Count:N0} functions, {strings.Count:N0} strings.");

        return new AnalysisResult
        {
            Image = image,
            Linear = linear,
            Functions = functions,
            FunctionByVa = byVa,
            Xrefs = xrefs,
            Strings = strings,
            JumpTables = new Dictionary<ulong, ulong[]>(),
            StringPointerSlots = new Dictionary<ulong, ulong>(),
            Names = names,
            Comments = comments,
            Warnings = warnings,
        };
    }

    private static void Descend(IBinaryImage image, INeutralDisassembler dis, CodeBitmap code,
        IEnumerable<ulong> seeds, HashSet<ulong> callTargets, HashSet<ulong> branchTargets,
        XrefDatabase xrefs, CancellationToken token)
    {
        var work = new Stack<ulong>();
        foreach (var s in seeds) if (image.IsExecutableVa(s)) work.Push(s);

        long n = 0;
        while (work.Count > 0 && n < Budget)
        {
            if ((n & 0xFFFFF) == 0 && token.IsCancellationRequested) break;
            ulong va = work.Pop();
            if (!image.IsExecutableVa(va) || code.IsCode(va)) continue;
            if (!dis.TryDecode(va, out var ni)) continue;
            code.Mark(va, ni.Length);
            n++;

            ulong fall = va + (ulong)ni.Length;
            switch (ni.Flow)
            {
                case FlowKind.CondJump:
                    if (ni.DirectTarget is ulong tc && image.IsExecutableVa(tc))
                    { branchTargets.Add(tc); xrefs.Add(va, tc, XrefKind.CondJump); work.Push(tc); }
                    work.Push(fall);
                    break;
                case FlowKind.Jump:
                    if (ni.DirectTarget is ulong tj && image.IsExecutableVa(tj))
                    { branchTargets.Add(tj); xrefs.Add(va, tj, XrefKind.Jump); work.Push(tj); }
                    break;   // no fall-through past an unconditional jump
                case FlowKind.Call:
                    if (ni.DirectTarget is ulong tk && image.IsExecutableVa(tk))
                    { callTargets.Add(tk); xrefs.Add(va, tk, XrefKind.Call); work.Push(tk); }
                    work.Push(fall);
                    break;
                case FlowKind.Ret:
                case FlowKind.IndirectJump:      // JMP @A+DPTR — unresolved computed branch, path ends here
                case FlowKind.Interrupt:
                    break;
                default:
                    work.Push(fall);             // Seq, IndirectCall — execution continues after
                    break;
            }
        }
    }

    private static LinearIndex BuildIndex(IBinaryImage image, INeutralDisassembler dis, CodeBitmap code,
        IReadOnlyDictionary<ulong, FoundString> stringByVa, CancellationToken token)
    {
        var index = new LinearIndex();
        var stringStarts = stringByVa.Keys.OrderBy(k => k).ToArray();
        foreach (var sec in image.Sections.Where(s => s.FileSize > 0).OrderBy(s => s.StartVa))
        {
            ulong end = sec.StartVa + (sec.VirtualSize > 0 ? Math.Min(sec.VirtualSize, (ulong)sec.FileSize) : (ulong)sec.FileSize);
            ulong va = sec.StartVa;
            while (va < end)
            {
                if ((index.Count & 0x3FFFF) == 0 && token.IsCancellationRequested) return index;

                if (sec.IsExecutable && code.IsCode(va))
                {
                    if (dis.TryDecode(va, out var ni) && ni.Length > 0) { index.Add(va); va += (ulong)ni.Length; }
                    else { index.Add(va, isData: true); va++; }
                    continue;
                }

                ulong gapEnd = sec.IsExecutable ? code.NextCode(va, end) : end;
                EmitData(index, stringByVa, stringStarts, ref va, gapEnd);
            }
        }
        return index;
    }

    /// <summary>Emit a data run as lines: a scanned string is one line at its exact VA; the bytes around it
    /// are aligned dw/db rows, stopped at the next string start so a non-aligned string is not skipped.</summary>
    private static void EmitData(LinearIndex index, IReadOnlyDictionary<ulong, FoundString> stringByVa,
        ulong[] stringStarts, ref ulong va, ulong end)
    {
        while (va < end)
        {
            if (stringByVa.TryGetValue(va, out var fs))
            {
                ulong slen = (ulong)Math.Max(1, fs.Wide ? fs.Length * 2 : fs.Length);
                index.Add(va, isData: true);
                va += Math.Min(slen, end - va);
                continue;
            }
            ulong stop = NextStringStart(stringStarts, va, end);
            ulong rem = stop - va;
            // 8051 code addresses are 16-bit — coalesce to dw (2 bytes) at most, never dd/dq.
            ulong chunk = va % 2 == 0 && rem >= 2 ? 2UL : 1UL;
            index.Add(va, isData: true);
            va += chunk;
        }
    }

    private static ulong NextStringStart(ulong[] starts, ulong after, ulong end)
    {
        int lo = 0, hi = starts.Length;
        while (lo < hi) { int mid = (lo + hi) >> 1; if (starts[mid] <= after) lo = mid + 1; else hi = mid; }
        return lo < starts.Length && starts[lo] < end ? starts[lo] : end;
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

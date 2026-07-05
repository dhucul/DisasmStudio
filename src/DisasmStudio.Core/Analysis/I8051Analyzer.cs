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

        // 1. Strings first, so the code sweep can treat string/parameter tables as data instead of decoding
        //    them as stray instructions. 8051 firmware keeps its tables inside the one executable section.
        progress?.Report("Scanning strings…");
        var strings = StringScanner.Scan(image, includeExecutable: true, token: token).ToList();
        var stringSpans = strings.Select(s => (s.Va, End: s.Va + (ulong)Math.Max(1, s.Wide ? s.Length * 2 : s.Length)))
                                 .OrderBy(x => x.Va).ToArray();

        // 2. Linear sweep (the 8051 convention: firmware is predominantly contiguous code). Runs of >= 16
        //    identical 0x00/0xFF are skipped as padding, string spans are skipped as data, and every other
        //    decodable byte is marked code — so the whole code bank is disassembled (recursive descent alone
        //    misses code reachable only via indirect dispatch or a bank this dump doesn't contain), while the
        //    zero sea shows as data instead of a wall of NOPs.
        progress?.Report("Disassembling (linear sweep)…");
        Sweep(image, dis, code, stringSpans, callTargets, branchTargets, xrefs, token);

        // Keep only strings that didn't land inside swept code (defends against a printable run in code).
        strings = strings.Where(s => !code.IsCode(s.Va)).ToList();
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

    /// <summary>Linear sweep of the executable sections. Skips padding runs and string spans as data and
    /// marks every other decodable instruction as code, collecting call/branch targets + xrefs. An
    /// instruction is never allowed to straddle into a string span (the sweep stops the run at the span so a
    /// table isn't half-eaten by a preceding opcode).</summary>
    private static void Sweep(IBinaryImage image, INeutralDisassembler dis, CodeBitmap code,
        (ulong Va, ulong End)[] stringSpans, HashSet<ulong> callTargets, HashSet<ulong> branchTargets,
        XrefDatabase xrefs, CancellationToken token)
    {
        foreach (var sec in image.Sections)
        {
            if (!sec.IsExecutable || sec.FileSize <= 0) continue;
            ulong end = sec.StartVa + (sec.VirtualSize > 0 ? Math.Min(sec.VirtualSize, (ulong)sec.FileSize) : (ulong)sec.FileSize);
            ulong va = sec.StartVa;
            long n = 0;
            while (va < end && n < Budget)
            {
                if ((n & 0xFFFFF) == 0 && token.IsCancellationRequested) break;
                n++;

                ulong runEnd = PaddingRunEnd(image, va, end);      // > va when va starts a padding run
                if (runEnd > va) { va = runEnd; continue; }         // padding -> data

                if (InSpan(stringSpans, va, out ulong spanEnd)) { va = Math.Min(spanEnd, end); continue; }  // string -> data

                if (!dis.TryDecode(va, out var ni) || ni.Length == 0) { va++; continue; }
                ulong next = va + (ulong)ni.Length;
                if (next > NextSpanStart(stringSpans, va, end)) { va++; continue; }   // would cross a string → treat as data

                code.Mark(va, ni.Length);
                if (ni.DirectTarget is ulong t && image.IsExecutableVa(t))
                {
                    switch (ni.Flow)
                    {
                        case FlowKind.Call: callTargets.Add(t); xrefs.Add(va, t, XrefKind.Call); break;
                        case FlowKind.Jump: branchTargets.Add(t); xrefs.Add(va, t, XrefKind.Jump); break;
                        case FlowKind.CondJump: branchTargets.Add(t); xrefs.Add(va, t, XrefKind.CondJump); break;
                    }
                }
                va = next;
            }
        }
    }

    /// <summary>If a run of >= 16 identical 0x00/0xFF bytes starts at <paramref name="va"/>, return the VA
    /// just past the whole run (clamped to <paramref name="end"/>); otherwise return <paramref name="va"/>.</summary>
    private static ulong PaddingRunEnd(IBinaryImage image, ulong va, ulong end)
    {
        var b = image.ReadBytesAtVa(va, 16);
        if (b.Length < 16 || (b[0] != 0x00 && b[0] != 0xFF)) return va;
        for (int i = 1; i < 16; i++) if (b[i] != b[0]) return va;
        byte fill = b[0];
        ulong p = va + 16;
        while (p < end)
        {
            var chunk = image.ReadBytesAtVa(p, 256);
            if (chunk.Length == 0) break;
            int i = 0;
            while (i < chunk.Length && chunk[i] == fill) i++;
            p += (ulong)i;
            if (i < chunk.Length) break;
        }
        return Math.Min(p, end);
    }

    private static bool InSpan((ulong Va, ulong End)[] spans, ulong va, out ulong spanEnd)
    {
        int lo = 0, hi = spans.Length - 1;
        while (lo <= hi)
        {
            int mid = (lo + hi) >> 1;
            if (va < spans[mid].Va) hi = mid - 1;
            else if (va >= spans[mid].End) lo = mid + 1;
            else { spanEnd = spans[mid].End; return true; }
        }
        spanEnd = va; return false;
    }

    private static ulong NextSpanStart((ulong Va, ulong End)[] spans, ulong after, ulong end)
    {
        int lo = 0, hi = spans.Length;
        while (lo < hi) { int mid = (lo + hi) >> 1; if (spans[mid].Va <= after) lo = mid + 1; else hi = mid; }
        return lo < spans.Length && spans[lo].Va < end ? spans[lo].Va : end;
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

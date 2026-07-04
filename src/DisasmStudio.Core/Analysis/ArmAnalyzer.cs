using System.Text;
using DisasmStudio.Core.Disasm;
using DisasmStudio.Core.Formats;

namespace DisasmStudio.Core.Analysis;

/// <summary>
/// Analysis for ARM-family raw images (ARM / Thumb / AArch64), parallel to <see cref="AnalysisEngine"/> but
/// self-contained so the shared x86/x64 pipeline is untouched. Recursive descent over the Capstone-backed
/// <see cref="ArmDisassembler"/> from legitimate roots (the entry, any symbols, and discovered function
/// prologues) marks reachable instructions in a <see cref="CodeBitmap"/>; whatever it leaves unmarked is
/// data (literal pools, tables), so the listing separates code from constants instead of decoding pool
/// words as stray instructions. Direct <c>bl</c> targets seed functions (<c>sub_</c>) and branch targets
/// name locations (<c>loc_</c>). Produces the same <see cref="AnalysisResult"/> shape the views consume.
/// The x86-only passes (jump-table recovery, API annotation, structure fields) are simply not run.
/// </summary>
public static class ArmAnalyzer
{
    private const long Budget = 40_000_000;

    public static AnalysisResult Analyze(IBinaryImage image, IProgress<string>? progress = null,
        CancellationToken token = default)
    {
        var warnings = new List<string>();
        using var dis = new ArmDisassembler(image, image.Arch, null);   // flow-only decoder (no name substitution needed)
        var code = new CodeBitmap(image);
        var xrefs = new XrefDatabase();
        var callTargets = new HashSet<ulong>();
        var branchTargets = new HashSet<ulong>();

        // 1. Recursive descent from the entry + any symbols. Follows bl/b targets, marking reachable code and
        //    collecting call/branch targets + xrefs along the way.
        progress?.Report("Disassembling (recursive descent)…");
        var roots = new List<ulong>();
        if (image.EntryVa != 0 && image.IsExecutableVa(image.EntryVa)) roots.Add(image.EntryVa);
        foreach (var s in image.Symbols) if (image.IsExecutableVa(s.Va)) roots.Add(s.Va);
        Descend(image, dis, code, roots, callTargets, branchTargets, xrefs, token);

        // 2. Gap prologue scan: functions no bl reaches (indirectly-called) are found by their prologue and
        //    descended from. Mirrors CodeMap.GapScan for x86.
        progress?.Report("Scanning for function prologues…");
        var prologues = ScanPrologues(image, token);
        foreach (var p in prologues)
            if (image.IsExecutableVa(p) && !code.IsCode(p))
                Descend(image, dis, code, [p], callTargets, branchTargets, xrefs, token);

        // 3. Strings: scan the whole blob (firmware keeps string tables inside the one "executable" section),
        //    then keep only those starting in a data region so code isn't mined for false strings.
        progress?.Report("Scanning strings…");
        var strings = StringScanner.Scan(image, includeExecutable: true, token: token)
            .Where(s => !code.IsCode(s.Va)).ToList();
        var comments = new Dictionary<ulong, string>();
        foreach (var s in strings)
            foreach (var x in xrefs.To(s.Va))
                comments.TryAdd(x.From, Preview(s));
        var stringByVa = new Dictionary<ulong, FoundString>(strings.Count);
        foreach (var s in strings) stringByVa.TryAdd(s.Va, s);

        // 4. Names: symbols, entry, bl targets (sub_), prologue functions (sub_), branch targets (loc_).
        progress?.Report("Resolving symbols…");
        var funcStarts = new SortedSet<ulong>();
        if (image.EntryVa != 0 && image.IsExecutableVa(image.EntryVa)) funcStarts.Add(image.EntryVa);
        foreach (var s in image.Symbols) if (image.IsExecutableVa(s.Va)) funcStarts.Add(s.Va);
        foreach (var t in callTargets) funcStarts.Add(t);
        foreach (var p in prologues) if (code.IsCode(p)) funcStarts.Add(p);

        var names = new Dictionary<ulong, string>();
        foreach (var sym in image.Symbols) names[sym.Va] = sym.Name;
        if (image.EntryVa != 0 && image.IsExecutableVa(image.EntryVa)) names.TryAdd(image.EntryVa, "start");
        foreach (var t in funcStarts) names.TryAdd(t, $"sub_{t:X}");
        foreach (var t in branchTargets) names.TryAdd(t, $"loc_{t:X}");
        foreach (var sec in image.Sections) if (sec.FileSize > 0) names.TryAdd(sec.StartVa, sec.Name);

        // 5. Classified linear index: a code line per marked instruction, gaps collapsed into data.
        progress?.Report("Classifying code vs data…");
        var linear = BuildIndex(image, dis, code, stringByVa, token);

        // 6. Function list.
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
                    break;   // no fall-through
                case FlowKind.Call:
                    if (ni.DirectTarget is ulong tk && image.IsExecutableVa(tk))
                    { callTargets.Add(tk); xrefs.Add(va, tk, XrefKind.Call); work.Push(tk); }
                    work.Push(fall);
                    break;
                case FlowKind.Ret:
                case FlowKind.IndirectJump:      // unresolved computed branch — path ends here
                case FlowKind.Interrupt:
                    break;
                default:
                    work.Push(fall);             // Seq, IndirectCall — execution continues after
                    break;
            }
        }
    }

    /// <summary>Scan the executable sections for function prologues: Thumb <c>push {…,lr}</c> (0xB5xx),
    /// A32 <c>push/stmfd sp!,{…,lr}</c> (0xE92D4xxx), or AArch64 <c>stp x29,x30,[sp,…]</c>. These seed the
    /// gap descent for indirectly-called functions.</summary>
    private static List<ulong> ScanPrologues(IBinaryImage image, CancellationToken token)
    {
        var seeds = new List<ulong>();
        var arch = image.Arch;
        foreach (var sec in image.Sections)
        {
            if (!sec.IsExecutable || sec.FileSize <= 0) continue;
            if (token.IsCancellationRequested) break;
            byte[] d = image.ReadBytesAtVa(sec.StartVa, sec.FileSize);

            if (arch == Architecture.Thumb)
            {
                // Thumb PUSH {…, lr} = 0xB5xx (little-endian: high byte 0xB5) — a function entry.
                for (int i = 0; i + 1 < d.Length; i += 2)
                    if (d[i + 1] == 0xB5) seeds.Add(sec.StartVa + (ulong)i);
            }
            else if (arch == Architecture.Arm)
            {
                // A32 PUSH/STMFD sp!, {…, lr} = 0xE92D_4xxx (STMFD with the LR bit set).
                for (int i = 0; i + 3 < d.Length; i += 4)
                {
                    uint w = (uint)(d[i] | d[i + 1] << 8 | d[i + 2] << 16 | d[i + 3] << 24);
                    if ((w & 0xFFFF_4000u) == 0xE92D_4000u) seeds.Add(sec.StartVa + (ulong)i);
                }
            }
            else // Arm64: STP x29, x30, [sp, #imm]{!} — the standard AArch64 frame prologue.
            {
                for (int i = 0; i + 3 < d.Length; i += 4)
                {
                    uint w = (uint)(d[i] | d[i + 1] << 8 | d[i + 2] << 16 | d[i + 3] << 24);
                    if ((w & 0xFFC0_7FFFu) == 0xA980_7BFDu) seeds.Add(sec.StartVa + (ulong)i);
                }
            }
        }
        return seeds;
    }

    private static LinearIndex BuildIndex(IBinaryImage image, INeutralDisassembler dis, CodeBitmap code,
        IReadOnlyDictionary<ulong, FoundString> stringByVa, CancellationToken token)
    {
        var index = new LinearIndex();
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
                EmitData(index, stringByVa, ref va, gapEnd);
            }
        }
        return index;
    }

    /// <summary>Emit a data run as lines: a referenced string is one line; otherwise word-aligned 4-byte <c>dd</c>
    /// rows (ARM literal pools are 4-byte words), falling to a single byte to re-align.</summary>
    private static void EmitData(LinearIndex index, IReadOnlyDictionary<ulong, FoundString> stringByVa,
        ref ulong va, ulong end)
    {
        while (va < end)
        {
            if (stringByVa.TryGetValue(va, out var fs))
            {
                ulong slen = (ulong)Math.Max(1, fs.Wide ? fs.Length * 2 : fs.Length);
                index.Add(va, isData: true);
                va += Math.Min(slen, end - va);
            }
            else
            {
                ulong chunk = va % 4 == 0 && end - va >= 4 ? 4UL : 1UL;
                index.Add(va, isData: true);
                va += chunk;
            }
        }
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

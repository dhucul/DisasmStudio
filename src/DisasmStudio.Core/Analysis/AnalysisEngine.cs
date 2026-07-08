using System.Text;
using DisasmStudio.Core.Analysis.Signatures;
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

    /// <summary>Analyse with default options (code only) — preserves the original (image, progress, token)
    /// call shape for callers that don't fold in extra sections.</summary>
    public static AnalysisResult Analyze(IBinaryImage image, IProgress<string>? progress,
        CancellationToken token = default) => Analyze(image, null, progress, token);

    public static AnalysisResult Analyze(IBinaryImage image, AnalysisOptions? options = null,
        IProgress<string>? progress = null, CancellationToken token = default)
    {
        // Non-x86 raw images use self-contained pipelines; the x86/x64 Iced passes below don't apply.
        if (image.IsArm) return ArmAnalyzer.Analyze(image, progress, token);       // ARM/Thumb/AArch64 (Capstone)
        if (image.Is8051) return I8051Analyzer.Analyze(image, progress, token);     // Intel 8051/MCS-51

        options ??= AnalysisOptions.None;
        var warnings = new List<string>();

        progress?.Report("Disassembling (linear sweep)…");
        var sweepIndex = new LinearIndex();   // full instruction stream — used for backtracking analyses
        var xrefs = new XrefDatabase();
        var callTargets = new HashSet<ulong>();
        var branchTargets = new HashSet<ulong>();
        var dataTargets = new HashSet<ulong>();   // every address referenced as data (gates exec-section strings)
        var comments = new Dictionary<ulong, string>();
        var dis = new Disassembler(image);
        var dataRefs = new List<ulong>();
        var apiCalls = new List<(ulong CallVa, string Import)>();   // call [iat] sites
        var thunks = new Dictionary<ulong, string>();               // jmp [iat] thunk VA → import name
        var indirectJmps = new List<ulong>();                       // candidate switch dispatchers
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
                if ((sweepIndex.Count & 0x3FFFF) == 0 && token.IsCancellationRequested)
                {
                    warnings.Add("Analysis cancelled — partial result.");
                    goto done;
                }
                if (sweepIndex.Count >= MaxInstructions) { capped = true; goto done; }

                if (!dis.TryDecodeAt(va, out var instr)) { va++; continue; }
                sweepIndex.Add(va);
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

                // Recognise Windows API references: call/jmp through an IAT slot.
                if ((instr.Mnemonic is Mnemonic.Call or Mnemonic.Jmp) && instr.Op0Kind == OpKind.Memory)
                {
                    ulong slot = instr.IsIPRelativeMemoryOperand ? instr.IPRelativeMemoryAddress
                        : instr.MemoryBase == Register.None && instr.MemoryIndex == Register.None ? instr.MemoryDisplacement64 : 0;
                    if (slot != 0 && image.ImportsByIatVa.TryGetValue(slot, out var imp))
                    {
                        if (instr.Mnemonic == Mnemonic.Call) apiCalls.Add((ip, imp.Name));
                        else thunks[ip] = imp.Name; // jmp [iat] is an import thunk — its callers are the call sites
                    }
                }

                // Collect indirect branches (both jmp reg and jmp [mem]) as switch-dispatch candidates —
                // a separate check, not chained off the IAT block above, so memory-form jmps are included.
                if (instr.FlowControl == FlowControl.IndirectBranch && indirectJmps.Count < 200_000)
                    indirectJmps.Add(ip);

                va += (ulong)instr.Length;
            }
        }
    done:
        if (capped) warnings.Add($"Instruction cap ({MaxInstructions:N0}) reached — linear view truncated.");

        // Recover jump tables (compiled switches) so their case targets become followed, labelled CFG
        // edges instead of dead-ending the control flow at the indirect jmp.
        progress?.Report("Recovering jump tables…");
        var jumpTables = new Dictionary<ulong, ulong[]>();
        foreach (var jva in indirectJmps)
        {
            if (token.IsCancellationRequested) break;
            if (!JumpTableRecovery.TryRecover(image, sweepIndex, dis, jva, out var tgts)) continue;
            jumpTables[jva] = tgts;
            comments[jva] = $"switch ({tgts.Length} cases)";
            foreach (var t in tgts) { xrefs.Add(jva, t, XrefKind.Jump); branchTargets.Add(t); }
        }

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

        // Annotate Windows API call sites (IDA/BN-style) with parameters + recovered argument values.
        // Direct calls into jmp[iat] thunks resolve via the thunk's callers.
        progress?.Report("Annotating API calls…");
        foreach (var (thunkVa, name) in thunks)
            foreach (var x in xrefs.To(thunkVa))
                if (x.Kind == XrefKind.Call) apiCalls.Add((x.From, name));
        var stringByVa = new Dictionary<ulong, FoundString>(strings.Count);
        foreach (var s in strings) stringByVa.TryAdd(s.Va, s);
        ApiAnnotator.Annotate(image, sweepIndex, apiCalls, names, stringByVa, comments);

        // Recursive-descent code map from legitimate roots (entry, exports/symbols, and code pointers
        // referenced from data). Whatever it leaves unmarked inside .text is data.
        progress?.Report("Mapping reachable code…");
        var ptrTargets = new List<ulong>();
        var ptrSeen = new HashSet<ulong>();
        foreach (var d in dataTargets) if (image.IsExecutableVa(d) && ptrSeen.Add(d)) ptrTargets.Add(d);
        // Code pointers living in data (vtables, callback/jump tables) — reach methods no instruction names.
        foreach (var d in PointerScanner.CollectCodePointers(image, token: token)) if (ptrSeen.Add(d)) ptrTargets.Add(d);
        var code = CodeMap.Compute(image, CodeSeeds(image, ptrTargets), jumpTables, token);

        // Gap scan: find function prologues in the unmarked .text gaps (chiefly indirectly-called
        // functions — on a CET build these begin with endbr64) and descend from them. Name + list them.
        progress?.Report("Scanning gaps for functions…");
        foreach (var f in CodeMap.GapScan(image, code, jumpTables, token))
        {
            names.TryAdd(f, $"sub_{f:X}");
            ptrTargets.Add(f);
        }

        // Classified linear index: real instructions, with padding / jump tables / literals collapsed
        // into data lines instead of disassembled junk.
        // Structured data: parse the PE header, .pdata (RUNTIME_FUNCTIONs) and .reloc (fixup blocks) into
        // labelled fields so — when loaded into the listing — they render as structure (dd/dw + field-name
        // comments, begin RVAs resolved to function names) instead of a wall of db bytes.
        var fieldList = new List<(ulong Va, int Size)>();
        bool InLoaded(ulong va)
        {
            var s = image.SectionAt(va);
            if (s is not null) return s.IsExecutable || options.IncludedDataSections.Contains(s.Name);
            return options.IncludeHeader && image.HeaderRegion is { } hh && va >= hh.StartVa && va < hh.StartVa + (ulong)hh.FileSize;
        }
        void AddFields(IReadOnlyList<HeaderField> flds)
        {
            foreach (var fld in flds)
            {
                if (!InLoaded(fld.Va)) continue;   // only the fields that land in a loaded region show
                if (fld.Label.Length > 0)
                    comments[fld.Va] = fld.RefVa != 0 && names.TryGetValue(fld.RefVa, out var nm)
                        ? $"{fld.Label} ({nm})" : fld.Label;
                fieldList.Add((fld.Va, fld.Size));
            }
        }
        if (options.IncludeHeader && image.Format == BinaryFormat.Pe && image.HeaderRegion is { } hr)
        {
            AddFields(PeHeaderLayout.Describe(image));
            names.TryAdd(hr.StartVa, "HEADER");
        }
        // Name each in-listing section start (code always; data when loaded) as a collapsible landmark, and
        // structure-parse the loaded .pdata / .reloc. TryAdd keeps a real function name if one starts there.
        foreach (var sec in image.Sections)
        {
            if (sec.FileSize <= 0 || !(sec.IsExecutable || options.IncludedDataSections.Contains(sec.Name))) continue;
            names.TryAdd(sec.StartVa, sec.Name);
            if (options.IncludedDataSections.Contains(sec.Name))
            {
                if (sec.Name == ".pdata") AddFields(PeHeaderLayout.DescribePdata(image, sec));
                else if (sec.Name == ".reloc") AddFields(PeHeaderLayout.DescribeReloc(image, sec));
            }
        }
        // Import / export / TLS / debug tables (typically in .rdata/.idata/.edata/.tls) — parsed wherever they
        // live and kept only where their section is loaded. Skipped entirely when no data section is loaded.
        if (image is PeImage pe && options.IncludedDataSections.Count > 0)
        {
            try { AddFields(PeHeaderLayout.DescribeImports(pe)); } catch { }
            try { AddFields(PeHeaderLayout.DescribeExports(pe)); } catch { }
            try { AddFields(PeHeaderLayout.DescribeTls(pe)); } catch { }
            try { AddFields(PeHeaderLayout.DescribeDebug(pe)); } catch { }
        }
        fieldList.Sort((a, b) => a.Va.CompareTo(b.Va));
        var fields = fieldList.ToArray();

        progress?.Report("Classifying code vs data…");
        var linear = BuildClassifiedIndex(image, code, stringByVa, options, fields, token);

        progress?.Report("Identifying functions…");
        var jumpTargets = new HashSet<ulong>();
        foreach (var ts in jumpTables.Values) foreach (var t in ts) jumpTargets.Add(t);
        var (functions, byVa) = BuildFunctions(image, names, callTargets, ptrTargets, code, jumpTargets);

        // Library-function identification (FLIRT/FID-lite): name still-unnamed functions whose prologue matches
        // a known signature. No-op unless the user has generated/imported signatures into signatures/*.sig.
        int libNamed = 0;
        if (SignatureLibrary.Shared.Count > 0)
        {
            progress?.Report("Matching library signatures…");
            libNamed = SignatureMatcher.Apply(image, functions, names, comments, SignatureLibrary.Shared);
        }

        progress?.Report($"Done — {functions.Count:N0} functions, {strings.Count:N0} strings, {jumpTables.Count:N0} switches" +
            (libNamed > 0 ? $", {libNamed:N0} library-named." : "."));

        return new AnalysisResult
        {
            Image = image,
            Linear = linear,
            Functions = functions,
            FunctionByVa = byVa,
            Xrefs = xrefs,
            Strings = strings,
            JumpTables = jumpTables,
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
        foreach (var sym in image.Symbols) names[sym.Va] = Demangler.Demangle(sym.Name);   // imports, exports, ELF funcs (C++ demangled)
        if (image.EntryVa != 0 && image.IsExecutableVa(image.EntryVa)) names.TryAdd(image.EntryVa, "start");
        foreach (var f in image.FunctionStarts) names.TryAdd(f, $"sub_{f:X}");   // .pdata functions
        foreach (var t in callTargets) names.TryAdd(t, $"sub_{t:X}");
        foreach (var t in branchTargets) names.TryAdd(t, $"loc_{t:X}");
        return names;
    }

    /// <summary>Legitimate roots for the recursive-descent code map.</summary>
    private static IEnumerable<ulong> CodeSeeds(IBinaryImage image, List<ulong> ptrTargets)
    {
        if (image.EntryVa != 0) yield return image.EntryVa;
        foreach (var f in image.FunctionStarts) yield return f;   // PE x64 .pdata — authoritative function list
        foreach (var sym in image.Symbols)
            if (sym.Kind is NamedSymbolKind.Function or NamedSymbolKind.Export) yield return sym.Va;
        foreach (var d in ptrTargets) yield return d;   // code pointers stored in data (gap functions)
    }

    private static (List<Function>, Dictionary<ulong, Function>) BuildFunctions(IBinaryImage image,
        IReadOnlyDictionary<ulong, string> names, HashSet<ulong> callTargets,
        List<ulong> ptrTargets, CodeBitmap code, HashSet<ulong> jumpTargets)
    {
        var seeds = new SortedSet<ulong>();
        if (image.EntryVa != 0 && image.IsExecutableVa(image.EntryVa)) seeds.Add(image.EntryVa);
        foreach (var sym in image.Symbols)
            if (sym.Kind is NamedSymbolKind.Function or NamedSymbolKind.Export && image.IsExecutableVa(sym.Va))
                seeds.Add(sym.Va);
        foreach (var f in image.FunctionStarts) if (image.IsExecutableVa(f)) seeds.Add(f);
        foreach (var t in callTargets) seeds.Add(t);
        // Gap pass: a code pointer stored in data (callback / vtable entry) that the code map confirmed
        // is real code, and isn't merely a jump-table case, is an indirect-only function.
        foreach (var d in ptrTargets)
            if (code.IsCode(d) && !jumpTargets.Contains(d)) seeds.Add(d);

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

    /// <summary>
    /// Produce the display index over an address-ordered set of regions: a code line per real instruction
    /// (in executable sections, classified via the code map) and data runs (referenced strings as one
    /// line; aligned pointers as dd/dq; otherwise db rows ≤16 B) for everything else. Non-executable
    /// sections (and the PE header) the user folded in via <paramref name="options"/> are emitted purely
    /// as data. Regions are emitted in strictly ascending, non-overlapping VA order — the index is
    /// binary-searched, so duplicate/out-of-order entries would break navigation.
    /// </summary>
    private static LinearIndex BuildClassifiedIndex(IBinaryImage image, CodeBitmap code,
        IReadOnlyDictionary<ulong, FoundString> stringByVa, AnalysisOptions options,
        (ulong Va, int Size)[] fields, CancellationToken token)
    {
        var index = new LinearIndex();
        var dis = new Disassembler(image);

        var regions = new List<(ulong Start, ulong End, bool IsCode)>();
        foreach (var sec in image.Sections)
        {
            if (sec.FileSize <= 0) continue;
            ulong end = sec.StartVa + (sec.VirtualSize > 0 ? Math.Min(sec.VirtualSize, (ulong)sec.FileSize) : (ulong)sec.FileSize);
            if (sec.IsExecutable) regions.Add((sec.StartVa, end, true));
            else if (options.IncludedDataSections.Contains(sec.Name)) regions.Add((sec.StartVa, end, false));
        }
        if (options.IncludeHeader && image.HeaderRegion is { FileSize: > 0 } h)
            regions.Add((h.StartVa, h.StartVa + (ulong)h.FileSize, false));

        regions.Sort((a, b) => a.Start.CompareTo(b.Start));
        // Clamp each region's end to the next region's start so emitted VAs never overlap or go backwards.
        for (int i = 0; i < regions.Count - 1; i++)
            if (regions[i].End > regions[i + 1].Start)
                regions[i] = (regions[i].Start, regions[i + 1].Start, regions[i].IsCode);

        foreach (var (start, end, isCode) in regions)
        {
            ulong va = start;
            while (va < end)
            {
                if ((index.Count & 0x3FFFF) == 0 && token.IsCancellationRequested) return index;

                if (isCode && code.IsCode(va))
                {
                    if (dis.TryDecodeAt(va, out var ins) && ins.Length > 0) { index.Add(va); va += (ulong)ins.Length; }
                    else { index.Add(va, isData: true); va++; } // defensive — code map only marks decodable
                    continue;
                }

                // Data run: a code section's gap stops at the next code byte; a data region runs to its end.
                // Parsed structure fields (header / .pdata / .reloc) inside the run are emitted at their own
                // boundaries; everything else falls to strings / dd-dq pointers / db rows.
                ulong gapEnd = isCode ? code.NextCode(va, end) : end;
                EmitData(index, image, stringByVa, fields, ref va, gapEnd, token);
            }
        }
        return index;
    }

    /// <summary>Emit one data run [va, end) as lines. A parsed structure field (from <paramref name="fields"/>,
    /// sorted by VA) is emitted at its exact size; otherwise a referenced string is one line, an aligned
    /// pointer is dd/dq, and the rest are db rows of ≤16 bytes — but never crossing the next field boundary.</summary>
    private static void EmitData(LinearIndex index, IBinaryImage image,
        IReadOnlyDictionary<ulong, FoundString> stringByVa, (ulong Va, int Size)[] fields,
        ref ulong va, ulong end, CancellationToken token)
    {
        int fi = LowerBound(fields, va);   // first field at/after va
        while (va < end)
        {
            if ((index.Count & 0x3FFFF) == 0 && token.IsCancellationRequested) return;
            while (fi < fields.Length && fields[fi].Va < va) fi++;   // keep the cursor at/after va

            if (fi < fields.Length && fields[fi].Va == va)           // a parsed structure field
            {
                index.Add(va, isData: true);
                va += (ulong)Math.Min(Math.Max(1, fields[fi].Size), (int)Math.Min(end - va, int.MaxValue));
                fi++;
                continue;
            }

            ulong stop = fi < fields.Length && fields[fi].Va < end ? fields[fi].Va : end;   // don't cross a field
            if (stringByVa.TryGetValue(va, out var fs))
            {
                ulong slen = (ulong)Math.Max(1, fs.Wide ? fs.Length * 2 : fs.Length);
                index.Add(va, isData: true);
                va += Math.Min(slen, stop - va);
            }
            else
            {
                ulong rem = stop - va;
                ulong chunk =
                    va % 8 == 0 && rem >= 8 && IsPointer(image, va, 8) ? 8 :
                    va % 4 == 0 && rem >= 4 && IsPointer(image, va, 4) ? 4 :
                    Math.Min(16, rem);
                index.Add(va, isData: true);
                va += Math.Max(1, chunk);
            }
        }
    }

    /// <summary>Index of the first field with VA ≥ <paramref name="va"/> (binary search over the sorted array).</summary>
    private static int LowerBound((ulong Va, int Size)[] fields, ulong va)
    {
        int lo = 0, hi = fields.Length;
        while (lo < hi) { int m = (lo + hi) >> 1; if (fields[m].Va < va) lo = m + 1; else hi = m; }
        return lo;
    }

    private static bool IsPointer(IBinaryImage image, ulong va, int size)
    {
        var b = image.ReadBytesAtVa(va, size);
        if (b.Length < size) return false;
        ulong v = size == 8 ? BitConverter.ToUInt64(b, 0) : BitConverter.ToUInt32(b, 0);
        return image.IsMappedVa(v);
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

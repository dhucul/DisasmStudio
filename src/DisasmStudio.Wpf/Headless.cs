using System.IO;
using System.Text;
using System.Text.Json;
using DisasmStudio.Core.Analysis;
using DisasmStudio.Core.Analysis.Signatures;
using DisasmStudio.Core.Export;
using DisasmStudio.Core.Formats;
using DisasmStudio.Core.IL;

namespace DisasmStudio.Wpf;

/// <summary>
/// Headless (no-GUI) command-line mode — a Ghidra <c>analyzeHeadless</c>-style front end over the Core
/// analysis engine, so DisasmStudio can be scripted or dropped into a pipeline. Reached from
/// <see cref="App.OnStartup"/> when the first argument is a headless verb; it runs entirely on Core (never
/// touches WPF), writes to stdout or <c>--out</c>, and the app exits without creating a window.
///
/// Verbs: analyze · disasm · decompile · callgraph · siggen · emulate · help.
/// </summary>
public static class Headless
{
    private static readonly HashSet<string> Verbs = new(StringComparer.OrdinalIgnoreCase)
        { "analyze", "disasm", "decompile", "callgraph", "siggen", "emulate", "help", "--help", "-h" };

    /// <summary>True when <paramref name="arg"/> selects headless mode (the App routes here instead of the GUI).</summary>
    public static bool IsHeadlessVerb(string arg) => Verbs.Contains(arg);

    public static int Run(string[] args, bool hasConsole)
    {
        // Make Console.Out flow to the attached parent console (a WinExe has no console by default).
        if (hasConsole) { try { Console.SetOut(new StreamWriter(Console.OpenStandardOutput()) { AutoFlush = true }); } catch { } }

        string verb = args.Length > 0 ? args[0].ToLowerInvariant() : "help";
        if (verb is "help" or "--help" or "-h") { Usage(Console.Out); return 0; }

        var opt = Opts.Parse(args[1..]);
        if (opt.Input is null) { Console.Error.WriteLine("error: no input file given."); Usage(Console.Error); return 1; }
        if (!File.Exists(opt.Input)) { Console.Error.WriteLine($"error: file not found: {opt.Input}"); return 2; }

        IBinaryImage image;
        try { image = LoadImage(opt); }
        catch (Exception ex) { Console.Error.WriteLine($"error loading '{opt.Input}': {ex.Message}\n(hint: for a flat blob pass --raw --base <hex> --arch <x86|x64|arm|thumb|arm64|8051>)"); return 2; }

        AnalysisResult result;
        try { result = AnalysisEngine.Analyze(image, BuildOptions(opt, image), opt.Verbose ? new SyncProgress(s => Console.Error.WriteLine(s)) : null); }
        catch (Exception ex) { Console.Error.WriteLine($"analysis failed: {ex.Message}"); return 2; }

        var (w, dispose) = OpenOut(opt);
        try
        {
            return verb switch
            {
                "analyze" => Analyze(w, result, opt),
                "disasm" => Disasm(w, result, opt),
                "decompile" => Decompile(w, result, opt),
                "callgraph" => CallGraphCmd(w, result, opt),
                "siggen" => SigGen(w, result, opt),
                "emulate" => Emulate(w, result, opt),
                _ => Unknown(verb),
            };
        }
        catch (Exception ex) { Console.Error.WriteLine($"'{verb}' failed: {ex.Message}"); return 2; }
        finally { w.Flush(); if (dispose) w.Dispose(); if (opt.Out is { } f) Console.Error.WriteLine($"wrote {f}"); }
    }

    // ---- verbs ----

    private static int Analyze(TextWriter w, AnalysisResult r, Opts opt)
    {
        var img = r.Image;
        int cap = opt.Limit > 0 ? opt.Limit : int.MaxValue;
        var funcs = r.Functions.OrderBy(f => f.Va).Take(cap)
            .Select(f => new { va = Hex(f.Va), name = f.Name, section = img.SectionAt(f.Va)?.Name ?? "" }).ToList();
        var strings = r.Strings.Take(cap).Select(s => new { va = Hex(s.Va), text = s.Text, wide = s.Wide }).ToList();
        var imports = img.Imports.Take(cap).Select(i => new { va = Hex(i.IatVa), module = i.Module, name = i.Name }).ToList();
        var exports = img.Symbols.Where(s => s.Kind == NamedSymbolKind.Export).Take(cap)
            .Select(s => new { va = Hex(s.Va), name = s.Name }).ToList();

        if (opt.Json)
        {
            var obj = new
            {
                file = img.FilePath,
                format = img.FormatName,
                arch = img.ArchName,
                bits = img.Bitness,
                imageBase = Hex(img.ImageBase),
                entry = Hex(img.EntryVa),
                counts = new { functions = r.Functions.Count, strings = r.Strings.Count, imports = img.Imports.Count, exports = img.Symbols.Count(s => s.Kind == NamedSymbolKind.Export), warnings = r.Warnings.Count },
                warnings = r.Warnings,
                functions = funcs,
                strings,
                imports,
                exports,
            };
            w.WriteLine(JsonSerializer.Serialize(obj, new JsonSerializerOptions { WriteIndented = true }));
            return 0;
        }

        w.WriteLine($"{Path.GetFileName(img.FilePath)}   {img.FormatName}   {img.ArchName}   base {Hex(img.ImageBase)}   entry {Hex(img.EntryVa)}");
        w.WriteLine($"functions {r.Functions.Count:N0}   strings {r.Strings.Count:N0}   imports {img.Imports.Count:N0}   exports {exports.Count:N0}");
        foreach (var warn in r.Warnings) w.WriteLine($"  ! {warn}");
        if (opt.Has("functions")) { w.WriteLine("\n[functions]"); foreach (var f in funcs) w.WriteLine($"  {f.va}  {f.name}  ({f.section})"); }
        if (opt.Has("strings")) { w.WriteLine("\n[strings]"); foreach (var s in strings) w.WriteLine($"  {s.va}  {(s.wide ? "L" : "")}\"{s.text}\""); }
        if (opt.Has("imports")) { w.WriteLine("\n[imports]"); foreach (var i in imports) w.WriteLine($"  {i.va}  {i.module}!{i.name}"); }
        if (opt.Has("exports")) { w.WriteLine("\n[exports]"); foreach (var e in exports) w.WriteLine($"  {e.va}  {e.name}"); }
        return 0;
    }

    private static int Disasm(TextWriter w, AnalysisResult r, Opts opt)
    {
        if (opt.Func is ulong fv) { if (FindFunc(r, fv) is { } fn) SourceExporter.WriteAsmFunction(w, r, fn); else { Console.Error.WriteLine($"no function at {Hex(fv)}"); return 2; } }
        else SourceExporter.WriteAsm(w, r);
        return 0;
    }

    private static int Decompile(TextWriter w, AnalysisResult r, Opts opt)
    {
        if (opt.Func is ulong fv)
        {
            if (FindFunc(r, fv) is not { } fn) { Console.Error.WriteLine($"no function at {Hex(fv)}"); return 2; }
            if (opt.Has("compilable")) SourceExporter.WriteCompilableCFunction(w, r, fn); else SourceExporter.WriteCFunction(w, r, fn);
        }
        else if (opt.Has("compilable")) SourceExporter.WriteCompilableC(w, r);
        else SourceExporter.WriteC(w, r);
        return 0;
    }

    private static int CallGraphCmd(TextWriter w, AnalysisResult r, Opts opt)
    {
        var g = CallGraph.Build(r);
        bool callers = opt.Has("callers");
        if (opt.Json)
        {
            var edges = r.Functions.OrderBy(f => f.Va)
                .Select(f => new { va = Hex(f.Va), name = f.Name, callees = g.Callees(f.Va).Select(Hex).ToList(), callers = g.Callers(f.Va).Select(Hex).ToList() })
                .Where(e => e.callees.Count > 0 || e.callers.Count > 0).ToList();
            w.WriteLine(JsonSerializer.Serialize(new { edgeCount = g.EdgeCount, functions = edges }, new JsonSerializerOptions { WriteIndented = true }));
            return 0;
        }
        ulong root = opt.Func ?? (r.Image.EntryVa != 0 ? r.Image.EntryVa : r.Functions.Count > 0 ? r.Functions[0].Va : 0);
        root = g.ContainingFunction(root) is var c && c != 0 ? c : root;
        int depth = opt.Depth > 0 ? opt.Depth : 8;
        w.WriteLine($"{(callers ? "callers" : "callees")} of {NameFor(r, root)} ({g.EdgeCount:N0} edges)");
        PrintTree(w, r, g, root, callers, depth, 0, []);
        return 0;
    }

    private static void PrintTree(TextWriter w, AnalysisResult r, CallGraph g, ulong va, bool callers, int maxDepth, int depth, HashSet<ulong> path)
    {
        w.WriteLine(new string(' ', depth * 2) + (depth == 0 ? "" : "→ ") + NameFor(r, va) + (path.Contains(va) ? "  ↺" : ""));
        if (depth >= maxDepth || !path.Add(va)) return;
        foreach (var c in callers ? g.Callers(va) : g.Callees(va)) PrintTree(w, r, g, c, callers, maxDepth, depth + 1, path);
        path.Remove(va);
    }

    private static int SigGen(TextWriter w, AnalysisResult r, Opts opt)
    {
        var sigs = SignatureMatcher.Generate(r);
        w.WriteLine($"# {sigs.Count} signatures generated from {Path.GetFileName(r.Image.FilePath)} ({r.Image.ArchName})");
        foreach (var s in sigs) w.WriteLine(s.Serialize());
        Console.Error.WriteLine($"generated {sigs.Count} signature(s)" + (opt.Out is null ? " (use --out file.sig to save)" : ""));
        return sigs.Count > 0 ? 0 : 2;
    }

    private static int Emulate(TextWriter w, AnalysisResult r, Opts opt)
    {
        if (opt.Func is not ulong fv) { Console.Error.WriteLine("emulate: --func <hex> is required."); return 1; }
        if (FindFunc(r, fv) is not { } fn) { Console.Error.WriteLine($"no function at {Hex(fv)}"); return 2; }
        var er = DisasmStudio.Core.IL.Decompiler.Emulate(fn, r);

        var runs = ContiguousRuns(er.MemoryWrites);
        if (opt.Json)
        {
            var obj = new
            {
                function = new { va = Hex(fn.Va), name = fn.Name },
                status = er.Status.ToString(),
                steps = er.Steps,
                values = er.Values.Values.OrderBy(v => v.Va).Select(v => new { va = Hex(v.Va), reg = v.Reg, value = Hex((ulong)v.Value), width = v.Width }),
                branches = er.Branches.DistinctBy(b => b.Va).OrderBy(b => b.Va).Select(b => new { va = Hex(b.Va), alwaysTaken = b.Taken }),
                decrypted = runs.Select(run => new { start = Hex(run.Start), bytes = Convert.ToHexString(run.Bytes), ascii = Ascii(run.Bytes) }),
            };
            w.WriteLine(JsonSerializer.Serialize(obj, new JsonSerializerOptions { WriteIndented = true }));
            return 0;
        }
        w.WriteLine($"emulate {fn.Name} @ {Hex(fn.Va)} — {er.Status}, {er.Steps:N0} steps");
        w.WriteLine($"\n[resolved values] ({er.Values.Count})");
        foreach (var v in er.Values.Values.OrderBy(v => v.Va)) w.WriteLine($"  {Hex(v.Va)}  {v.Reg} = 0x{(ulong)v.Value:X}");
        w.WriteLine($"\n[folded branches] ({er.Branches.DistinctBy(b => b.Va).Count()})");
        foreach (var b in er.Branches.DistinctBy(b => b.Va).OrderBy(b => b.Va)) w.WriteLine($"  {Hex(b.Va)}  {(b.Taken ? "always taken" : "never taken")}");
        w.WriteLine($"\n[decrypted bytes] ({er.MemoryWrites.Count})");
        foreach (var run in runs) w.WriteLine($"  {Hex(run.Start)}  [{run.Bytes.Length} B]  \"{Ascii(run.Bytes)}\"\n    {Convert.ToHexString(run.Bytes)}");
        return 0;
    }

    // ---- helpers ----

    private static IBinaryImage LoadImage(Opts opt)
    {
        if (opt.Has("raw") || opt.Base is not null)
        {
            var arch = ParseArch(opt.Arch);
            int bits = arch is Architecture.X64 or Architecture.Arm64 ? 64 : arch is Architecture.I8051 ? 16 : 32;
            ulong baseVa = opt.Base ?? (bits == 64 ? 0x140000000UL : 0x400000UL);
            ulong entry = opt.Entry ?? baseVa;
            return RawImage.Load(opt.Input!, baseVa, bits, entry, arch, null);
        }
        return BinaryLoader.Load(opt.Input!);
    }

    private static AnalysisOptions BuildOptions(Opts opt, IBinaryImage image)
    {
        if (opt.Sections is null && !opt.Has("header") && !opt.Has("all-sections")) return AnalysisOptions.None;
        var set = new HashSet<string>();
        if (opt.Has("all-sections")) foreach (var s in image.Sections) if (!s.IsExecutable && s.FileSize > 0) set.Add(s.Name);
        if (opt.Sections is { } names) foreach (var n in names.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)) set.Add(n);
        return new AnalysisOptions { IncludedDataSections = set, IncludeHeader = opt.Has("header") };
    }

    private static Architecture ParseArch(string? a) => (a ?? "x64").ToLowerInvariant() switch
    {
        "x86" or "x32" or "i386" => Architecture.X86,
        "arm" => Architecture.Arm,
        "thumb" => Architecture.Thumb,
        "arm64" or "aarch64" => Architecture.Arm64,
        "8051" or "mcs51" => Architecture.I8051,
        _ => Architecture.X64,
    };

    /// <summary>The function starting at <paramref name="va"/>, else the one that contains it.</summary>
    private static Function? FindFunc(AnalysisResult r, ulong va)
    {
        if (r.FunctionByVa.TryGetValue(va, out var f)) return f;
        Function? best = null;
        foreach (var fn in r.Functions) if (fn.Va <= va && (best is null || fn.Va > best.Va)) best = fn;
        return best;
    }

    private static string NameFor(AnalysisResult r, ulong va) => r.NameFor(va) is { Length: > 0 } n ? n : $"sub_{va:X}";
    private static string Hex(ulong v) => v.ToString("X");
    private static string Ascii(byte[] b) { var sb = new StringBuilder(b.Length); foreach (var x in b) sb.Append(x is >= 0x20 and < 0x7F ? (char)x : '.'); return sb.ToString(); }

    private static List<(ulong Start, byte[] Bytes)> ContiguousRuns(SortedDictionary<ulong, byte> writes)
    {
        var runs = new List<(ulong, byte[])>();
        List<byte>? cur = null; ulong start = 0, prev = 0;
        foreach (var (addr, b) in writes)
        {
            if (cur is null || addr != prev + 1) { if (cur is not null) runs.Add((start, cur.ToArray())); cur = []; start = addr; }
            cur.Add(b); prev = addr;
        }
        if (cur is not null) runs.Add((start, cur.ToArray()));
        return runs;
    }

    private static (TextWriter, bool) OpenOut(Opts opt) =>
        opt.Out is { } f ? (new StreamWriter(f, false, new UTF8Encoding(false)), true) : (Console.Out, false);

    private static int Unknown(string verb) { Console.Error.WriteLine($"unknown verb: {verb}"); Usage(Console.Error); return 1; }

    private static void Usage(TextWriter w)
    {
        w.WriteLine("""
            DisasmStudio — headless mode

            Usage:  DisasmStudio <verb> <binary> [options]

            Verbs:
              analyze     Analyse and summarise (add --functions/--strings/--imports/--exports, or --json)
              disasm      Emit the full disassembly listing (or one --func)
              decompile   Emit decompiled Pseudo-C (--compilable for compilable C, or one --func)
              callgraph   Emit the static call graph (tree from --func / entry; --callers; --json)
              siggen      Generate FLIRT/FID-lite signatures (use --out file.sig)
              emulate     Emulate a function (--func <hex>): resolve constants, decrypt data, fold predicates

            Options:
              --out <file>        Write output to a file instead of stdout
              --json              Structured JSON output (analyze / callgraph / emulate)
              --func <hex>        Target function VA (disasm/decompile/callgraph/emulate)
              --limit <n>         Cap list sizes (analyze)
              --depth <n>         Call-graph tree depth (default 8)
              --sections a,b      Fold these data sections into analysis; --all-sections for all; --header
              --raw --base <hex>  Load a flat blob;  --arch x86|x64|arm|thumb|arm64|8051  --entry <hex>
              --verbose           Progress to stderr

            Examples:
              DisasmStudio analyze app.exe --json --out app.json
              DisasmStudio decompile app.exe --func 401000
              DisasmStudio callgraph app.exe --func 401000 --depth 4
              DisasmStudio emulate app.exe --func 401500 --json
              DisasmStudio siggen mylib.dll --out mylib.sig
            """);
    }

    // ---- tiny arg parser + synchronous progress ----

    private sealed class Opts
    {
        public string? Input;
        public string? Out;
        public string? Sections;
        public string? Arch;
        public ulong? Base, Entry, Func;
        public int Limit, Depth;
        public bool Json, Verbose;
        private readonly HashSet<string> _flags = new(StringComparer.OrdinalIgnoreCase);

        public bool Has(string flag) => _flags.Contains(flag);

        public static Opts Parse(string[] args)
        {
            var o = new Opts();
            for (int i = 0; i < args.Length; i++)
            {
                string a = args[i];
                if (!a.StartsWith('-')) { o.Input ??= a; continue; }
                string key = a.TrimStart('-').ToLowerInvariant();
                string? Next() => i + 1 < args.Length && !args[i + 1].StartsWith('-') ? args[++i] : null;
                switch (key)
                {
                    case "out": o.Out = Next(); break;
                    case "sections": o.Sections = Next(); break;
                    case "arch": o.Arch = Next(); break;
                    case "base": o.Base = ParseHex(Next()); break;
                    case "entry": o.Entry = ParseHex(Next()); break;
                    case "func" or "function": o.Func = ParseHex(Next()); break;
                    case "limit": o.Limit = int.TryParse(Next(), out var l) ? l : 0; break;
                    case "depth": o.Depth = int.TryParse(Next(), out var d) ? d : 0; break;
                    case "json": o.Json = true; o._flags.Add("json"); break;
                    case "verbose": o.Verbose = true; break;
                    default: o._flags.Add(key); break;
                }
            }
            return o;
        }

        private static ulong? ParseHex(string? s)
        {
            if (string.IsNullOrWhiteSpace(s)) return null;
            s = s.Trim();
            if (s.StartsWith("0x", StringComparison.OrdinalIgnoreCase)) s = s[2..];
            return ulong.TryParse(s, System.Globalization.NumberStyles.HexNumber, System.Globalization.CultureInfo.InvariantCulture, out var v) ? v : null;
        }
    }

    private sealed class SyncProgress(Action<string> f) : IProgress<string> { public void Report(string value) => f(value); }
}

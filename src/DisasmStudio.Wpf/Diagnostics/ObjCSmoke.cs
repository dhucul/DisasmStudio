using System.IO;
using System.Text;
using DisasmStudio.Core.Analysis;
using DisasmStudio.Core.Formats;

namespace DisasmStudio.Wpf.Diagnostics;

/// <summary>
/// Hidden self-test (<c>--smoke-objc &lt;file&gt;</c>) for the Mach-O loader and Objective-C metadata parser.
/// Loads a thin (or fat, auto-sliced) Mach-O, dumps its sections/symbols/Obj-C classes for eyeballing, runs the
/// analysis engine, and asserts the load produced sections, symbols, and a non-trivial function count. Prints to
/// the launching console and also writes <c>%TEMP%\disasmstudio_smoke_objc.txt</c>; returns 0 when all pass.
/// </summary>
internal static class ObjCSmoke
{
    public static int Run(string path)
    {
        int pass = 0, fail = 0;
        var log = new StringBuilder();
        void Line(string s) { Console.WriteLine(s); log.AppendLine(s); }
        void Check(string name, bool ok) { Line($"[{(ok ? "PASS" : "FAIL")}] {name}"); if (ok) pass++; else fail++; }

        try
        {
            if (!File.Exists(path)) { Line($"file not found: {path}"); Flush(log); return 2; }

            if (MachOFat.TryList(path, out var slices))
            {
                Line($"fat/universal: {slices.Count} slice(s)");
                foreach (var s in slices) Line($"    {s.ArchName,-8} @ 0x{s.Offset:X}  {s.Size / 1024} KB");
            }

            var img = BinaryLoader.Load(path);
            Line($"\nformat={img.FormatName}  arch={img.ArchName}  bits={img.Bitness}  base=0x{img.ImageBase:X}  entry=0x{img.EntryVa:X}  dll={img.IsDll}");

            Check("format is Mach-O", img.Format == BinaryFormat.MachO);
            Check("has sections", img.Sections.Count > 0);
            Check("has symbols", img.Symbols.Count > 0);

            Line($"\n[sections] ({img.Sections.Count})");
            foreach (var sec in img.Sections)
                Line($"    {sec.Name,-18} va=0x{sec.StartVa:X8}  vsize=0x{sec.VirtualSize:X}  foff=0x{sec.FileOffset:X}  fsize=0x{sec.FileSize:X}  {(sec.IsExecutable ? "X" : "-")}{(sec.IsReadable ? "R" : "-")}{(sec.IsWritable ? "W" : "-")}");

            int funcs = img.Symbols.Count(s => s.Kind == NamedSymbolKind.Function);
            int exports = img.Symbols.Count(s => s.Kind == NamedSymbolKind.Export);
            int datas = img.Symbols.Count(s => s.Kind == NamedSymbolKind.Data);
            int imports = img.Symbols.Count(s => s.Kind == NamedSymbolKind.Import);
            Line($"\n[symbols] total={img.Symbols.Count}  fn={funcs}  export={exports}  data={datas}  import={imports}  funcStarts={img.FunctionStarts.Count}");
            foreach (var s in img.Symbols.Take(8)) Line($"    0x{s.Va:X8}  {s.Kind,-8}  {s.Name}");

            if (img is MachOImage mo)
                Line($"\n[chained-fixups] present={mo.HasChainedFixups}  rebases={mo.RebaseCount}");

            if (img is MachOImage m && m.ObjC is { } objc)
            {
                Line($"\n[objc] classes={objc.Classes.Count}  methodSymbols={objc.MethodSymbols.Count}");
                foreach (var c in objc.Classes.Take(6))
                {
                    Line($"    @0x{c.Va:X8}  {c.Name}{(c.SuperName is { } sn ? " : " + sn : "")}  ({c.InstanceMethods.Count}- {c.ClassMethods.Count}+)");
                    foreach (var mm in c.InstanceMethods.Take(4)) Line($"        -[{c.Name} {mm.Selector}]  @0x{mm.Imp:X8}");
                    foreach (var mm in c.ClassMethods.Take(2)) Line($"        +[{c.Name} {mm.Selector}]  @0x{mm.Imp:X8}");
                }
                Check("objc classes recovered", objc.Classes.Count > 0);

                // Exercise the exact view-models the Obj-C browser tab builds (what ProbeObjC feeds the TreeView).
                var vms = objc.Classes.OrderBy(c => c.Name).Select(c => new ViewModels.ObjCClassVm(c)).ToList();
                Check("class VMs match class count", vms.Count == objc.Classes.Count);
                var cvm = vms.FirstOrDefault(v => v.Children.Count > 0);
                Check("a class VM has method children", cvm is not null);
                if (cvm is not null)
                {
                    var mvm = cvm.Children[0];
                    Check("method VM navigates to its IMP", mvm.Va != 0 && (mvm.Display.StartsWith("-[") || mvm.Display.StartsWith("+[")));
                }
            }
            else Line("\n[objc] none");

            var result = AnalysisEngine.Analyze(img, null, null);
            Line($"\n[analysis] functions={result.Functions.Count}  strings={result.Strings.Count}  warnings={result.Warnings.Count}");
            foreach (var w in result.Warnings.Take(5)) Line($"    ! {w}");
            Check("analysis found functions", result.Functions.Count > 0);
        }
        catch (Exception ex) { Line("EXCEPTION: " + ex); fail++; }

        Line($"\nObjCSmoke: {pass} passed, {fail} failed.");
        Flush(log);
        return fail == 0 ? 0 : 1;
    }

    private static void Flush(StringBuilder log)
    {
        try { File.WriteAllText(Path.Combine(Path.GetTempPath(), "disasmstudio_smoke_objc.txt"), log.ToString()); }
        catch { /* best-effort */ }
    }
}

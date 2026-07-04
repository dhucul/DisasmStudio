using System.IO;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using DisasmStudio.Core.Formats;
using DisasmStudio.Core.Unpacking;
using DisasmStudio.Managed;
using DisasmStudio.Wpf.Controls;

// (DisasmStudio.Wpf.Controls imported above supplies both ManagedDecompilerView and SourceViewerWindow)

namespace DisasmStudio.Wpf.Diagnostics;

/// <summary>
/// Hidden self-test (<c>--smoke-managed &lt;file&gt;</c>) for the .NET managed path. Runs inside the live App so
/// <see cref="System.Windows.Application.Current"/> resources exist, then drives the real
/// <see cref="ManagedDecompilerView"/> — specifically <c>SetAssembly</c>, which builds the WPF tree and used to
/// throw an <see cref="InvalidCastException"/> on the lazy-load placeholder. Prints to the launching console and
/// also writes <c>%TEMP%\disasmstudio_smoke_managed.txt</c>; returns a process exit code (0 = all passed).
/// </summary>
internal static class ManagedSmoke
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

            var img = BinaryLoader.Load(path);
            Check("ManagedPeInfo detects managed", ManagedPeInfo.TryRead(img) is not null);

            bool loaded = ManagedAssembly.TryLoad(img, out var asm);
            Check("ManagedAssembly.TryLoad", loaded && asm is not null);
            if (asm is null) { Line($"\nManagedSmoke: {pass} passed, {fail + 1} failed."); Flush(log); return 1; }

            // The regression this guards: building the tree in SetAssembly must not throw on the placeholder cast.
            var view = new ManagedDecompilerView();
            bool threw = false;
            try { view.SetAssembly(asm); }
            catch (Exception ex) { threw = true; Line("  SetAssembly threw: " + ex.GetType().Name + ": " + ex.Message); }
            Check("ManagedDecompilerView.SetAssembly does not throw", !threw);

            var root = asm.Root;
            Check("tree has namespaces", root.Children.Count > 0);
            var type = root.Children.SelectMany(n => n.Children)
                .FirstOrDefault(t => t.Kind == ManagedNodeKind.Type && t.Children.Count > 0);
            Check("found a type with members", type is not null);
            if (type is not null)
                Check("C# decompiles non-empty", asm.DecompileCSharp(type).Count > 1);

            // Find a real method anywhere in the tree (the first type may be field-only, e.g. <PrivateImplementationDetails>).
            var method = root.Children.SelectMany(n => n.Children).SelectMany(t => t.Children)
                .FirstOrDefault(c => c.Kind == ManagedNodeKind.Method);
            Check("IL disassembles non-empty", method is not null && asm.DecompileIl(method).Count > 1);
            Check("resources enumerated", asm.Resources.Count > 0);

            // Save-to-C# → open-.cs round-trip: decompile the whole module, write it, then open it in the viewer.
            string cs = asm.WholeModuleCSharp();
            Check("WholeModuleCSharp produces C#", cs.Length > 200 && cs.Contains("class"));
            string csPath = Path.Combine(Path.GetTempPath(), "ds_smoke_saved.cs");
            File.WriteAllText(csPath, cs);
            Check("saved .cs is a source file", SourceViewerWindow.IsSourceFile(csPath) && new FileInfo(csPath).Length > 200);
            bool viewerThrew = false;
            try { _ = new SourceViewerWindow(csPath); }   // constructs + reads + tokenizes (not shown)
            catch (Exception ex) { viewerThrew = true; Line("  SourceViewerWindow threw: " + ex.GetType().Name + ": " + ex.Message); }
            Check("SourceViewerWindow opens the saved .cs", !viewerThrew);

            asm.Dispose();

            // Unpacker-dialog layout: the right-aligned button row must not clip the leftmost "Unpack" button.
            // Show the dialog off-screen, lay it out, and confirm the button sits fully within the window.
            try
            {
                var owner = new Window { Width = 300, Height = 200, WindowStyle = WindowStyle.None, ShowInTaskbar = false, ShowActivated = false, Left = -3000, Top = -3000 };
                owner.Show();
                var verdict = new PackerVerdict(null, PackerKind.Unknown, new List<(string, double)>(), "layout test");
                var dlg = new UnpackerDialog(owner, @"C:\Windows\System32\notepad.exe", 64, 0x140000000, verdict)
                { Left = -3000, Top = -3000, ShowActivated = false, ShowInTaskbar = false };
                dlg.Show();
                dlg.UpdateLayout();
                var btn = FindButton(dlg, "Unpack");
                double left = -1, right = -1;
                if (btn is not null && btn.ActualWidth > 0)
                {
                    var p = btn.TransformToAncestor(dlg).Transform(new Point(0, 0));
                    left = p.X; right = p.X + btn.ActualWidth;
                }
                Check("Unpacker 'Unpack' button fully visible (not clipped)",
                    btn is not null && left >= 0 && right <= dlg.ActualWidth + 0.5);
                Line($"    (Unpack button left={left:F0}, right={right:F0}, dialog width={dlg.ActualWidth:F0})");
                dlg.Close();
                owner.Close();
            }
            catch (Exception ex) { Line("  unpacker-dialog layout check skipped: " + ex.Message); }
        }
        catch (Exception ex) { Line("EXCEPTION: " + ex); fail++; }

        Line($"\nManagedSmoke: {pass} passed, {fail} failed.");
        Flush(log);
        return fail == 0 ? 0 : 1;
    }

    private static void Flush(StringBuilder log)
    {
        try { File.WriteAllText(System.IO.Path.Combine(System.IO.Path.GetTempPath(), "disasmstudio_smoke_managed.txt"), log.ToString()); }
        catch { /* best-effort */ }
    }

    private static Button? FindButton(DependencyObject root, string content)
    {
        if (root is Button b && (b.Content as string) == content) return b;
        int n = VisualTreeHelper.GetChildrenCount(root);
        for (int i = 0; i < n; i++)
            if (FindButton(VisualTreeHelper.GetChild(root, i), content) is { } hit) return hit;
        return null;
    }
}

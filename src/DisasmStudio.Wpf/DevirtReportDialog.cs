using System.IO;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using DisasmStudio.Core.Devirt;
using DisasmStudio.Core.Formats;
using DisasmStudio.Core.Unpacking;
using DisasmStudio.Wpf.Services;

namespace DisasmStudio.Wpf;

/// <summary>Small report window for the experimental devirtualizer.</summary>
internal sealed class DevirtReportDialog : Window
{
    private static readonly Brush Bg = Palette.Surface0Brush;   // surface0
    private static readonly Brush Fg = Palette.TextBrush;   // text
    private static readonly Brush Sub = Palette.Subtext1Brush;  // subtext1
    private static readonly FontFamily Mono = new("Cascadia Mono, Consolas");

    private readonly string _report;

    public DevirtReportDialog(Window owner, IBinaryImage image, DevirtResult result)
    {
        Owner = owner;
        Title = "Devirtualizer";
        Width = 860;
        Height = 680;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        Background = Bg;
        Foreground = Fg;

        _report = BuildReport(image, result);

        var root = new Grid { Margin = new Thickness(16) };
        root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        root.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
        root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

        var summary = new TextBlock
        {
            Text = $"{Path.GetFileName(image.FilePath)}  -  {image.FormatName}  -  {image.ArchName}  -  {result.Status}",
            Foreground = Sub,
            TextWrapping = TextWrapping.Wrap,
            Margin = new Thickness(0, 0, 0, 10),
        };
        Grid.SetRow(summary, 0);
        root.Children.Add(summary);

        var box = new TextBox
        {
            Text = _report,
            IsReadOnly = true,
            AcceptsReturn = true,
            FontFamily = Mono,
            FontSize = 12,
            Background = Palette.BaseBrush,
            Foreground = Sub,
            HorizontalScrollBarVisibility = ScrollBarVisibility.Auto,
            VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
            TextWrapping = TextWrapping.NoWrap,
        };
        Grid.SetRow(box, 1);
        root.Children.Add(box);

        var buttons = new StackPanel
        {
            Orientation = Orientation.Horizontal,
            HorizontalAlignment = HorizontalAlignment.Right,
            Margin = new Thickness(0, 12, 0, 0),
        };
        var save = new Button { Content = "Save report...", MinWidth = 96, Margin = new Thickness(0, 0, 8, 0) };
        save.Click += OnSave;
        var close = new Button { Content = "Close", MinWidth = 80, IsCancel = true };
        buttons.Children.Add(save);
        buttons.Children.Add(close);
        Grid.SetRow(buttons, 2);
        root.Children.Add(buttons);

        Content = root;
    }

    private void OnSave(object sender, RoutedEventArgs e)
    {
        var dlg = new Microsoft.Win32.SaveFileDialog
        {
            Title = "Save devirtualizer report",
            Filter = "Text|*.txt|All files|*.*",
            FileName = "devirt_report.txt",
        };
        if (dlg.ShowDialog(this) != true) return;
        try { File.WriteAllText(dlg.FileName, _report); }
        catch (Exception ex) { MessageBox.Show(this, ex.Message, "Save failed", MessageBoxButton.OK, MessageBoxImage.Error); }
    }

    private static string BuildReport(IBinaryImage image, DevirtResult result)
    {
        var sb = new StringBuilder();
        sb.AppendLine("Experimental devirtualizer report");
        sb.AppendLine();
        sb.AppendLine($"Image:       {image.FilePath}");
        sb.AppendLine($"Format:      {image.FormatName}");
        sb.AppendLine($"Arch:        {image.ArchName}");
        sb.AppendLine($"Base:        0x{image.ImageBase:X}");
        sb.AppendLine($"Entry:       0x{image.EntryVa:X}");
        sb.AppendLine($"Status:      {result.Status}");
        sb.AppendLine($"Message:     {result.Message}");
        sb.AppendLine();

        if (result.Triage is { } triage)
        {
            AppendInterpretation(sb, image, result, triage);

            sb.AppendLine("Snapshot triage");
            sb.AppendLine("  " + triage.Summary);
            sb.AppendLine();

            if (triage.Sections.Count > 0)
            {
                sb.AppendLine("Sections");
                foreach (var s in triage.Sections)
                {
                    string perms = $"{(s.Executable ? "X" : "-")}{(s.Writable ? "W" : "-")}";
                    sb.AppendLine($"  {s.Name,-8}  0x{s.StartVa:X}-0x{s.EndVa:X}  {perms}  size=0x{s.FileSize:X}  entropy={s.Entropy:F2}  nonzero={s.NonZeroPercent:F1}%");
                }
                sb.AppendLine();
            }

            if (triage.SelfCrashes.Count > 0)
            {
                sb.AppendLine("Null-write self-crash sites");
                foreach (var c in triage.SelfCrashes.Take(12))
                    sb.AppendLine($"  0x{c.Va:X}  {c.Section,-8}  zero={c.ZeroRegister,-3}  SEH-near={c.NearbySehInstall}  {c.Text}");
                sb.AppendLine();
            }

            if (triage.PointerTables.Count > 0)
            {
                sb.AppendLine("Executable-pointer table candidates");
                foreach (var t in triage.PointerTables.Take(16))
                {
                    string mode = t.IsRva ? "RVA" : "VA";
                    sb.AppendLine($"  0x{t.Va:X}  {t.Section,-8}  {t.Count} x {t.SlotSize}-byte {mode} -> {t.TargetSection}");
                }
                sb.AppendLine();
            }

            if (triage.BranchSamples.Count > 0)
            {
                sb.AppendLine("Indirect branch samples");
                foreach (var b in triage.BranchSamples.Take(16))
                    sb.AppendLine($"  0x{b.Va:X}  {b.Section,-8}  {b.Shape,-15}  {b.Text}  ; {b.Reason}");
                sb.AppendLine();
            }
        }

        if (result.Entry is { } entry)
        {
            sb.AppendLine("VM");
            sb.AppendLine($"  Entry:       0x{entry.EntryVa:X}");
            sb.AppendLine($"  Dispatcher:  0x{entry.DispatcherVa:X}");
            sb.AppendLine($"  First VIP:   0x{entry.FirstVipVa:X}");
            sb.AppendLine($"  VIP reg:     {entry.Arch.VipReg}");
            sb.AppendLine($"  Table:       0x{entry.Arch.HandlerTableVa:X}");
            sb.AppendLine($"  Handlers:    {entry.Arch.HandlerCount} x {entry.Arch.HandlerSlotSize}-byte slots");
            sb.AppendLine();
        }

        if (result.Handlers.Count > 0)
        {
            int unknown = result.Handlers.Count(h => h.Kind == HandlerKind.Unknown);
            sb.AppendLine($"Handlers ({result.Handlers.Count}, unknown {unknown})");
            for (int i = 0; i < result.Handlers.Count; i++)
            {
                var h = result.Handlers[i];
                string op = h.OperandBytes > 0 ? $" opbytes={h.OperandBytes}" : "";
                string reg = h.Kind is HandlerKind.PushReg or HandlerKind.PopReg ? $" vreg={h.RegIndex}" : "";
                string bin = h.BinOp is { } b ? $" {b}" : "";
                string cmp = h.CmpOp is { } c ? $" {c}" : "";
                sb.AppendLine($"  {i:X2}  0x{h.Va:X}  {h.Kind}{bin}{cmp}{reg}{op}  conf={h.Confidence:F2}");
            }
            sb.AppendLine();
        }

        if (result.Program.Count > 0)
        {
            sb.AppendLine("Virtual instructions");
            int limit = Math.Min(result.Program.Count, 2000);
            for (int i = 0; i < limit; i++)
            {
                var vi = result.Program[i];
                string target = vi.BranchTargetIndex is { } t ? $" -> v{t}" : "";
                string operand = vi.Handler.OperandBytes > 0 ? $" operand=0x{vi.Operand:X}" : "";
                sb.AppendLine($"  v{i:D4}  VIP 0x{vi.VipVa:X}  {vi.Handler.Kind}{operand}{target}");
            }
            if (result.Program.Count > limit)
                sb.AppendLine($"  ... {result.Program.Count - limit:N0} more virtual instruction(s) omitted");
            sb.AppendLine();
        }

        if (result.PseudoC.Count > 0)
        {
            sb.AppendLine("Pseudo-C");
            foreach (var line in result.PseudoC.Take(2000))
            {
                sb.Append("  ");
                sb.Append(new string(' ', line.Indent * 4));
                foreach (var tok in line.Tokens) sb.Append(tok.Text);
                sb.AppendLine();
            }
            if (result.PseudoC.Count > 2000)
                sb.AppendLine($"  ... {result.PseudoC.Count - 2000:N0} more line(s) omitted");
        }

        return sb.ToString();
    }

    private static void AppendInterpretation(StringBuilder sb, IBinaryImage image, DevirtResult result, VmTriageResult triage)
    {
        var hot = triage.Sections
            .Where(s => s.Executable)
            .OrderByDescending(s => s.Entropy)
            .FirstOrDefault();
        bool opaqueHotSection = hot is { Entropy: >= 7.0, NonZeroPercent: >= 50.0 };
        bool crashPath = triage.SelfCrashes.Any(c => c.NearbySehInstall);
        bool lowConfidenceBranches = triage.BranchSamples.Count > 0
            && triage.BranchSamples.All(b => b.Reason.Contains("low confidence", StringComparison.OrdinalIgnoreCase));

        sb.AppendLine("Interpretation");
        if (result.Status == DevirtStatus.UnsupportedVm && opaqueHotSection)
        {
            sb.AppendLine($"  The hottest executable section ({hot!.Name}, entropy {hot.Entropy:F2}) still looks packed/encrypted or heavily obfuscated.");
            if (lowConfidenceBranches)
                sb.AppendLine("  The indirect branches shown below are low-confidence because they come from high-entropy bytes and may be decoder noise.");
            if (crashPath)
                sb.AppendLine("  A SEH-near null-write self-crash was found, so this dump likely captured an anti-debug/anti-tamper path.");
            sb.AppendLine("  HARD STOP: do not keep retrying devirtualization on this same snapshot; it does not expose a stable VM dispatcher.");
            sb.AppendLine("  Next action: compare the generated *_runfree_*.bin snapshots.");
            sb.AppendLine("  Retry Devirt on the earliest snapshot where the active executable section's entropy drops noticeably (roughly below 7.0, ideally below 6.5).");
            int probeCount = AppendRunFreeProbeFiles(sb, image.FilePath);
            if (probeCount == 1 && IsRunFreeEntryProbe(image.FilePath))
                sb.AppendLine("  Only the entry probe exists, so the target exited or self-crashed before live/timed probes captured another state.");
        }
        else if (result.Status == DevirtStatus.NoVmFound && triage.InstructionsScanned == 0
            && !triage.Sections.Any(s => s.Executable))
        {
            sb.AppendLine("  This snapshot has no mapped executable section, so it is not a usable devirtualizer input.");
            sb.AppendLine("  For live run-free probes, this usually means the dump raced process teardown or caught a transient unmapped image state.");
            sb.AppendLine("  Ignore this probe and compare the nearest earlier live/entry/fault snapshot instead.");
        }
        else if (result.Status == DevirtStatus.UnsupportedVm)
        {
            sb.AppendLine("  No supported dispatcher shape was found. If the section entropy is low, this may be an obfuscated dispatcher shape that needs trace-based recovery.");
        }
        else if (result.Status == DevirtStatus.ImageEncrypted)
        {
            sb.AppendLine("  The on-disk image still looks encrypted. Capture a memory dump after the protector has unpacked/decrypted more of the target.");
        }
        else if (result.Status == DevirtStatus.PartialRecovery)
        {
            sb.AppendLine("  A VM-like shape was found, but some handlers, branches, or bytecode could not be resolved.");
        }
        sb.AppendLine();
    }

    private static int AppendRunFreeProbeFiles(StringBuilder sb, string imagePath)
    {
        string dir;
        try { dir = Path.GetDirectoryName(Path.GetFullPath(imagePath)) ?? ""; }
        catch { dir = ""; }
        if (dir.Length == 0 || !Directory.Exists(dir))
        {
            sb.AppendLine("  Run-free probe files: could not inspect this dump's directory.");
            return 0;
        }

        var probes = Directory.GetFiles(dir, "*_runfree_*.bin")
            .OrderBy(File.GetLastWriteTimeUtc)
            .Take(16)
            .ToArray();
        if (probes.Length == 0)
        {
            sb.AppendLine($"  Run-free probe files: none found in {dir}.");
            sb.AppendLine("  Generate them by opening the original target and running Unpack with the Run-free strategy.");
            return 0;
        }

        sb.AppendLine("  Run-free probe files found:");
        var scored = probes.Select(ScoreProbe).ToArray();
        foreach (var p in scored)
        {
            string score = p.Valid
                ? $"  hot={p.Section} entropy={p.Entropy:F2} nonzero={p.NonZeroPercent:F1}%"
                : "  unusable";
            sb.AppendLine("    " + p.Path + score);
        }
        var best = scored.Where(p => p.Valid).OrderBy(p => p.Entropy).FirstOrDefault();
        if (best.Valid)
        {
            sb.AppendLine($"  Best probe by executable-section entropy: {Path.GetFileName(best.Path)} ({best.Entropy:F2}).");
            if (best.Entropy >= 7.0)
                sb.AppendLine("  All valid probes are still high-entropy; none exposes a clearly decrypted VM body.");
        }
        return probes.Length;
    }

    private static bool IsRunFreeEntryProbe(string imagePath) =>
        Path.GetFileNameWithoutExtension(imagePath).EndsWith("_runfree_entry", StringComparison.OrdinalIgnoreCase);

    private static ProbeScore ScoreProbe(string path)
    {
        try
        {
            var image = PeMemoryImage.Load(path);
            var hot = image.Sections
                .Where(s => s.IsExecutable && s.FileSize > 0)
                .Select(s =>
                {
                    int len = Math.Min(s.FileSize, 1 << 20);
                    var bytes = image.ReadBytesAtVa(s.StartVa, len);
                    double entropy = bytes.Length > 0 ? Entropy.Shannon(bytes) : 0;
                    double nonZero = bytes.Length > 0 ? 100.0 * bytes.Count(b => b != 0) / bytes.Length : 0;
                    return (s.Name, Entropy: entropy, NonZero: nonZero);
                })
                .OrderByDescending(s => s.Entropy)
                .FirstOrDefault();
            return hot.Name is null
                ? new ProbeScore(path, false, "", 0, 0)
                : new ProbeScore(path, true, hot.Name, hot.Entropy, hot.NonZero);
        }
        catch
        {
            return new ProbeScore(path, false, "", 0, 0);
        }
    }

    private readonly record struct ProbeScore(string Path, bool Valid, string Section, double Entropy,
        double NonZeroPercent);
}

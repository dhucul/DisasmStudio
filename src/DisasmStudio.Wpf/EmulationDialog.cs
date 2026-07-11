using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using DisasmStudio.Core.IL;
using DisasmStudio.Wpf.Services;

namespace DisasmStudio.Wpf;

/// <summary>
/// Shows what an <see cref="IlEmulator"/> run recovered for a function: the concrete values it resolved
/// (obfuscated constants), the branches it folded (constant / opaque predicates), and any bytes it wrote to
/// mapped memory (a decrypted buffer). Double-click a finding to navigate; the buttons apply the results as
/// comments or patch the decrypted bytes back into the image. Modeless, so the main window stays navigable.
/// </summary>
public sealed class EmulationDialog : Window
{
    private sealed record Finding(ulong Va, string Address, string Kind, string Detail);

    public EmulationDialog(Window owner, string funcName, EmulationResult er, Func<ulong, string?> nameFor,
        Action<ulong> onNavigate, Action onApplyComments, Action onApplyPatch)
    {
        Owner = owner;
        Title = $"Emulate — {funcName}";
        Width = 720;
        Height = 560;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        Background = Palette.Surface0Brush;
        Foreground = Palette.TextBrush;
        var mono = new FontFamily("Cascadia Mono, Consolas");

        string statusText = er.Status switch
        {
            EmuStatus.Returned => "ran to a return",
            EmuStatus.UnknownBranch => "stopped at an input-dependent branch (partial)",
            EmuStatus.Budget => "hit the step budget (partial)",
            EmuStatus.HaltedAsm => $"stopped at an unmodelled instruction @ {er.StoppedAt:X} (partial)",
            EmuStatus.NoCode => "no code to emulate",
            _ => er.Status.ToString(),
        };

        var header = new TextBlock
        {
            Margin = new Thickness(16, 14, 16, 6),
            TextWrapping = TextWrapping.Wrap,
            Foreground = Palette.Subtext1Brush,
            Text = $"Emulation {statusText} after {er.Steps:N0} steps.   " +
                   $"{er.Values.Count:N0} resolved value(s), {er.Branches.Count:N0} folded branch(es), " +
                   $"{er.MemoryWrites.Count:N0} decrypted byte(s).",
        };

        // Findings: resolved values + folded branches, address-ordered.
        var findings = new List<Finding>();
        foreach (var v in er.Values.Values.OrderBy(v => v.Va))
            findings.Add(new Finding(v.Va, v.Va.ToString("X"), "value",
                $"{v.Reg} = 0x{(ulong)v.Value:X}  ({v.Value})"));
        foreach (var b in er.Branches.OrderBy(b => b.Va).DistinctBy(b => b.Va))
            findings.Add(new Finding(b.Va, b.Va.ToString("X"), "branch",
                b.Taken ? "condition always TRUE (take the branch)" : "condition always FALSE (fall through)"));

        // A DataGrid (not a ListView) so the results pick up the app's dark theme from Dark.xaml — the
        // implicit TextBlock style pins cell text to the light TextPrimary, which on a ListView's default
        // (unstyled) white background rendered light-on-white and was unreadable.
        var list = new DataGrid
        {
            Margin = new Thickness(16, 0, 16, 8),
            AutoGenerateColumns = false,
            HeadersVisibility = DataGridHeadersVisibility.Column,
            CanUserAddRows = false, CanUserDeleteRows = false, CanUserResizeRows = false, IsReadOnly = true,
            SelectionMode = DataGridSelectionMode.Single,
            GridLinesVisibility = DataGridGridLinesVisibility.None,
        };
        list.Columns.Add(new DataGridTextColumn { Header = "Address", Width = 130, Binding = new System.Windows.Data.Binding(nameof(Finding.Address)) });
        list.Columns.Add(new DataGridTextColumn { Header = "Kind", Width = 70, Binding = new System.Windows.Data.Binding(nameof(Finding.Kind)) });
        list.Columns.Add(new DataGridTextColumn { Header = "Detail", Width = new DataGridLength(1, DataGridLengthUnitType.Star), Binding = new System.Windows.Data.Binding(nameof(Finding.Detail)) });
        list.ItemsSource = findings;
        list.MouseDoubleClick += (_, _) => { if (list.SelectedItem is Finding f) onNavigate(f.Va); };

        // Decrypted-bytes preview (contiguous runs → hex + printable ASCII).
        var decrypted = new TextBox
        {
            FontFamily = mono, FontSize = 12, IsReadOnly = true, Margin = new Thickness(16, 0, 16, 8),
            Height = 130, VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
            Background = Palette.BaseBrush, Foreground = Palette.GreenBrush,
            Text = FormatDecrypted(er, nameFor),
        };

        var commentBtn = new Button { Content = "Apply as comments", MinWidth = 150, Margin = new Thickness(0, 0, 8, 0), IsEnabled = findings.Count > 0 };
        commentBtn.Click += (_, _) => { onApplyComments(); commentBtn.Content = "Comments applied ✓"; commentBtn.IsEnabled = false; };
        var patchBtn = new Button { Content = "Patch decrypted bytes", MinWidth = 170, Margin = new Thickness(0, 0, 8, 0), IsEnabled = er.MemoryWrites.Count > 0 };
        patchBtn.Click += (_, _) => { onApplyPatch(); Close(); };
        var closeBtn = new Button { Content = "Close", MinWidth = 80, IsCancel = true };
        closeBtn.Click += (_, _) => Close();

        var buttons = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right, Margin = new Thickness(16, 4, 16, 14) };
        buttons.Children.Add(commentBtn);
        buttons.Children.Add(patchBtn);
        buttons.Children.Add(closeBtn);

        var root = new DockPanel();
        DockPanel.SetDock(header, Dock.Top);
        DockPanel.SetDock(buttons, Dock.Bottom);
        DockPanel.SetDock(decrypted, Dock.Bottom);
        DockPanel.SetDock(new TextBlock { Text = "Decrypted / written bytes", Margin = new Thickness(16, 2, 16, 2), Foreground = Palette.Subtext1Brush }, Dock.Bottom);
        root.Children.Add(header);
        root.Children.Add(buttons);
        root.Children.Add(decrypted);
        root.Children.Add(list);   // fills the middle
        Content = root;
    }

    private static string FormatDecrypted(EmulationResult er, Func<ulong, string?> nameFor)
    {
        if (er.MemoryWrites.Count == 0) return "(none — this function didn't write to mapped memory under emulation)";
        var sb = new StringBuilder();
        var runs = ContiguousRuns(er.MemoryWrites);
        foreach (var (start, bytes) in runs)
        {
            string? sym = nameFor(start);
            var ascii = new StringBuilder(bytes.Length);
            foreach (var b in bytes) ascii.Append(b is >= 0x20 and < 0x7F ? (char)b : '.');
            string hex = string.Join(' ', bytes.Take(32).Select(b => b.ToString("X2")));
            if (bytes.Length > 32) hex += " …";
            sb.Append(start.ToString("X"));
            if (sym is { Length: > 0 }) sb.Append(" (").Append(sym).Append(')');
            sb.Append("  [").Append(bytes.Length).Append(" B]\n    ").Append(hex).Append("\n    \"").Append(ascii).Append("\"\n\n");
        }
        return sb.ToString();
    }

    /// <summary>Group the (sorted) written bytes into maximal contiguous runs.</summary>
    private static List<(ulong Start, byte[] Bytes)> ContiguousRuns(SortedDictionary<ulong, byte> writes)
    {
        var runs = new List<(ulong, byte[])>();
        List<byte>? cur = null;
        ulong start = 0, prev = 0;
        foreach (var (addr, b) in writes)
        {
            if (cur is null || addr != prev + 1)
            {
                if (cur is not null) runs.Add((start, cur.ToArray()));
                cur = []; start = addr;
            }
            cur.Add(b);
            prev = addr;
        }
        if (cur is not null) runs.Add((start, cur.ToArray()));
        return runs;
    }
}

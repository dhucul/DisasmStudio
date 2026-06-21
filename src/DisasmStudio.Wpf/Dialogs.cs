using System.Globalization;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;

namespace DisasmStudio.Wpf;

/// <summary>Small, code-built modal prompts (raw-load options, go-to-address) styled to the theme.</summary>
internal static class Dialogs
{
    private static readonly Brush Bg = new SolidColorBrush(Color.FromRgb(0x16, 0x1B, 0x22));
    private static readonly Brush Fg = new SolidColorBrush(Color.FromRgb(0xE6, 0xEA, 0xF0));

    /// <summary>How to host a DLL under the debugger: the host EXE that loads it, the full command line
    /// (incl. argv0), the working directory, and the chosen export's static VA to break at (null = "just
    /// load — break at DllMain").</summary>
    public sealed record DebugDllOptions(string HostExe, string CommandLine, string? WorkingDir,
                                         ulong? ChosenExportVa);

    private const string DllJustLoad = "(just load — break at DllMain)";
    // rundll32 won't LoadLibrary without an entry token, so "just load" passes a harmless probe name instead:
    // rundll32 LoadLibrary's the DLL (DllMain runs → the debugger breaks) and never calls a real export.
    private const string DllLoadProbe = "DisasmStudioLoadProbe";

    /// <summary>Ask the base VA and bitness for opening a flat/raw blob.</summary>
    public static (ulong BaseVa, int Bitness)? AskRawOptions(Window owner)
    {
        var bits = new ComboBox { Margin = new Thickness(0, 0, 0, 10) };
        bits.Items.Add("x64 (64-bit)");
        bits.Items.Add("x86 (32-bit)");
        bits.SelectedIndex = 0;
        var baseBox = new TextBox { Text = "140000000" };

        var panel = new StackPanel { Margin = new Thickness(16) };
        panel.Children.Add(Label("Architecture"));
        panel.Children.Add(bits);
        panel.Children.Add(Label("Base address (hex)"));
        panel.Children.Add(baseBox);

        bool ok = ShowModal(owner, "Open as raw", panel, baseBox);
        if (!ok) return null;
        int bitness = bits.SelectedIndex == 0 ? 64 : 32;
        ulong baseVa = ParseHex(baseBox.Text) ?? (bitness == 64 ? 0x140000000UL : 0x400000UL);
        return (baseVa, bitness);
    }

    /// <summary>Ask how to patch the instruction at <paramref name="va"/>. Returns the assembly text
    /// (or hex bytes) to encode, and whether to just NOP it out; null if cancelled.</summary>
    public static (string Asm, bool Nop)? AskPatch(Window owner, ulong va, string currentText, string currentBytes, string prefill = "")
    {
        var mono = new FontFamily("Cascadia Mono, Consolas");
        var info = new TextBlock { Text = $"{va:X}   {currentText}", Foreground = Fg, FontFamily = mono, Margin = new Thickness(0, 0, 0, 2) };
        var bytes = new TextBlock { Text = currentBytes, Foreground = new SolidColorBrush(Color.FromRgb(0x79, 0x82, 0x8F)), FontFamily = mono, Margin = new Thickness(0, 0, 0, 10) };
        var box = new TextBox { Text = prefill, FontFamily = mono, AcceptsReturn = true, MinLines = 2, MaxLines = 8 };
        box.SelectAll();
        var nop = new CheckBox { Content = "Replace with NOPs", Foreground = Fg, Margin = new Thickness(0, 10, 0, 0) };

        var panel = new StackPanel { Margin = new Thickness(16) };
        panel.Children.Add(Label("Instruction"));
        panel.Children.Add(info);
        panel.Children.Add(bytes);
        panel.Children.Add(Label("Assembly (e.g. \"nop\", \"jmp 0x401000\", \"mov eax, 1\") or raw hex bytes; ';' separates"));
        panel.Children.Add(box);
        panel.Children.Add(nop);

        bool ok = ShowModal(owner, "Patch instruction", panel, box, 480);
        return ok ? (box.Text, nop.IsChecked == true) : null;
    }

    /// <summary>Ask how to host a DLL under the debugger: which EXE loads it (rundll32 by default, or a
    /// custom host), an optional export (from the DLL's export table), and command-line arguments. If an
    /// export is chosen the debugger breaks at it (rundll32 calls it; a custom host is presumably its
    /// consumer); otherwise it breaks at DllMain. A typed #ordinal has no resolvable address, so it falls
    /// back to a DllMain break. Returns the host + command line, or null if cancelled.</summary>
    public static DebugDllOptions? AskDebugDll(Window owner, string dllPath, int bitness,
                                               IReadOnlyList<(string Name, ulong Va)> exports)
    {
        var mono = new FontFamily("Cascadia Mono, Consolas");

        var hostBox = new TextBox { Text = Rundll32Path(bitness), FontFamily = mono };
        var browse = new Button { Content = "Browse…", MinWidth = 76, Margin = new Thickness(8, 0, 0, 0) };
        browse.Click += (_, _) =>
        {
            var dlg = new Microsoft.Win32.OpenFileDialog
            {
                Title = "Choose host EXE",
                Filter = "Executable (*.exe)|*.exe|All files (*.*)|*.*",
            };
            if (dlg.ShowDialog(owner) == true) hostBox.Text = dlg.FileName;
        };
        var hostRow = new DockPanel { Margin = new Thickness(0, 0, 0, 10) };
        DockPanel.SetDock(browse, Dock.Right);
        hostRow.Children.Add(browse);
        hostRow.Children.Add(hostBox);

        var exportBox = new ComboBox { IsEditable = true, FontFamily = mono, Margin = new Thickness(0, 0, 0, 10) };
        exportBox.Items.Add(DllJustLoad);
        foreach (var (name, _) in exports) exportBox.Items.Add(name);
        exportBox.SelectedIndex = 0;

        var argsBox = new TextBox { FontFamily = mono };

        var panel = new StackPanel { Margin = new Thickness(16) };
        panel.Children.Add(Label("Host EXE (rundll32 loads the DLL; or browse to a custom host)"));
        panel.Children.Add(hostRow);
        panel.Children.Add(Label("Export to break at (or “just load” to break at DllMain; #N for an ordinal)"));
        panel.Children.Add(exportBox);
        panel.Children.Add(Label("Command-line arguments (optional)"));
        panel.Children.Add(argsBox);

        bool ok = ShowModal(owner, "Debug DLL", panel, hostBox, 460);
        if (!ok) return null;

        string hostExe = hostBox.Text.Trim();
        string exportText = (exportBox.Text ?? "").Trim();
        string args = argsBox.Text.Trim();
        bool justLoad = exportText.Length == 0 || exportText == DllJustLoad;

        // Map a chosen export name back to its static VA (so we can break there if the DLL has no DllMain).
        // An ordinal token (#N) or an unknown name has no VA — leave null and rely on DllMain / the load stop.
        ulong? chosenVa = null;
        if (!justLoad)
            foreach (var (name, va) in exports)
                if (string.Equals(name, exportText, StringComparison.Ordinal)) { chosenVa = va; break; }

        bool isRundll32 = string.Equals(Path.GetFileName(hostExe), "rundll32.exe", StringComparison.OrdinalIgnoreCase);
        string cmd;
        if (isRundll32)
        {
            // rundll32 syntax: rundll32.exe "<dll>",<export>  — quote only the path, no space after the comma.
            // "just load" uses the probe token (see DllLoadProbe) so rundll32 still LoadLibrary's the DLL and
            // DllMain runs; an explicit export (or #ordinal) is forwarded as-is.
            string token = justLoad ? DllLoadProbe : exportText;
            cmd = Quote(hostExe) + " " + $"{Quote(dllPath)},{token}" + (args.Length == 0 ? "" : " " + args);
        }
        else
        {
            // A custom host loads the DLL itself; we only forward the user's args.
            cmd = Quote(hostExe) + (args.Length == 0 ? "" : " " + args);
        }

        string? workDir = null;
        try { workDir = Path.GetDirectoryName(Path.GetFullPath(dllPath)); } catch { /* keep null */ }

        return new DebugDllOptions(hostExe, cmd, workDir, chosenVa);
    }

    /// <summary>The bitness-matched OS rundll32. The app runs 64-bit, so System32 is the real 64-bit dir
    /// (no WOW64 redirection) and SysWOW64 is spelled literally for a 32-bit DLL.</summary>
    private static string Rundll32Path(int bitness)
    {
        string win = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        string dir = bitness == 32 ? "SysWOW64" : "System32";
        string p = Path.Combine(win, dir, "rundll32.exe");
        return File.Exists(p) ? p : Path.Combine(win, "System32", "rundll32.exe");
    }

    private static string Quote(string s) =>
        s.Length > 0 && !s.StartsWith('"') && s.Contains(' ') ? $"\"{s}\"" : s;

    /// <summary>Ask for a process id (decimal) to attach the debugger to.</summary>
    public static uint? AskPid(Window owner)
    {
        var box = new TextBox();
        var panel = new StackPanel { Margin = new Thickness(16) };
        panel.Children.Add(Label("Attach to process id (decimal)"));
        panel.Children.Add(box);
        bool ok = ShowModal(owner, "Attach to process", panel, box);
        return ok && uint.TryParse(box.Text.Trim(), out var pid) ? pid : null;
    }

    /// <summary>Ask for an address (hex) to navigate to.</summary>
    public static ulong? AskAddress(Window owner)
    {
        var box = new TextBox();
        var panel = new StackPanel { Margin = new Thickness(16) };
        panel.Children.Add(Label("Go to address (hex)"));
        panel.Children.Add(box);
        bool ok = ShowModal(owner, "Go to address", panel, box);
        return ok ? ParseHex(box.Text) : null;
    }

    private static TextBlock Label(string text) => new()
    {
        Text = text,
        Foreground = new SolidColorBrush(Color.FromRgb(0xAE, 0xB7, 0xC4)),
        Margin = new Thickness(0, 0, 0, 4),
    };

    private static bool ShowModal(Window owner, string title, Panel content, Control focus, int width = 320)
    {
        var win = new Window
        {
            Title = title,
            Owner = owner,
            Width = width,
            SizeToContent = SizeToContent.Height,
            WindowStartupLocation = WindowStartupLocation.CenterOwner,
            ResizeMode = ResizeMode.NoResize,
            Background = Bg,
            Foreground = Fg,
        };

        bool result = false;
        var ok = new Button { Content = "OK", IsDefault = true, MinWidth = 70, Margin = new Thickness(0, 0, 8, 0) };
        var cancel = new Button { Content = "Cancel", IsCancel = true, MinWidth = 70 };
        ok.Click += (_, _) => { result = true; win.DialogResult = true; };

        var buttons = new StackPanel
        {
            Orientation = Orientation.Horizontal,
            HorizontalAlignment = HorizontalAlignment.Right,
            Margin = new Thickness(16, 0, 16, 16),
        };
        buttons.Children.Add(ok);
        buttons.Children.Add(cancel);

        var root = new DockPanel();
        DockPanel.SetDock(buttons, Dock.Bottom);
        root.Children.Add(buttons);
        root.Children.Add(content);
        win.Content = root;

        focus.Loaded += (_, _) => focus.Focus();
        win.ShowDialog();
        return result;
    }

    private static ulong? ParseHex(string? s)
    {
        if (string.IsNullOrWhiteSpace(s)) return null;
        s = s.Trim();
        if (s.StartsWith("0x", StringComparison.OrdinalIgnoreCase)) s = s[2..];
        return ulong.TryParse(s, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var v) ? v : null;
    }
}

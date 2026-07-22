using System.ComponentModel;
using System.Globalization;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Media;
using DisasmStudio.Core.Analysis;
using DisasmStudio.Core.Formats;
using DisasmStudio.Debug;
using DisasmStudio.Wpf.Services;
using DisasmStudio.Wpf.ViewModels;

namespace DisasmStudio.Wpf;

/// <summary>Small, code-built modal prompts (raw-load options, go-to-address) styled to the theme.</summary>
internal static class Dialogs
{
    private static readonly Brush Bg = Palette.Surface0Brush;   // surface0
    private static readonly Brush Fg = Palette.TextBrush;   // text
    private static readonly Brush Muted = Palette.Overlay1Brush; // overlay1

    /// <summary>How to host a DLL under the debugger: the host EXE that loads it, the full command line
    /// (incl. argv0), the working directory, and the chosen export's static VA to break at (null = "just
    /// load — break at DllMain").</summary>
    public sealed record DebugDllOptions(string HostExe, string CommandLine, string? WorkingDir,
                                         ulong? ChosenExportVa);

    private const string DllJustLoad = "(just load — break at DllMain)";
    // rundll32 won't LoadLibrary without an entry token, so "just load" passes a harmless probe name instead:
    // rundll32 LoadLibrary's the DLL (DllMain runs → the debugger breaks) and never calls a real export.
    private const string DllLoadProbe = "DisasmStudioLoadProbe";

    /// <summary>Ask the base VA, bitness and entry point for opening a flat/raw blob. When
    /// <paramref name="scan"/> detected a firmware layout, the fields are pre-filled with its suggestion and a
    /// summary of what was found is shown; the entry box tracks the base (preserving the detected offset) until
    /// the user edits it. <paramref name="fileLength"/> is the blob size, used to keep the entry pinned relative
    /// to the base. Returns the chosen base, bitness (16/32/64) and entry VA, or null if cancelled.</summary>
    public static (ulong BaseVa, int Bitness, ulong EntryVa, Architecture Arch)? AskRawOptions(
        Window owner, FirmwareScan scan, long fileLength, Architecture? suggestedArch = null)
    {
        var mono = new FontFamily("Cascadia Mono, Consolas");

        var bits = new ComboBox { Margin = new Thickness(0, 0, 0, 10) };
        bits.Items.Add("x64 (64-bit)");                // 0
        bits.Items.Add("x86 (32-bit)");                // 1
        bits.Items.Add("x86-16 (16-bit real mode)");   // 2
        bits.Items.Add("ARM (32-bit)");                // 3
        bits.Items.Add("Thumb (16/32-bit)");           // 4
        bits.Items.Add("ARM64 (AArch64)");             // 5
        bits.Items.Add("8051 / MCS-51 (8-bit)");       // 6
        // An ARM/Thumb guess (from a byte-frequency sniff) wins the default; else the firmware bitness; else x64.
        bits.SelectedIndex = suggestedArch switch
        {
            Architecture.Arm => 3,
            Architecture.Thumb => 4,
            Architecture.Arm64 => 5,
            _ => scan.IsFirmware ? scan.Bitness switch { 16 => 2, 32 => 1, _ => 0 } : 0,
        };

        // ARM firmware is conventionally based at 0; x86 firmware/blobs keep the sniffer's suggestion or the x64 default.
        ulong defaultBase = suggestedArch is not null ? 0UL : scan.IsFirmware ? scan.BaseVa : 0x140000000UL;
        ulong defaultEntry = scan.IsFirmware ? scan.EntryVa : defaultBase;
        var baseBox = new TextBox { Text = defaultBase.ToString("X"), FontFamily = mono };
        var entryBox = new TextBox { Text = defaultEntry.ToString("X"), FontFamily = mono };

        // The entry keeps a fixed offset from the base (for firmware, the reset vector sits 16 bytes below the
        // top of the image) until the user takes over the entry field, so re-basing still lands on the reset vector.
        long entryOffset = (long)defaultEntry - (long)defaultBase;
        bool userTouchedEntry = false, syncing = false;
        baseBox.TextChanged += (_, _) =>
        {
            if (userTouchedEntry || ParseHex(baseBox.Text) is not ulong b) return;
            syncing = true;
            entryBox.Text = ((ulong)((long)b + entryOffset)).ToString("X");
            syncing = false;
        };
        entryBox.TextChanged += (_, _) => { if (!syncing) userTouchedEntry = true; };
        // 8051 lives in a 16-bit code space based at 0 — snap base/entry to 0 when it's chosen so branch
        // targets (absolute + page + relative) resolve instead of landing at a huge x86-style base.
        bits.SelectionChanged += (_, _) =>
        {
            if (bits.SelectedIndex != 6) return;
            userTouchedEntry = false;
            baseBox.Text = "0";
            entryBox.Text = "0";
        };

        var panel = new StackPanel { Margin = new Thickness(16) };
        if (scan.IsFirmware)
        {
            panel.Children.Add(new TextBlock
            {
                Text = scan.Summary,
                Foreground = Palette.GreenBrush,
                TextWrapping = TextWrapping.Wrap,
                Margin = new Thickness(0, 0, 0, 12),
            });
        }
        panel.Children.Add(Label("Architecture"));
        panel.Children.Add(bits);
        panel.Children.Add(Label("Base address (hex)"));
        panel.Children.Add(baseBox);
        panel.Children.Add(Label(scan.IsFirmware ? "Entry point (hex) — where the CPU starts" : "Entry point (hex)"));
        panel.Children.Add(entryBox);

        bool ok = ShowModal(owner, scan.IsFirmware ? "Open firmware" : "Open as raw", panel,
                            scan.IsFirmware ? entryBox : baseBox, scan.IsFirmware ? 460 : 340);
        if (!ok) return null;
        (int bitness, Architecture arch) = bits.SelectedIndex switch
        {
            2 => (16, Architecture.X86),
            1 => (32, Architecture.X86),
            3 => (32, Architecture.Arm),
            4 => (32, Architecture.Thumb),
            5 => (64, Architecture.Arm64),
            6 => (16, Architecture.I8051),
            _ => (64, Architecture.X64),
        };
        ulong baseVa = ParseHex(baseBox.Text) ?? (bitness == 64 ? 0x140000000UL : 0x400000UL);
        ulong entryVa = ParseHex(entryBox.Text) ?? baseVa;
        return (baseVa, bitness, entryVa, arch);
    }

    /// <summary>Ask which architecture slice of a fat/universal Mach-O to open. Defaults to the x86_64 slice
    /// (full decompiler support), else arm64, else the first. Returns the chosen slice, or null if cancelled.</summary>
    public static MachOSlice? AskMachOSlice(Window owner, IReadOnlyList<MachOSlice> slices)
    {
        var combo = new ComboBox { Margin = new Thickness(0, 0, 0, 10), FontFamily = new FontFamily("Cascadia Mono, Consolas") };
        foreach (var s in slices)
            combo.Items.Add($"{s.ArchName,-8}  @ 0x{s.Offset:X}   {s.Size / 1024:N0} KB");

        int Prefer(string name) { for (int i = 0; i < slices.Count; i++) if (slices[i].ArchName == name) return i; return -1; }
        int def = Prefer("x64"); if (def < 0) def = Prefer("arm64"); if (def < 0) def = 0;
        combo.SelectedIndex = def;

        var panel = new StackPanel { Margin = new Thickness(16) };
        panel.Children.Add(Label("This is a fat/universal Mach-O — choose an architecture slice to open:"));
        panel.Children.Add(combo);

        bool ok = ShowModal(owner, "Open Mach-O slice", panel, combo, 400);
        return ok && combo.SelectedIndex >= 0 ? slices[combo.SelectedIndex] : null;
    }

    /// <summary>Show every section in the image and let the user fold optional ones into the listing as data.
    /// Executable sections are listed checked + disabled ("always shown"); non-code sections with file bytes
    /// (and the PE header) are toggleable; a section with no file data is shown disabled. The list scrolls, so
    /// even a binary with many sections fits on screen. Returns the chosen options, an unchanged copy of
    /// <paramref name="current"/> when there's nothing optional to load, or null if cancelled.</summary>
    public static AnalysisOptions? AskLoadSections(Window owner, IBinaryImage image, AnalysisOptions current)
    {
        var outer = new StackPanel { Margin = new Thickness(16) };
        outer.Children.Add(Label("Sections in this image. Code is always shown; tick a data section / the header to fold it into the listing as data:"));

        var rows = new List<(CheckBox Box, string? Section, bool Header)>();   // toggleable rows only
        var selectAll = new CheckBox { Content = "Select all data sections", Foreground = Fg, FontWeight = FontWeights.SemiBold, Margin = new Thickness(0, 8, 0, 4) };
        selectAll.Click += (_, _) => { bool on = selectAll.IsChecked == true; foreach (var (box, _, _) in rows) box.IsChecked = on; };
        outer.Children.Add(selectAll);

        // The section rows scroll so a many-section binary can't push the OK/Cancel buttons off-screen.
        var list = new StackPanel();
        outer.Children.Add(new ScrollViewer { Content = list, MaxHeight = 360, VerticalScrollBarVisibility = ScrollBarVisibility.Auto });

        void AddRow(string text, bool isChecked, bool enabled, string? section, bool header)
        {
            var cb = new CheckBox
            {
                Content = text,
                Foreground = enabled ? Fg : Muted,
                Margin = new Thickness(0, 6, 0, 0),
                IsChecked = isChecked,
                IsEnabled = enabled,
                FontFamily = new FontFamily("Cascadia Mono, Consolas"),
            };
            if (enabled)
            {
                cb.Click += (_, _) => { if (cb.IsChecked != true) selectAll.IsChecked = false; };   // keep "Select all" honest
                rows.Add((cb, section, header));
            }
            list.Children.Add(cb);
        }

        if (image.HeaderRegion is { FileSize: > 0 })
            AddRow("HEADER    (PE header)            [data]", current.IncludeHeader, true, null, true);
        foreach (var s in image.Sections.OrderBy(s => s.StartVa))
        {
            bool exec = s.IsExecutable, hasData = s.FileSize > 0;
            string tag = exec ? "[code · always]" : hasData ? "[data]" : "[no file data]";
            AddRow($"{s.Name,-8} {s.StartVa:X}-{s.EndVa:X}  {tag}",
                isChecked: exec || (hasData && current.IncludedDataSections.Contains(s.Name)),
                enabled: !exec && hasData,
                section: !exec && hasData ? s.Name : null, header: false);
        }

        if (rows.Count == 0) return current;   // nothing optional to choose (e.g. a raw blob: one code section)
        selectAll.IsChecked = rows.All(r => r.Box.IsChecked == true);

        bool ok = ShowModal(owner, "Load sections", outer, selectAll, 460);
        if (!ok) return null;

        var set = new HashSet<string>();
        bool header = false;
        foreach (var (box, section, isHeader) in rows)
        {
            if (box.IsChecked != true) continue;
            if (isHeader) header = true;
            else if (section is not null) set.Add(section);
        }
        return new AnalysisOptions { IncludedDataSections = set, IncludeHeader = header };
    }

    /// <summary>Ask how to patch the instruction at <paramref name="va"/>. Returns the assembly text
    /// (or hex bytes) to encode, and whether to just NOP it out; null if cancelled.</summary>
    public static (string Asm, bool Nop)? AskPatch(Window owner, ulong va, string currentText, string currentBytes, string prefill = "")
    {
        var mono = new FontFamily("Cascadia Mono, Consolas");
        var info = new TextBlock { Text = $"{va:X}   {currentText}", Foreground = Fg, FontFamily = mono, Margin = new Thickness(0, 0, 0, 2) };
        var bytes = new TextBlock { Text = currentBytes, Foreground = Palette.Overlay1Brush, FontFamily = mono, Margin = new Thickness(0, 0, 0, 10) };
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

    /// <summary>Pick a running process to attach to, from a live, filterable list (pid, name, arch, window
    /// title, image path). Double-click a row or press Attach to confirm; the filter box also accepts a bare
    /// decimal pid as a fallback for a process that doesn't enumerate. <paramref name="expectBitness"/> (the
    /// open binary's bitness) is shown as a hint so a mismatched-arch process isn't picked by accident.
    /// Returns the chosen pid, or null if cancelled.</summary>
    public static uint? AskProcess(Window owner, int expectBitness)
    {
        var mono = new FontFamily("Cascadia Mono, Consolas");
        // expectBitness 0 = no file open: the process's own image is analyzed after attach, so any arch is fine.
        string hint = expectBitness switch
        {
            64 => "the open binary is x64, so match the Arch column",
            32 => "the open binary is x86, so match the Arch column",
            _  => "no file is open — DisasmStudio will analyze the process image after you attach",
        };

        var grid = new DataGrid
        {
            AutoGenerateColumns = false,
            IsReadOnly = true,
            SelectionMode = DataGridSelectionMode.Single,
            HeadersVisibility = DataGridHeadersVisibility.Column,
        };
        DataGridTextColumn Col(string header, string prop, double width, bool star = false) => new()
        {
            Header = header,
            Binding = new Binding(prop),
            Width = star ? new DataGridLength(1, DataGridLengthUnitType.Star) : new DataGridLength(width),
        };
        grid.Columns.Add(Col("PID", nameof(ProcessEntry.Pid), 60));
        grid.Columns.Add(Col("Name", nameof(ProcessEntry.Name), 168));
        grid.Columns.Add(Col("Arch", nameof(ProcessEntry.Arch), 54));
        grid.Columns.Add(Col("Title", nameof(ProcessEntry.Title), 0, star: true));
        grid.Columns.Add(Col("Path", nameof(ProcessEntry.Path), 0, star: true));

        var filter = new TextBox { FontFamily = mono };
        string FilterText() => (filter.Text ?? "").Trim();

        ICollectionView? view = null;
        void Load()
        {
            view = CollectionViewSource.GetDefaultView(ProcessList.Enumerate());
            view.Filter = o =>
            {
                if (o is not ProcessEntry en) return false;
                string f = FilterText();
                return f.Length == 0
                    || en.Name.Contains(f, StringComparison.OrdinalIgnoreCase)
                    || en.Title.Contains(f, StringComparison.OrdinalIgnoreCase)
                    || en.Path.Contains(f, StringComparison.OrdinalIgnoreCase)
                    || en.Pid.ToString().Contains(f);
            };
            grid.ItemsSource = view;
        }
        Load();
        filter.TextChanged += (_, _) => view?.Refresh();

        var refresh = new Button { Content = "↻ Refresh", MinWidth = 86, Margin = new Thickness(8, 0, 0, 0) };
        refresh.Click += (_, _) => Load();
        var filterRow = new DockPanel { Margin = new Thickness(0, 0, 0, 8) };
        DockPanel.SetDock(refresh, Dock.Right);
        filterRow.Children.Add(refresh);
        filterRow.Children.Add(filter);

        var header = new StackPanel { Margin = new Thickness(16, 16, 16, 0) };
        header.Children.Add(Label($"Select a process to attach to — {hint}. Filter by name, pid or path:"));
        header.Children.Add(filterRow);

        var win = new Window
        {
            Title = "Attach to process",
            Owner = owner,
            Width = 680,
            Height = 520,
            MinWidth = 460,
            MinHeight = 320,
            WindowStartupLocation = WindowStartupLocation.CenterOwner,
            ResizeMode = ResizeMode.CanResize,
            Background = Bg,
            Foreground = Fg,
        };

        uint? result = null;
        // The selected row, else a bare decimal pid typed into the filter box (manual fallback).
        uint? Selected() => grid.SelectedItem is ProcessEntry en ? en.Pid
            : uint.TryParse(FilterText(), out var pid) ? pid : null;
        void Commit() { if (Selected() is uint pid) { result = pid; win.DialogResult = true; } }

        var ok = new Button { Content = "Attach", IsDefault = true, MinWidth = 80, Margin = new Thickness(0, 0, 8, 0) };
        var cancel = new Button { Content = "Cancel", IsCancel = true, MinWidth = 70 };
        ok.Click += (_, _) => Commit();
        // Commit only when the double-click lands on a row — not a column header (sorting) or empty space,
        // which would otherwise attach to whatever row happened to be selected.
        grid.MouseDoubleClick += (_, e) =>
        {
            for (DependencyObject? d = e.OriginalSource as Visual; d is not null; d = VisualTreeHelper.GetParent(d))
                if (d is DataGridRow) { Commit(); return; }
        };

        var buttons = new StackPanel
        {
            Orientation = Orientation.Horizontal,
            HorizontalAlignment = HorizontalAlignment.Right,
            Margin = new Thickness(16, 8, 16, 16),
        };
        buttons.Children.Add(ok);
        buttons.Children.Add(cancel);

        var root = new DockPanel();
        DockPanel.SetDock(header, Dock.Top);
        DockPanel.SetDock(buttons, Dock.Bottom);
        root.Children.Add(header);
        root.Children.Add(buttons);
        root.Children.Add(new Border { Margin = new Thickness(16, 0, 16, 0), Child = grid });   // fills the middle
        win.Content = root;

        filter.Loaded += (_, _) => filter.Focus();
        win.ShowDialog();
        return result;
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

    /// <summary>A parsed byte-search pattern from <see cref="AskSearchPattern"/>: the bytes to match, an
    /// optional wildcard <see cref="Mask"/> (null = every byte significant), and a short display string for
    /// the status bar.</summary>
    public readonly record struct SearchQuery(byte[] Pattern, bool[]? Mask, string Display);

    /// <summary>Prompt for a byte search: a mode (Hex / ASCII text / UTF-16 text) and the pattern text.
    /// Self-contained so OK can validate inline — a malformed hex pattern keeps the dialog open with a message
    /// instead of silently failing (same idea as <see cref="AskBreakpointEdit"/>). Returns null if cancelled.</summary>
    public static SearchQuery? AskSearchPattern(Window owner)
    {
        var mode = new ComboBox { Margin = new Thickness(0, 0, 0, 10) };
        mode.Items.Add("Hex bytes (?? = wildcard)");
        mode.Items.Add("Text (ASCII)");
        mode.Items.Add("Text (UTF-16)");
        mode.SelectedIndex = 0;

        var box = new TextBox { FontFamily = new FontFamily("Cascadia Mono, Consolas") };
        var error = new TextBlock
        {
            Foreground = Palette.RedBrush, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 6, 0, 0),
        };

        var panel = new StackPanel { Margin = new Thickness(16) };
        panel.Children.Add(Label("Search"));
        panel.Children.Add(mode);
        panel.Children.Add(box);
        panel.Children.Add(error);

        var win = new Window
        {
            Title = "Find bytes",
            Owner = owner,
            Width = 380,
            SizeToContent = SizeToContent.Height,
            WindowStartupLocation = WindowStartupLocation.CenterOwner,
            ResizeMode = ResizeMode.NoResize,
            Background = Bg,
            Foreground = Fg,
        };

        SearchQuery? result = null;
        var ok = new Button { Content = "Find", IsDefault = true, MinWidth = 70, Margin = new Thickness(0, 0, 8, 0) };
        var cancel = new Button { Content = "Cancel", IsCancel = true, MinWidth = 70 };
        ok.Click += (_, _) =>
        {
            string text = box.Text;
            if (mode.SelectedIndex == 0)
            {
                if (!ByteSearch.TryParseHex(text, out var pat, out var mask))
                {
                    error.Text = "Enter whole hex bytes, e.g. 48 8B ?? 05  (?? = any byte).";
                    return;
                }
                result = new SearchQuery(pat, mask, "hex " + text.Trim());
            }
            else
            {
                if (string.IsNullOrEmpty(text)) { error.Text = "Enter some text to search for."; return; }
                bool wide = mode.SelectedIndex == 2;
                result = new SearchQuery(ByteSearch.ParseText(text, wide), null, $"{(wide ? "utf-16 " : "")}\"{text}\"");
            }
            win.DialogResult = true;
        };

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
        root.Children.Add(panel);
        win.Content = root;

        box.Loaded += (_, _) => box.Focus();
        win.ShowDialog();
        return result;
    }

    /// <summary>Edit a scanned string in its existing allocation. The field preserves leading/trailing spaces,
    /// validates continuously against <see cref="StringEditCodec"/>, and returns null when cancelled.</summary>
    public static string? AskStringEdit(Window owner, ulong va, string initial, int capacityChars, bool wide,
        bool allowLineBreaks)
    {
        string encoding = wide ? "UTF-16LE" : allowLineBreaks ? "ASCII (tabs/line breaks allowed)" : "ASCII";
        var box = new TextBox
        {
            Text = initial,
            FontFamily = new FontFamily("Cascadia Mono, Consolas"),
            AcceptsReturn = allowLineBreaks,
            AcceptsTab = true,
            MinWidth = 440,
            MinLines = allowLineBreaks ? 3 : 1,
            MaxLines = allowLineBreaks ? 8 : 1,
            TextWrapping = allowLineBreaks ? TextWrapping.Wrap : TextWrapping.NoWrap,
            VerticalScrollBarVisibility = allowLineBreaks ? ScrollBarVisibility.Auto : ScrollBarVisibility.Hidden,
        };
        var count = new TextBlock
        {
            Foreground = Muted,
            HorizontalAlignment = HorizontalAlignment.Right,
            Margin = new Thickness(0, 5, 0, 0),
        };
        var error = new TextBlock
        {
            Foreground = Palette.RedBrush,
            TextWrapping = TextWrapping.Wrap,
            Margin = new Thickness(0, 5, 0, 0),
        };
        var panel = new StackPanel { Margin = new Thickness(16) };
        panel.Children.Add(Label($"{va:X}  ·  {encoding}  ·  capacity {capacityChars:N0} characters"));
        panel.Children.Add(box);
        panel.Children.Add(count);
        panel.Children.Add(error);

        var win = new Window
        {
            Title = "Edit string",
            Owner = owner,
            Width = 500,
            SizeToContent = SizeToContent.Height,
            WindowStartupLocation = WindowStartupLocation.CenterOwner,
            ResizeMode = ResizeMode.NoResize,
            Background = Bg,
            Foreground = Fg,
        };
        string? result = null;
        var ok = new Button { Content = "Apply", IsDefault = true, MinWidth = 70, Margin = new Thickness(0, 0, 8, 0) };
        var cancel = new Button { Content = "Cancel", IsCancel = true, MinWidth = 70 };
        void Validate()
        {
            bool valid = StringEditCodec.TryEncode(box.Text, capacityChars, wide, allowLineBreaks,
                out _, out string why);
            count.Text = $"{box.Text.Length:N0} / {capacityChars:N0}";
            error.Text = valid ? "" : why;
            ok.IsEnabled = valid;
        }
        box.TextChanged += (_, _) => Validate();
        ok.Click += (_, _) => { result = box.Text; win.DialogResult = true; };

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
        root.Children.Add(panel);
        win.Content = root;

        box.Loaded += (_, _) => { box.SelectAll(); box.Focus(); };
        Validate();
        win.ShowDialog();
        return result;
    }

    /// <summary>Ask for a single line of text, pre-filled with <paramref name="initial"/> (selected, so typing
    /// replaces it). Used for rename / comment prompts. Returns the entered text (which may be empty — the
    /// caller treats empty as "clear"), or null if cancelled. <paramref name="multiline"/> gives a taller box.</summary>
    public static string? AskText(Window owner, string title, string prompt, string initial = "", bool multiline = false)
    {
        var box = new TextBox
        {
            Text = initial,
            FontFamily = new FontFamily("Cascadia Mono, Consolas"),
            AcceptsReturn = multiline,
            MinLines = multiline ? 3 : 1,
            MaxLines = multiline ? 8 : 1,
            TextWrapping = multiline ? TextWrapping.Wrap : TextWrapping.NoWrap,
        };
        box.Loaded += (_, _) => box.SelectAll();
        var panel = new StackPanel { Margin = new Thickness(16) };
        panel.Children.Add(Label(prompt));
        panel.Children.Add(box);
        bool ok = ShowModal(owner, title, panel, box, 420);
        return ok ? box.Text.Trim() : null;
    }

    /// <summary>Ask the kind (Execute / Write / Read-Write) and size (1/2/4/8 bytes) of a hardware breakpoint.
    /// Execute breakpoints are forced to 1 byte. Returns null if cancelled.</summary>
    public static (HwKind Kind, int Size)? AskHardwareBreakpoint(Window owner)
    {
        var kind = new ComboBox { Margin = new Thickness(0, 0, 0, 10) };
        kind.Items.Add("Execute (code)");
        kind.Items.Add("Write (data)");
        kind.Items.Add("Read/Write (data)");
        kind.SelectedIndex = 0;

        var size = new ComboBox();
        foreach (var s in new[] { "1", "2", "4", "8" }) size.Items.Add(s);
        size.SelectedIndex = 0;

        // Execute breakpoints are always 1 byte — disable the size picker when Execute is chosen.
        void Sync() { bool exec = kind.SelectedIndex == 0; size.IsEnabled = !exec; if (exec) size.SelectedIndex = 0; }
        kind.SelectionChanged += (_, _) => Sync();
        Sync();

        var panel = new StackPanel { Margin = new Thickness(16) };
        panel.Children.Add(Label("Kind"));
        panel.Children.Add(kind);
        panel.Children.Add(Label("Size (bytes)"));
        panel.Children.Add(size);

        bool ok = ShowModal(owner, "Hardware breakpoint", panel, kind);
        if (!ok) return null;
        HwKind k = kind.SelectedIndex switch { 1 => HwKind.Write, 2 => HwKind.ReadWrite, _ => HwKind.Execute };
        int sz = int.Parse((string)size.SelectedItem!, CultureInfo.InvariantCulture);
        return (k, k == HwKind.Execute ? 1 : sz);
    }

    /// <summary>Edit a breakpoint's condition / hit-count / enabled state. Self-contained (not via
    /// <see cref="ShowModal"/>) so OK can validate the condition inline and keep the dialog open on error.
    /// Returns an updated <see cref="BpDef"/> (preserving the hardware kind/size of <paramref name="current"/>),
    /// or null if cancelled.</summary>
    public static BpDef? AskBreakpointEdit(Window owner, BpDef current)
    {
        var win = new Window
        {
            Title = "Edit breakpoint",
            Owner = owner,
            Width = 440,
            SizeToContent = SizeToContent.Height,
            WindowStartupLocation = WindowStartupLocation.CenterOwner,
            ResizeMode = ResizeMode.NoResize,
            Background = Bg,
            Foreground = Fg,
        };

        var cond = new TextBox { Text = current.Condition ?? "" };
        var err = new TextBlock
        {
            Foreground = Palette.RedBrush,
            Margin = new Thickness(0, 4, 0, 0),
            TextWrapping = TextWrapping.Wrap,
            Visibility = Visibility.Collapsed,
        };

        var hitMode = new ComboBox { Margin = new Thickness(0, 0, 0, 10) };
        hitMode.Items.Add("Ignore hit count");
        hitMode.Items.Add("Break when hit count = N");
        hitMode.Items.Add("Break when hit count ≥ N");
        hitMode.Items.Add("Break every Nth hit");
        hitMode.SelectedIndex = (int)current.HitMode;

        var hitN = new TextBox { Text = current.HitTarget > 0 ? current.HitTarget.ToString(CultureInfo.InvariantCulture) : "" };
        void SyncN() => hitN.IsEnabled = hitMode.SelectedIndex != 0;
        hitMode.SelectionChanged += (_, _) => SyncN();
        SyncN();

        var enabled = new CheckBox { Content = "Enabled", IsChecked = current.Enabled, Margin = new Thickness(0, 6, 0, 0), Foreground = Fg };

        string kindNote = current.Hardware
            ? $"Hardware {current.Kind}{(current.Kind == HwKind.Execute ? "" : "/" + current.Size + "B")} breakpoint"
            : "Software breakpoint";

        var panel = new StackPanel { Margin = new Thickness(16) };
        panel.Children.Add(Label(kindNote));
        panel.Children.Add(Label("Condition (blank = always).  e.g.  rax == 5   ·   ecx < 0x10 && ZF == 1   ·   [rsp+8] == 0xDEAD"));
        panel.Children.Add(cond);
        panel.Children.Add(err);
        panel.Children.Add(Label("Hit count"));
        panel.Children.Add(hitMode);
        panel.Children.Add(Label("N"));
        panel.Children.Add(hitN);
        panel.Children.Add(enabled);

        BpDef? result = null;
        var ok = new Button { Content = "OK", IsDefault = true, MinWidth = 70, Margin = new Thickness(0, 0, 8, 0) };
        var cancel = new Button { Content = "Cancel", IsCancel = true, MinWidth = 70 };
        ok.Click += (_, _) =>
        {
            if (!ConditionExpr.TryParse(cond.Text, out _, out string? e))
            {
                err.Text = $"Condition error: {e}";
                err.Visibility = Visibility.Visible;
                return;   // keep the dialog open, entries preserved
            }
            var mode = (HitCountMode)hitMode.SelectedIndex;
            int n = 0;
            if (mode != HitCountMode.None && (!int.TryParse(hitN.Text, out n) || n <= 0))
            {
                err.Text = "Enter a positive whole number for N.";
                err.Visibility = Visibility.Visible;
                return;
            }
            result = new BpDef
            {
                Hardware = current.Hardware,
                Kind = current.Kind,
                Size = current.Size,
                Enabled = enabled.IsChecked == true,
                Condition = string.IsNullOrWhiteSpace(cond.Text) ? null : cond.Text.Trim(),
                HitMode = mode,
                HitTarget = n,
            };
            win.DialogResult = true;
        };

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
        root.Children.Add(panel);
        win.Content = root;

        cond.Loaded += (_, _) => cond.Focus();
        win.ShowDialog();
        return result;
    }

    private static TextBlock Label(string text) => new()
    {
        Text = text,
        Foreground = Palette.Subtext1Brush,
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

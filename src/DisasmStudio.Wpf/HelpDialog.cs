using System.Reflection;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using DisasmStudio.Wpf.Services;

namespace DisasmStudio.Wpf;

/// <summary>Read-only Help dialogs (Keyboard Shortcuts, About) — code-built and themed to match the rest of
/// the app, same pattern as <see cref="Dialogs"/> / <see cref="ExceptionDialog"/>.</summary>
internal static class HelpDialog
{
    private static readonly Brush Bg = Palette.Surface0Brush;   // surface0
    private static readonly Brush Fg = Palette.TextBrush;   // text
    private static readonly Brush Sub = Palette.Subtext1Brush;  // subtext1
    private static readonly Brush Accent = Palette.AccentBrush; // lavender
    private static readonly FontFamily Mono = new("Cascadia Mono, Consolas");

    private static readonly (string Title, (string Key, string Desc)[] Items)[] Groups =
    [
        ("Debugger", [
            ("F5", "Run / continue"),
            ("F7", "Step into"),
            ("F8", "Step over"),
            ("Shift+F11", "Step out"),
            ("Ctrl+F9", "Continue until the current function returns (stop on its ret)"),
            ("F2", "Toggle breakpoint on the caret instruction"),
            ("Click the gutter", "Toggle a breakpoint on that instruction (the left margin)"),
            ("Breakpoints panel", "Lists breakpoints; double-click to jump, Delete to remove"),
            ("◴ Trace / Clear trace", "Instruction trace from where you're stopped: single-steps the loaded module on Continue and tints each executed instruction (system DLLs run at full speed); click ◴ Trace again to stop (no pause needed)"),
            ("Ctrl+Z", "Undo the last edit (patch or created function)"),
            ("(toolbar)", "Pause · Stop · Restart · Attach… · Exceptions…"),
        ]),
        ("Navigation", [
            ("Ctrl+G", "Go to address"),
            ("↑ / ↓", "Move the caret one instruction"),
            ("PageUp / PageDown", "Move the caret one screen"),
            ("Home / End", "First / last instruction"),
            ("Enter", "Follow the branch/call under the caret"),
            ("Double-click", "Follow the target"),
            ("◀ Back / Forward ▶", "Navigation history"),
            ("Address box + Go", "Jump to a hex address"),
            ("Double-click a row", "Jump from a side panel (Functions, Strings, Imports, Exports, Sections, Xrefs)"),
        ]),
        ("Find instructions", [
            ("Ctrl+F", "Open the Find tab and focus its search box"),
            ("Type + Enter", "Search the whole disassembly for instruction text (e.g. \"cmp eax, 5\") — case- and spacing-insensitive"),
            ("Click a result", "Jump to that instruction in the linear listing"),
            ("◴ Trace hits", "Instrument every match; on Run, the sites that actually execute are marked ● and tinted — so you can see which of the matches run"),
            ("Hits only", "Filter the results down to just the matches that were hit"),
        ]),
        ("Linear view", [
            ("Ctrl+C", "Copy the selected lines"),
            ("Ctrl+A", "Select all"),
            ("C", "Create a function at the caret, then decompile it"),
            ("Space", "Toggle jump: send the conditional jump under the caret the other way — while stopped on it in the debugger this flips the real CPU flags (ZF/CF/…) so execution actually changes; elsewhere it's a what-if. The branch line turns green (taken) or red (not taken)"),
            ("Jump arrows (left margin)", "Lines link each branch to its target; a toggled jump is bold and glows — green if taken, red if it falls through — and points at the instruction that actually runs next. Arrows keep drawing to off-screen targets (↑/↓ at the edge) so you can follow them by scrolling"),
            ("Shift + move keys", "Extend the selection"),
            ("Right-click", "Xrefs · open in graph · create function · decompile · save ASM · run-to-cursor · capture · toggle jump · patch…"),
            ("Drag the divider", "Resize the bytes / disassembly split"),
        ]),
        ("Hex view", [
            ("← ↑ → ↓", "Move the byte caret"),
            ("Home / End", "Start / end of the row"),
            ("PageUp / PageDown", "Scroll a screen"),
            ("0-9, A-F", "Type to edit the byte at the caret"),
            ("Ctrl+C", "Copy the selection as hex"),
            ("Right-click", "Copy as hex / text · Find… / next / previous · rename / comment / bookmark"),
            ("Click / double-click", "Focus the byte (status + xrefs) / navigate every view to it"),
            ("Ctrl+F", "Find bytes — hex (with ?? wildcards), ASCII, or UTF-16 text"),
            ("F3 / Shift+F3", "Find next / previous match"),
            ("Right-click → Memory breakpoint", "While debugging: software data breakpoint on the selected bytes — break on read / write / read-write (any length; via page protection)"),
        ]),
        ("Graph", [
            ("Ctrl + Wheel", "Zoom in / out"),
            ("Shift + Wheel", "Pan vertically"),
            ("Drag", "Pan"),
            ("Click a block", "Sync the linear view to it"),
            ("Space / right-click", "Toggle jump: flip the conditional jump the other way (flips the real CPU flags while debugging, else a what-if); the block's edges recolour green (taken) / red (not taken)"),
        ]),
        ("Decompiler", [
            ("↑ / ↓, PageUp/Down", "Move the caret"),
            ("Enter / double-click", "Follow a call / branch"),
            ("Low / Medium / High / Pseudo-C", "Switch IL level (buttons)"),
        ]),
    ];

    /// <summary>Scrollable, grouped keyboard-shortcut reference.</summary>
    public static void ShowShortcuts(Window owner)
    {
        var stack = new StackPanel { Margin = new Thickness(18, 14, 18, 14) };
        foreach (var (title, items) in Groups)
        {
            stack.Children.Add(new TextBlock
            {
                Text = title, Foreground = Accent, FontWeight = FontWeights.SemiBold, FontSize = 13,
                Margin = new Thickness(0, stack.Children.Count == 0 ? 0 : 14, 0, 6),
            });
            var grid = new Grid();
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(168) });
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            foreach (var (key, desc) in items)
            {
                grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
                int r = grid.RowDefinitions.Count - 1;
                var k = new TextBlock { Text = key, Foreground = Fg, FontFamily = Mono, Margin = new Thickness(0, 1, 12, 1) };
                var d = new TextBlock { Text = desc, Foreground = Sub, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 1, 0, 1) };
                Grid.SetRow(k, r); Grid.SetColumn(k, 0);
                Grid.SetRow(d, r); Grid.SetColumn(d, 1);
                grid.Children.Add(k);
                grid.Children.Add(d);
            }
            stack.Children.Add(grid);
        }
        stack.Children.Add(new TextBlock
        {
            Text = "Press F1 to reopen this.", Foreground = Palette.Overlay1Brush,
            FontStyle = FontStyles.Italic, Margin = new Thickness(0, 16, 0, 0),
        });

        var scroll = new ScrollViewer { Content = stack, VerticalScrollBarVisibility = ScrollBarVisibility.Auto };
        Show(owner, "Keyboard shortcuts", scroll, width: 560, height: 640, resizable: true);
    }

    /// <summary>Name, version, tagline, and a short feature overview.</summary>
    public static void ShowAbout(Window owner)
    {
        string version = Assembly.GetExecutingAssembly().GetName().Version?.ToString(3) ?? "1.0.0";
        var panel = new StackPanel { Margin = new Thickness(20, 18, 20, 8) };
        panel.Children.Add(new TextBlock { Text = "DisasmStudio", Foreground = Fg, FontSize = 22, FontWeight = FontWeights.SemiBold });
        panel.Children.Add(new TextBlock { Text = $"Version {version}", Foreground = Sub, Margin = new Thickness(0, 2, 0, 12) });
        panel.Children.Add(new TextBlock
        {
            Text = "A Binary Ninja–style disassembler and debugger for Windows.",
            Foreground = Fg, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 0, 0, 10),
        });
        panel.Children.Add(new TextBlock
        {
            Text = "Loads PE / ELF / raw binaries and disassembles x86/x64 (via Iced). A virtualized linear listing, " +
                   "per-function control-flow graph, and an editable hex view; a multi-level IL + Pseudo-C " +
                   "decompiler; and a live user-mode debugger with software/hardware breakpoints, stepping, and " +
                   "FunCap-style function capture.",
            Foreground = Sub, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 0, 0, 12),
        });
        panel.Children.Add(new TextBlock
        {
            Text = $".NET {Environment.Version}  ·  {(Environment.Is64BitProcess ? "x64" : "x86")}",
            Foreground = Palette.Overlay1Brush, FontFamily = Mono, FontSize = 11,
        });
        Show(owner, "About DisasmStudio", panel, width: 440, height: 0, resizable: false);
    }

    // Shared chrome: themed window, content fills, a single Close button docked bottom-right.
    private static void Show(Window owner, string title, UIElement content, int width, int height, bool resizable)
    {
        var win = new Window
        {
            Title = title, Owner = owner, Width = width,
            Background = Bg, Foreground = Fg,
            WindowStartupLocation = WindowStartupLocation.CenterOwner,
            ResizeMode = resizable ? ResizeMode.CanResize : ResizeMode.NoResize,
        };
        if (height > 0) win.Height = height; else win.SizeToContent = SizeToContent.Height;

        var close = new Button { Content = "Close", IsCancel = true, IsDefault = true, MinWidth = 76 };
        close.Click += (_, _) => win.DialogResult = true;
        var bar = new StackPanel
        {
            Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right,
            Margin = new Thickness(16, 8, 16, 16),
        };
        bar.Children.Add(close);

        var root = new DockPanel();
        DockPanel.SetDock(bar, Dock.Bottom);
        root.Children.Add(bar);
        root.Children.Add(content);
        win.Content = root;
        win.ShowDialog();
    }
}

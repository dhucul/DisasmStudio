using System.Globalization;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;

namespace DisasmStudio.Wpf;

/// <summary>Small, code-built modal prompts (raw-load options, go-to-address) styled to the theme.</summary>
internal static class Dialogs
{
    private static readonly Brush Bg = new SolidColorBrush(Color.FromRgb(0x16, 0x1B, 0x22));
    private static readonly Brush Fg = new SolidColorBrush(Color.FromRgb(0xE6, 0xEA, 0xF0));

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

    private static bool ShowModal(Window owner, string title, Panel content, Control focus)
    {
        var win = new Window
        {
            Title = title,
            Owner = owner,
            Width = 320,
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

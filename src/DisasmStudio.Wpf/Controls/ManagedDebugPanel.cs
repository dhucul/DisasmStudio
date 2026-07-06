using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using DisasmStudio.ManagedDebug;

namespace DisasmStudio.Wpf.Controls;

/// <summary>The managed-debug info pane: the current managed call stack (each frame → a C# method) and the
/// locals/arguments of the selected frame. The managed counterpart to the native <see cref="DebugPanel"/>
/// (which shows registers/memory) — managed debugging has neither. Double-click a frame to navigate to it.</summary>
public sealed class ManagedDebugPanel : Grid
{
    private readonly ListBox _frames = new() { BorderThickness = new Thickness(0), FontFamily = new FontFamily("Cascadia Mono, Consolas") };
    private readonly ListBox _locals = new() { BorderThickness = new Thickness(0), FontFamily = new FontFamily("Cascadia Mono, Consolas") };

    /// <summary>Raised when a call-stack frame is activated (double-click) — the frame index.</summary>
    public event Action<int>? FrameActivated;

    public ManagedDebugPanel()
    {
        ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });

        Children.Add(Section("Call stack", _frames, 0));
        var split = new GridSplitter { Width = 4, HorizontalAlignment = HorizontalAlignment.Stretch, Background = (Brush)Application.Current.Resources["Outline"] };
        SetColumn(split, 1);
        Children.Add(split);
        Children.Add(Section("Locals", _locals, 2));

        _frames.MouseDoubleClick += (_, _) => { if (_frames.SelectedIndex >= 0) FrameActivated?.Invoke(_frames.SelectedIndex); };
    }

    private static UIElement Section(string title, ListBox list, int col)
    {
        var dock = new DockPanel();
        var header = new TextBlock
        {
            Text = title,
            Padding = new Thickness(8, 4, 8, 4),
            Foreground = (Brush)Application.Current.Resources["TextSecondary"],
            Background = (Brush)Application.Current.Resources["Surface"],
        };
        DockPanel.SetDock(header, Dock.Top);
        dock.Children.Add(header);
        dock.Children.Add(list);
        SetColumn(dock, col);
        return dock;
    }

    /// <summary>Populate from a stop event. <paramref name="label"/> resolves a frame to a display label (module
    /// aware — a frame outside the opened assembly is labelled by module + token, not a mis-resolved name).</summary>
    public void Show(MdbgEvent stop, Func<MdbgFrame, string> label)
    {
        _frames.Items.Clear();
        if (stop.Frames is not null)
            for (int i = 0; i < stop.Frames.Length; i++)
            {
                var f = stop.Frames[i];
                _frames.Items.Add($"{i,2}  {label(f)}   (IL 0x{f.IlOffset:X})");
            }
        if (_frames.Items.Count > 0) _frames.SelectedIndex = 0;

        _locals.Items.Clear();
        if (stop.Locals is not null)
            foreach (var l in stop.Locals)
            {
                string val = string.IsNullOrEmpty(l.Value) ? "" : " = " + l.Value;
                _locals.Items.Add($"{(l.IsArg ? "(arg) " : "")}{l.Name} : {l.Type}{val}");
            }
    }

    public void Clear()
    {
        _frames.Items.Clear();
        _locals.Items.Clear();
    }
}

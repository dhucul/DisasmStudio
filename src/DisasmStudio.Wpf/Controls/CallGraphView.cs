using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using DisasmStudio.Core.Analysis;

namespace DisasmStudio.Wpf.Controls;

/// <summary>
/// The static call-graph pane: a lazily-expanded tree rooted at a chosen function, showing either what it
/// calls (Callees ↓) or what calls it (Callers ↑), built from the whole-program <see cref="CallGraph"/>.
/// Children are materialised only when a node is expanded — a whole program's transitive call tree is far
/// too large to build eagerly — and a branch stops descending when it revisits an ancestor (recursion ↺).
/// Double-click a node to navigate the disassembly to that function.
/// </summary>
public sealed class CallGraphView : DockPanel
{
    private readonly TreeView _tree;
    private readonly TextBlock _header;
    private readonly ComboBox _mode;

    private AnalysisResult? _result;
    private CallGraph? _graph;
    private ulong _root;

    // Each node's root→node VA path (inclusive), so a branch stops when it revisits an ancestor (recursion).
    // Keyed by the TreeViewItem — avoids a fragile visual/logical-tree walk for lazily-added containers.
    private readonly Dictionary<TreeViewItem, HashSet<ulong>> _paths = [];

    private static readonly object Placeholder = "…";   // marks a not-yet-expanded node (has children)

    public event Action<ulong>? NavigateRequested;

    private bool Callees => _mode.SelectedIndex == 0;

    public CallGraphView()
    {
        var mono = new FontFamily("Cascadia Mono, Consolas");

        _mode = new ComboBox { Width = 96, Margin = new Thickness(6, 0, 0, 0) };
        _mode.Items.Add("Callees ↓");
        _mode.Items.Add("Callers ↑");
        _mode.SelectedIndex = 0;
        _mode.SelectionChanged += (_, _) => Rebuild();

        var refresh = new Button { Content = "⟳", Width = 26, Margin = new Thickness(6, 0, 0, 0), ToolTip = "Rebuild the tree (e.g. after a rename)" };
        refresh.Click += (_, _) => Rebuild();

        _header = new TextBlock
        {
            VerticalAlignment = VerticalAlignment.Center,
            Foreground = (Brush)Application.Current.Resources["TextMuted"],
            FontFamily = mono,
            FontSize = 11,
            TextTrimming = TextTrimming.CharacterEllipsis,
            Text = "Open a binary to see the call graph.",
        };

        var top = new DockPanel { Margin = new Thickness(8, 6, 8, 4) };
        DockPanel.SetDock(_mode, Dock.Right);
        DockPanel.SetDock(refresh, Dock.Right);
        top.Children.Add(_mode);
        top.Children.Add(refresh);
        top.Children.Add(_header);
        SetDock(top, Dock.Top);
        Children.Add(top);

        _tree = new TreeView { FontFamily = mono, FontSize = 12, BorderThickness = new Thickness(0) };
        _tree.AddHandler(TreeViewItem.ExpandedEvent, new RoutedEventHandler(OnItemExpanded));
        _tree.MouseDoubleClick += (_, _) =>
        {
            if (_tree.SelectedItem is TreeViewItem it && it.Tag is ulong va && va != 0) NavigateRequested?.Invoke(va);
        };
        Children.Add(_tree);
    }

    /// <summary>Point the view at a new analysis (and its precomputed graph); resets the root to the entry point.</summary>
    public void SetResult(AnalysisResult? result, CallGraph? graph)
    {
        _result = result;
        _graph = graph;
        _root = 0;
        Rebuild();
    }

    public void Clear()
    {
        _result = null;
        _graph = null;
        _root = 0;
        _tree.Items.Clear();
        _paths.Clear();
        _header.Text = "Open a binary to see the call graph.";
    }

    /// <summary>Re-root the tree at the function that contains <paramref name="va"/> and show it.</summary>
    public void SetRoot(ulong va)
    {
        if (_graph is null) return;
        ulong fn = _graph.ContainingFunction(va);
        _root = fn != 0 ? fn : va;
        Rebuild();
    }

    private void Rebuild()
    {
        _tree.Items.Clear();
        _paths.Clear();
        if (_result is null || _graph is null) { _header.Text = "Open a binary to see the call graph."; return; }

        if (_root == 0 || !_result.Image.IsExecutableVa(_root))
            _root = _result.Image.EntryVa != 0 && _result.Image.IsExecutableVa(_result.Image.EntryVa)
                ? _result.Image.EntryVa
                : _result.Functions.Count > 0 ? _result.Functions[0].Va : 0;
        if (_root == 0) { _header.Text = "No functions."; return; }

        _header.Text = $"{(Callees ? "Callees of" : "Callers of")} {NameOf(_root)}   ·   {_graph.EdgeCount:N0} call edges";
        var rootItem = MakeNode(_root, []);
        _tree.Items.Add(rootItem);
        Populate(rootItem);            // populate the root directly (don't depend on the Expanded event firing)
        rootItem.IsExpanded = true;
    }

    private void OnItemExpanded(object sender, RoutedEventArgs e)
    {
        if (e.OriginalSource is TreeViewItem item) Populate(item);
    }

    /// <summary>Replace a node's lazy placeholder with its real children (once). Children that revisit an
    /// ancestor are marked as recursion and given no further placeholder.</summary>
    private void Populate(TreeViewItem item)
    {
        if (item.Items.Count != 1 || !ReferenceEquals(item.Items[0], Placeholder)) return;   // already populated / a leaf
        item.Items.Clear();
        if (item.Tag is not ulong va || _graph is null) return;
        var path = _paths.TryGetValue(item, out var p) ? p : [va];   // this node's inclusive root→node path
        foreach (var c in EdgesOf(va)) item.Items.Add(MakeNode(c, path));
    }

    /// <summary>Create a node for <paramref name="va"/> whose parent's inclusive path is <paramref name="ancestors"/>.</summary>
    private TreeViewItem MakeNode(ulong va, HashSet<ulong> ancestors)
    {
        bool cycle = ancestors.Contains(va);
        var item = new TreeViewItem { Tag = va, Header = cycle ? $"{NameOf(va)}   ↺" : NameOf(va) };
        _paths[item] = new HashSet<ulong>(ancestors) { va };   // record this node's inclusive path for its children
        if (!cycle && EdgesOf(va).Count > 0) item.Items.Add(Placeholder);   // lazy: real children built on expand
        return item;
    }

    private IReadOnlyCollection<ulong> EdgesOf(ulong va) => Callees ? _graph!.Callees(va) : _graph!.Callers(va);

    private string NameOf(ulong va) => _result?.NameFor(va) is { Length: > 0 } n ? n : $"sub_{va:X}";
}

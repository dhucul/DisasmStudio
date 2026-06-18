namespace DisasmStudio.Wpf.Services;

/// <summary>
/// A simple address-history navigator: every jump (double-click a call, go-to, pick a function)
/// pushes the previous location so Back/Forward walk the trail, like a browser.
/// </summary>
public sealed class NavigationService
{
    private readonly Stack<ulong> _back = new();
    private readonly Stack<ulong> _forward = new();
    private ulong? _current;

    /// <summary>Raised whenever the current address changes (host syncs the views).</summary>
    public event Action<ulong>? Navigated;

    public bool CanGoBack => _back.Count > 0;
    public bool CanGoForward => _forward.Count > 0;
    public ulong? Current => _current;

    public void Navigate(ulong va)
    {
        if (_current == va) { Navigated?.Invoke(va); return; }
        if (_current is ulong c) _back.Push(c);
        _forward.Clear();
        _current = va;
        Navigated?.Invoke(va);
    }

    public void Back()
    {
        if (_back.Count == 0) return;
        if (_current is ulong c) _forward.Push(c);
        _current = _back.Pop();
        Navigated?.Invoke(_current.Value);
    }

    public void Forward()
    {
        if (_forward.Count == 0) return;
        if (_current is ulong c) _back.Push(c);
        _current = _forward.Pop();
        Navigated?.Invoke(_current.Value);
    }

    public void Reset()
    {
        _back.Clear();
        _forward.Clear();
        _current = null;
    }
}

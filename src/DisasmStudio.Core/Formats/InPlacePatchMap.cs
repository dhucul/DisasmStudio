namespace DisasmStudio.Core.Formats;

/// <summary>
/// Tracks byte edits made directly to an in-memory backing array. This gives image formats whose backing store
/// is already mutable the same patch-map and transaction-level undo semantics as <see cref="MappedFile"/>.
/// </summary>
internal sealed class InPlacePatchMap
{
    private readonly byte[] _backing;
    private readonly Dictionary<int, byte> _patches = [];
    private readonly Dictionary<int, byte> _originalBytes = [];
    private readonly List<Dictionary<int, UndoByte>> _undo = [];

    private readonly record struct UndoByte(bool HadPatch, byte Previous);

    public InPlacePatchMap(byte[] backing) => _backing = backing;

    public bool IsDirty => _patches.Count != 0;
    public int PatchCount => _patches.Count;
    public IReadOnlyDictionary<int, byte> Patches => _patches;
    public bool CanUndo => _undo.Count != 0;

    public void Patch(int offset, ReadOnlySpan<byte> bytes)
    {
        if (offset < 0 || offset >= _backing.Length || bytes.Length == 0) return;

        int count = Math.Min(bytes.Length, _backing.Length - offset);
        var transaction = new Dictionary<int, UndoByte>(count);
        for (int i = 0; i < count; i++)
        {
            int currentOffset = offset + i;
            bool hadPatch = _patches.ContainsKey(currentOffset);
            byte previous = _backing[currentOffset];
            transaction[currentOffset] = new UndoByte(hadPatch, previous);
            _originalBytes.TryAdd(currentOffset, previous);
            _backing[currentOffset] = bytes[i];
            _patches[currentOffset] = bytes[i];
        }
        _undo.Add(transaction);
    }

    public void RevertPatch(int offset, int count)
    {
        if (offset < 0 || count <= 0 || offset >= _backing.Length) return;

        int end = offset + Math.Min(count, _backing.Length - offset);
        for (int currentOffset = offset; currentOffset < end; currentOffset++)
        {
            if (!_patches.ContainsKey(currentOffset)) continue;
            if (_originalBytes.TryGetValue(currentOffset, out byte original))
                _backing[currentOffset] = original;
            _patches.Remove(currentOffset);
        }
    }

    public bool IsPatchedAt(int offset) => _patches.ContainsKey(offset);

    public bool Undo()
    {
        if (_undo.Count == 0) return false;

        var transaction = _undo[^1];
        _undo.RemoveAt(_undo.Count - 1);
        foreach (var (offset, undo) in transaction)
        {
            _backing[offset] = undo.Previous;
            if (undo.HadPatch) _patches[offset] = undo.Previous;
            else _patches.Remove(offset);
        }
        return true;
    }
}

using System.Collections.Concurrent;
using System.IO.MemoryMappedFiles;
using System.Text;

namespace DisasmStudio.Core.Formats;

/// <summary>
/// A read-only, memory-mapped view of a file. Only the pages actually touched are
/// faulted into RAM, so a multi-hundred-megabyte target never sits fully on the managed
/// heap — the disassembler reads small slices on demand. All multi-byte reads are
/// little-endian, matching x86/x64 and the Windows/Linux images we load.
///
/// Disposable, and safe-by-default: <see cref="Dispose"/> releases the OS mapping deterministically, after
/// which every read returns 0/empty (Length is zeroed) rather than throwing — so a late read from a
/// background analysis thread that hasn't yet noticed cancellation degrades to garbage instead of crashing.
/// </summary>
public sealed class MappedFile : IDisposable
{
    private readonly MemoryMappedFile _mmf;
    private readonly MemoryMappedViewAccessor _view;
    // Reads happen on background analysis/string-scan threads while the UI can add another patch. A concurrent
    // map keeps those overlay probes/enumerations safe; the undo list itself remains UI-thread-owned.
    private readonly ConcurrentDictionary<int, byte> _patches = [];   // in-memory edits, overlaid on every read
    // ConcurrentDictionary.Count coordinates across every internal partition. File analysis calls the read
    // methods millions of times, so keep a separately-published count for the overwhelmingly common clean-file
    // fast path instead of consulting Count for every byte.
    private int _patchCount;
    private bool HasPatches => Volatile.Read(ref _patchCount) != 0;
    private readonly List<Dictionary<int, (bool Had, byte Val)>> _undo = [];   // per-Patch pre-edit state, for undo
    private int _disposed;

    public int Length { get; private set; }
    public string Path { get; }

    /// <summary>Release the OS mapping. After this every read returns 0/empty (Length is zeroed), so a stray
    /// read from a not-yet-cancelled reader degrades safely rather than throwing ObjectDisposedException.</summary>
    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
        Length = 0;          // bounds-checked reads now short-circuit without touching the view
        _view.Dispose();
        _mmf.Dispose();
    }

    private MappedFile(MemoryMappedFile mmf, MemoryMappedViewAccessor view, int length, string path)
    {
        _mmf = mmf;
        _view = view;
        Length = length;
        Path = path;
    }

    public static MappedFile Open(string path)
    {
        long length = new FileInfo(path).Length;
        if (length <= 0) throw new BinaryFormatException("File is empty.");
        if (length > int.MaxValue) throw new BinaryFormatException("Files larger than 2 GiB are not supported.");

        // Share read/write/delete so we never lock the target while it is open.
        var stream = new FileStream(path, FileMode.Open, FileAccess.Read,
            FileShare.ReadWrite | FileShare.Delete);
        MemoryMappedFile? mmf = null;
        try
        {
            mmf = MemoryMappedFile.CreateFromFile(stream, mapName: null, capacity: 0,
                MemoryMappedFileAccess.Read, HandleInheritability.None, leaveOpen: false);
            var view = mmf.CreateViewAccessor(0, 0, MemoryMappedFileAccess.Read);
            return new MappedFile(mmf, view, checked((int)length), path);
        }
        catch
        {
            if (mmf is not null) mmf.Dispose();
            else stream.Dispose();
            throw;
        }
    }

    public bool InBounds(int offset, int count) =>
        offset >= 0 &&
        count >= 0 &&
        count <= Length &&
        offset <= Length - count;

    public byte ReadByte(int o)
    {
        if (HasPatches && _patches.TryGetValue(o, out var p)) return p;
        if (Volatile.Read(ref _disposed) != 0 || (uint)o >= (uint)Length) return 0;
        try { return _view.ReadByte(o); }
        catch (ObjectDisposedException) { return 0; }
    }
    public ushort ReadU16(int o)
    {
        if (!HasPatches && Volatile.Read(ref _disposed) == 0 && InBounds(o, 2))
        {
            try { return _view.ReadUInt16(o); }
            catch (ObjectDisposedException) { return 0; }
        }
        return (ushort)(ReadByte(o) | ReadByte(o + 1) << 8);
    }
    public uint ReadU32(int o)
    {
        if (!HasPatches && Volatile.Read(ref _disposed) == 0 && InBounds(o, 4))
        {
            try { return _view.ReadUInt32(o); }
            catch (ObjectDisposedException) { return 0; }
        }
        return (uint)(ReadByte(o) | ReadByte(o + 1) << 8 | ReadByte(o + 2) << 16 | ReadByte(o + 3) << 24);
    }
    public int ReadI32(int o) => (int)ReadU32(o);
    public ulong ReadU64(int o)
    {
        if (!HasPatches && Volatile.Read(ref _disposed) == 0 && InBounds(o, 8))
        {
            try { return _view.ReadUInt64(o); }
            catch (ObjectDisposedException) { return 0; }
        }
        return ReadU32(o) | (ulong)ReadU32(o + 4) << 32;
    }

    public byte[] ReadBytes(int offset, int count)
    {
        if (count <= 0 || offset < 0 || offset >= Length) return [];
        count = Math.Min(count, Length - offset);
        var b = new byte[count];
        try { _view.ReadArray(offset, b, 0, count); }
        catch (ObjectDisposedException) { return []; }
        if (HasPatches)
            for (int i = 0; i < count; i++) if (_patches.TryGetValue(offset + i, out var p)) b[i] = p;
        return b;
    }

    /// <summary>Read up to <paramref name="dest"/>.Length bytes at <paramref name="offset"/>; returns the count read.</summary>
    public int ReadInto(int offset, Span<byte> dest)
    {
        if (offset < 0 || offset >= Length) return 0;
        int count = Math.Min(dest.Length, Length - offset);
        for (int i = 0; i < count; i++) dest[i] = ReadByte(offset + i);
        return count;
    }

    // ---- patching ----
    public bool IsDirty => HasPatches;
    public int PatchCount => Volatile.Read(ref _patchCount);
    public bool IsPatched(int offset) => _patches.ContainsKey(offset);

    /// <summary>The live edit map (file offset → new value) — a read-only view, for persisting into a project.</summary>
    public IReadOnlyDictionary<int, byte> Patches => _patches;

    /// <summary>Overlay <paramref name="bytes"/> at <paramref name="offset"/> (in-memory; persisted by <see cref="SaveAs"/>).
    /// Recorded as one undo step.</summary>
    public void Patch(int offset, ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length == 0 || !InBounds(offset, bytes.Length)) return;
        var group = new Dictionary<int, (bool, byte)>(bytes.Length);
        for (int i = 0; i < bytes.Length; i++)
        {
            int o = offset + i;
            bool hadPatch = _patches.TryGetValue(o, out var prev);
            group[o] = hadPatch ? (true, prev) : (false, (byte)0);
            _patches[o] = bytes[i];
            if (!hadPatch) Interlocked.Increment(ref _patchCount);
        }
        if (group.Count > 0) _undo.Add(group);
    }

    public bool CanUndo => _undo.Count > 0;

    /// <summary>Undo the most recent <see cref="Patch"/>, restoring the bytes it changed.</summary>
    public bool Undo()
    {
        if (_undo.Count == 0) return false;
        var group = _undo[^1];
        _undo.RemoveAt(_undo.Count - 1);
        foreach (var kv in group)
            if (kv.Value.Had)
            {
                if (_patches.TryAdd(kv.Key, kv.Value.Val)) Interlocked.Increment(ref _patchCount);
                else _patches[kv.Key] = kv.Value.Val;
            }
            else if (_patches.TryRemove(kv.Key, out _)) Interlocked.Decrement(ref _patchCount);
        return true;
    }

    /// <summary>Drop edits in [offset, offset+count), restoring the original bytes.</summary>
    public void RevertPatch(int offset, int count)
    {
        for (int i = 0; i < count; i++)
            if (_patches.TryRemove(offset + i, out _)) Interlocked.Decrement(ref _patchCount);
    }

    /// <summary>Write the original file plus all edits to <paramref name="dest"/> (must differ from the open file).</summary>
    public void SaveAs(string dest)
    {
        if (string.Equals(System.IO.Path.GetFullPath(dest), System.IO.Path.GetFullPath(Path), StringComparison.OrdinalIgnoreCase))
            throw new IOException("The original file is open and can't be overwritten in place — save the patched copy under a different name.");
        File.Copy(Path, dest, overwrite: true);
        if (!HasPatches) return;
        using var fs = new FileStream(dest, FileMode.Open, FileAccess.Write);
        foreach (var (off, b) in _patches) { fs.Seek(off, SeekOrigin.Begin); fs.WriteByte(b); }
    }

    /// <summary>Read a NUL-terminated ASCII string at a file offset.</summary>
    public string ReadAsciiZ(int offset, int max = 1024)
    {
        if (offset < 0 || offset >= Length) return string.Empty;
        int count = Math.Min(Length, offset + max) - offset;
        var buf = ReadBytes(offset, count);
        int end = Array.IndexOf(buf, (byte)0);
        return Encoding.ASCII.GetString(buf, 0, end < 0 ? count : end);
    }
}

/// <summary>Raised when a file cannot be parsed as the detected (or requested) format.</summary>
public sealed class BinaryFormatException(string message) : Exception(message);

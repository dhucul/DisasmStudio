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
    private readonly Dictionary<int, byte> _patches = [];   // in-memory edits, overlaid on every read
    private readonly List<Dictionary<int, (bool Had, byte Val)>> _undo = [];   // per-Patch pre-edit state, for undo
    private bool _disposed;

    public int Length { get; private set; }
    public string Path { get; }

    /// <summary>Release the OS mapping. After this every read returns 0/empty (Length is zeroed), so a stray
    /// read from a not-yet-cancelled reader degrades safely rather than throwing ObjectDisposedException.</summary>
    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
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

        // Share read/write/delete so we never lock the target while it is open.
        var stream = new FileStream(path, FileMode.Open, FileAccess.Read,
            FileShare.ReadWrite | FileShare.Delete);
        var mmf = MemoryMappedFile.CreateFromFile(stream, mapName: null, capacity: 0,
            MemoryMappedFileAccess.Read, HandleInheritability.None, leaveOpen: false);
        var view = mmf.CreateViewAccessor(0, 0, MemoryMappedFileAccess.Read);
        return new MappedFile(mmf, view, (int)Math.Min(length, int.MaxValue), path);
    }

    public bool InBounds(int offset, int count) => offset >= 0 && count >= 0 && offset + count <= Length;

    public byte ReadByte(int o)
    {
        if (_patches.Count > 0 && _patches.TryGetValue(o, out var p)) return p;
        return (uint)o < (uint)Length ? _view.ReadByte(o) : (byte)0;
    }
    public ushort ReadU16(int o) => _patches.Count == 0 && InBounds(o, 2) ? _view.ReadUInt16(o) : (ushort)(ReadByte(o) | ReadByte(o + 1) << 8);
    public uint ReadU32(int o) => _patches.Count == 0 && InBounds(o, 4) ? _view.ReadUInt32(o)
        : (uint)(ReadByte(o) | ReadByte(o + 1) << 8 | ReadByte(o + 2) << 16 | ReadByte(o + 3) << 24);
    public int ReadI32(int o) => (int)ReadU32(o);
    public ulong ReadU64(int o) => _patches.Count == 0 && InBounds(o, 8) ? _view.ReadUInt64(o) : ReadU32(o) | (ulong)ReadU32(o + 4) << 32;

    public byte[] ReadBytes(int offset, int count)
    {
        if (count <= 0 || offset < 0 || offset >= Length) return [];
        count = Math.Min(count, Length - offset);
        var b = new byte[count];
        _view.ReadArray(offset, b, 0, count);
        if (_patches.Count > 0)
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
    public bool IsDirty => _patches.Count > 0;
    public int PatchCount => _patches.Count;
    public bool IsPatched(int offset) => _patches.ContainsKey(offset);

    /// <summary>The live edit map (file offset → new value) — a read-only view, for persisting into a project.</summary>
    public IReadOnlyDictionary<int, byte> Patches => _patches;

    /// <summary>Overlay <paramref name="bytes"/> at <paramref name="offset"/> (in-memory; persisted by <see cref="SaveAs"/>).
    /// Recorded as one undo step.</summary>
    public void Patch(int offset, ReadOnlySpan<byte> bytes)
    {
        var group = new Dictionary<int, (bool, byte)>(bytes.Length);
        for (int i = 0; i < bytes.Length; i++)
        {
            int o = offset + i;
            if ((uint)o >= (uint)Length) continue;
            group[o] = _patches.TryGetValue(o, out var prev) ? (true, prev) : (false, (byte)0);
            _patches[o] = bytes[i];
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
            if (kv.Value.Had) _patches[kv.Key] = kv.Value.Val; else _patches.Remove(kv.Key);
        return true;
    }

    /// <summary>Drop edits in [offset, offset+count), restoring the original bytes.</summary>
    public void RevertPatch(int offset, int count)
    {
        for (int i = 0; i < count; i++) _patches.Remove(offset + i);
    }

    /// <summary>Write the original file plus all edits to <paramref name="dest"/> (must differ from the open file).</summary>
    public void SaveAs(string dest)
    {
        if (string.Equals(System.IO.Path.GetFullPath(dest), System.IO.Path.GetFullPath(Path), StringComparison.OrdinalIgnoreCase))
            throw new IOException("The original file is open and can't be overwritten in place — save the patched copy under a different name.");
        File.Copy(Path, dest, overwrite: true);
        if (_patches.Count == 0) return;
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

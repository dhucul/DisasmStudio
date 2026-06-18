using System.IO.MemoryMappedFiles;
using System.Text;

namespace DisasmStudio.Core.Formats;

/// <summary>
/// A read-only, memory-mapped view of a file. Only the pages actually touched are
/// faulted into RAM, so a multi-hundred-megabyte target never sits fully on the managed
/// heap — the disassembler reads small slices on demand. All multi-byte reads are
/// little-endian, matching x86/x64 and the Windows/Linux images we load.
///
/// Not <see cref="IDisposable"/> on purpose: background analysis threads keep the image
/// alive while they read it, and the mapping's SafeHandles release the OS handle when the
/// object is finally collected.
/// </summary>
public sealed class MappedFile
{
    private readonly MemoryMappedFile _mmf;
    private readonly MemoryMappedViewAccessor _view;

    public int Length { get; }

    private MappedFile(MemoryMappedFile mmf, MemoryMappedViewAccessor view, int length)
    {
        _mmf = mmf;
        _view = view;
        Length = length;
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
        return new MappedFile(mmf, view, (int)Math.Min(length, int.MaxValue));
    }

    public bool InBounds(int offset, int count) => offset >= 0 && count >= 0 && offset + count <= Length;

    public byte ReadByte(int o) => (uint)o < (uint)Length ? _view.ReadByte(o) : (byte)0;
    public ushort ReadU16(int o) => InBounds(o, 2) ? _view.ReadUInt16(o) : (ushort)0;
    public uint ReadU32(int o) => InBounds(o, 4) ? _view.ReadUInt32(o) : 0u;
    public int ReadI32(int o) => InBounds(o, 4) ? _view.ReadInt32(o) : 0;
    public ulong ReadU64(int o) => InBounds(o, 8) ? _view.ReadUInt64(o) : 0ul;

    public byte[] ReadBytes(int offset, int count)
    {
        if (count <= 0 || offset < 0 || offset >= Length) return [];
        count = Math.Min(count, Length - offset);
        var b = new byte[count];
        _view.ReadArray(offset, b, 0, count);
        return b;
    }

    /// <summary>Read up to <paramref name="dest"/>.Length bytes at <paramref name="offset"/>; returns the count read.</summary>
    public int ReadInto(int offset, Span<byte> dest)
    {
        if (offset < 0 || offset >= Length) return 0;
        int count = Math.Min(dest.Length, Length - offset);
        for (int i = 0; i < count; i++) dest[i] = _view.ReadByte(offset + i);
        return count;
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

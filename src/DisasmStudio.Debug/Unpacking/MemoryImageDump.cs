using System.Runtime.InteropServices;
using DisasmStudio.Core.Unpacking;

namespace DisasmStudio.Debug.Unpacking;

/// <summary>
/// Reconstructs a live process image as a flat, RVA-indexed buffer (buffer offset == RVA) by reading every
/// committed region across <c>SizeOfImage</c>. Shared by the live debugger (<see cref="DebuggerEngine.DumpImage"/>)
/// and the non-invasive <see cref="NonInvasiveDumper"/>: both supply a process handle for the
/// <see cref="Native.VirtualQueryEx"/> region walk and a <see cref="MemReader"/> for the bytes — breakpoint-masked
/// for the debugger, a plain <c>ReadProcessMemory</c> for a read-only dump. Returns [] if the PE headers can't
/// be parsed or <c>SizeOfImage</c> is implausible.
/// </summary>
internal static class MemoryImageDump
{
    public static byte[] Dump(IntPtr proc, ulong imageBase, MemReader read, out uint sizeOfImage)
    {
        sizeOfImage = 0;
        if (proc == IntPtr.Zero) return [];
        var hdr = read(imageBase, 0x1000);
        if (hdr.Length < 0x200 || !PeView.TryParse(hdr, out var view)) return [];
        uint size = view.SizeOfImage;
        if (size < 0x1000 || size > 1024u * 1024 * 1024) return [];
        sizeOfImage = size;
        var buf = new byte[size];
        Array.Copy(hdr, 0, buf, 0, Math.Min(hdr.Length, buf.Length));
        ulong endVa = imageBase + size, addr = imageBase;
        int mbiSize = Marshal.SizeOf<Native.MEMORY_BASIC_INFORMATION>();
        while (addr < endVa)
        {
            if (Native.VirtualQueryEx(proc, addr, out var mbi, (nuint)mbiSize) == 0) break;
            ulong regionBase = mbi.BaseAddress, regionSize = mbi.RegionSize;
            if (regionSize == 0) break;
            ulong next = regionBase + regionSize;
            bool readable = mbi.State == Native.MEM_COMMIT
                && (mbi.Protect & 0xFF) != Native.PAGE_NOACCESS && (mbi.Protect & Native.PAGE_GUARD) == 0;
            if (readable)
            {
                ulong copyStart = Math.Max(regionBase, imageBase);
                ulong copyEnd = Math.Min(next, endVa);
                if (copyEnd > copyStart)
                {
                    var chunk = read(copyStart, (int)(copyEnd - copyStart));
                    if (chunk.Length > 0) Array.Copy(chunk, 0, buf, (int)(copyStart - imageBase), chunk.Length);
                }
            }
            if (next <= addr) break;
            addr = next;
        }
        return buf;
    }
}

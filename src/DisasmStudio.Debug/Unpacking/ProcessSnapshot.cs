using System.Runtime.InteropServices;
using DisasmStudio.Core.Formats;
using DisasmStudio.Core.Unpacking;

namespace DisasmStudio.Debug.Unpacking;

/// <summary>
/// Captures a process's whole relevant address space to a <c>.dssnap</c> snapshot (see
/// <see cref="ProcessSnapshotImage"/>) — the main image plus the <b>private</b> committed regions a
/// virtualizing protector keeps its decrypted bytecode and VM context in (e.g. the table a Themida
/// <c>jmp [0x780000]</c> reads through), which a single-image dump misses. It deliberately <i>skips</i> other
/// loaded modules (<c>MEM_IMAGE</c> — recoverable from disk) and file mappings (<c>MEM_MAPPED</c>), so the
/// snapshot stays small (this is the difference between a few MB of VM data and hundreds of MB of noise).
/// Passive: VirtualQueryEx + ReadProcessMemory over a handle the caller already holds; no debugger.
/// </summary>
public static class ProcessSnapshot
{
    private const uint MEM_PRIVATE = 0x20000;
    private const long DefaultMaxBytes = 256L << 20;   // overall cap on captured bytes
    private const int ExecCap = 0x10000;               // 64 KiB executable window around the entry in the main image

    /// <summary>Capture process <paramref name="h"/> to <paramref name="outPath"/>. Returns the segment count
    /// written, or -1 if nothing could be captured.</summary>
    public static int CaptureToFile(IntPtr h, ulong mainBase, int bitness, string outPath,
        Action<string>? log = null, long maxBytes = DefaultMaxBytes)
    {
        void Log(string m) => log?.Invoke(m);
        MemReader read = MakeReader(h);

        var segments = new List<SnapshotSegment>();
        long total = 0;
        ulong entryVa = mainBase;

        // 1) The main image as one entry-rooted segment (via the shared region-aware image dump).
        var mainImg = MemoryImageDump.Dump(h, mainBase, read, out uint sizeOfImage);
        if (mainImg.Length > 0 && PeView.TryParse(mainImg, out var view))
        {
            bitness = view.Is64 ? 64 : 32;
            if (view.EntryRva != 0) entryVa = mainBase + view.EntryRva;
            uint execChars = PeConstants.SCN_CNT_CODE | PeConstants.SCN_MEM_EXECUTE | PeConstants.SCN_MEM_READ | PeConstants.SCN_MEM_WRITE;
            uint dataChars = PeConstants.SCN_CNT_INITIALIZED_DATA | PeConstants.SCN_MEM_READ | PeConstants.SCN_MEM_WRITE;

            // A virtualizing protector maps its whole image executable, but almost all of it is unreachable VM
            // bytecode/junk — which makes the analyzer's gap scan grind for minutes. Keep an executable code
            // window that contains the entry; re-mark the overflow as DATA (still captured, just not gap-scanned).
            // The runtime VM code regions are captured separately below as their own (small) executable segments,
            // so this doesn't lose them.
            if (mainImg.Length > ExecCap)
            {
                int win = ExecCap;
                if (view.EntryRva >= (uint)win && view.EntryRva < (uint)mainImg.Length)
                    win = (int)Math.Min((uint)mainImg.Length, view.EntryRva + 0x10000);
                segments.Add(new SnapshotSegment(mainBase, mainImg[..win], execChars, ".text"));
                segments.Add(new SnapshotSegment(mainBase + (ulong)win, mainImg[win..], dataChars, ".image"));
                Log($"Snapshot: main image {sizeOfImage:X} bytes @ {mainBase:X} ({bitness}-bit); executable extent bounded to {ExecCap >> 10} KB (rest as data).");
            }
            else
            {
                segments.Add(new SnapshotSegment(mainBase, mainImg, execChars, ".image"));
                Log($"Snapshot: main image {sizeOfImage:X} bytes @ {mainBase:X} ({bitness}-bit).");
            }
            total += mainImg.Length;
        }
        else Log("Snapshot: could not capture the main image; including private regions only.");

        // 2) Private committed regions — heap, decrypted VM code, VM context/pointer tables.
        ulong addr = 0;
        int mbiSize = Marshal.SizeOf<Native.MEMORY_BASIC_INFORMATION>();
        ulong limit = bitness == 64 ? 0x7FFF_FFFF_0000UL : 0xFFFF_0000UL;
        int privCount = 0, privExec = 0, capped = 0;
        long privBytes = 0;
        while (addr < limit)
        {
            if (Native.VirtualQueryEx(h, addr, out var mbi, (nuint)mbiSize) == 0) break;
            ulong regionBase = mbi.BaseAddress, regionSize = mbi.RegionSize;
            if (regionSize == 0) break;
            ulong next = regionBase + regionSize;

            bool keep = mbi.State == Native.MEM_COMMIT && mbi.Type == MEM_PRIVATE
                && (mbi.Protect & 0xFF) != Native.PAGE_NOACCESS && (mbi.Protect & Native.PAGE_GUARD) == 0;
            if (keep)
            {
                if (total + (long)regionSize > maxBytes) capped++;
                else
                {
                    var bytes = read(regionBase, (int)Math.Min(regionSize, int.MaxValue));
                    if (bytes.Length > 0)
                    {
                        bool exec = (mbi.Protect & 0xF0) != 0;
                        bool write = (mbi.Protect & 0xCC) != 0;
                        uint chars = exec
                            ? PeConstants.SCN_CNT_CODE | PeConstants.SCN_MEM_EXECUTE | PeConstants.SCN_MEM_READ | (write ? PeConstants.SCN_MEM_WRITE : 0)
                            : PeConstants.SCN_CNT_INITIALIZED_DATA | PeConstants.SCN_MEM_READ | (write ? PeConstants.SCN_MEM_WRITE : 0);
                        string name = (exec ? "code_" : "data_") + regionBase.ToString("X");
                        if (name.Length > 15) name = name[..15];
                        segments.Add(new SnapshotSegment(regionBase, bytes, chars, name));
                        privCount++; if (exec) privExec++; privBytes += bytes.Length; total += bytes.Length;
                    }
                }
            }
            if (next <= addr) break;
            addr = next;
        }

        if (segments.Count == 0) { Log("Snapshot: nothing to capture."); return -1; }
        Log($"Snapshot: {privCount} private region(s) ({privExec} executable, {privBytes / 1024.0 / 1024.0:F1} MB)" +
            (capped > 0 ? $"; {capped} region(s) skipped by the {maxBytes >> 20} MB cap." : "."));
        try { ProcessSnapshotImage.Write(outPath, bitness, mainBase, entryVa, segments); }
        catch (Exception ex) { Log("Snapshot write failed: " + ex.Message); return -1; }
        Log($"Snapshot: wrote {segments.Count} segment(s), {total / 1024.0 / 1024.0:F1} MB → {outPath}.");
        return segments.Count;
    }

    private static MemReader MakeReader(IntPtr h) => (va, count) =>
    {
        if (count <= 0) return [];
        var buf = new byte[count];
        if (Native.ReadProcessMemory(h, va, buf, (nuint)count, out var got))
        {
            if ((int)got != count) Array.Resize(ref buf, (int)got);
            return buf;
        }
        return ReadPaged(h, va, count);
    };

    private static byte[] ReadPaged(IntPtr h, ulong va, int count)
    {
        var outBuf = new byte[count];
        int done = 0;
        while (done < count)
        {
            ulong cur = va + (ulong)done;
            int chunk = Math.Min(0x1000 - (int)(cur & 0xFFF), count - done);
            var tmp = new byte[chunk];
            if (!Native.ReadProcessMemory(h, cur, tmp, (nuint)chunk, out var got) || got == 0) break;
            Array.Copy(tmp, 0, outBuf, done, (int)got);
            done += (int)got;
            if ((int)got != chunk) break;
        }
        if (done != count) Array.Resize(ref outBuf, done);
        return outBuf;
    }
}

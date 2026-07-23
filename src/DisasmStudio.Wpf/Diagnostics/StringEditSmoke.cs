using System.IO;
using System.Text;
using DisasmStudio.Core.Analysis;
using DisasmStudio.Core.Formats;

namespace DisasmStudio.Wpf.Diagnostics;

/// <summary>
/// Hidden self-test for fixed-allocation string editing: validates ASCII/UTF-16LE encoding, shortening/NUL-fill,
    /// scanner visibility after a patch, live ANSI line breaks, rejection of growth/unsupported characters,
    /// and patch/undo/save behavior for file- and memory-backed images. Usage: DisasmStudio.exe --smoke-string-edit
/// </summary>
internal static class StringEditSmoke
{
    public static int Run()
    {
        var log = new StringBuilder();
        void Log(string text) { log.AppendLine(text); Console.WriteLine(text); }
        void Check(bool condition, string name, ref bool pass)
        {
            Log($"  {(condition ? "ok" : "FAIL")}  {name}");
            pass &= condition;
        }

        Log("=== string edit smoke ===");
        bool pass = true;
        string path = Path.Combine(Path.GetTempPath(), "ds_smoke_string_edit.bin");
        string snapshotPath = Path.Combine(Path.GetTempPath(), "ds_smoke_string_edit.dssnap");
        string savedSnapshotPath = Path.Combine(Path.GetTempPath(), "ds_smoke_string_edit_saved.dssnap");
        string truncatedSnapshotPath = Path.Combine(Path.GetTempPath(), "ds_smoke_snapshot_truncated.dssnap");
        string invalidRangeSnapshotPath = Path.Combine(Path.GetTempPath(), "ds_smoke_snapshot_range.dssnap");
        try
        {
            var data = new byte[128];
            Encoding.ASCII.GetBytes("Original").CopyTo(data, 16);
            Encoding.Unicode.GetBytes("WideText").CopyTo(data, 64);
            File.WriteAllBytes(path, data);

            using var img = RawImage.Load(path, 0x400000, 64);
            var initial = StringScanner.Scan(img, includeExecutable: true);
            var ascii = initial.Single(s => !s.Wide && s.Text == "Original");
            var wide = initial.Single(s => s.Wide && s.Text == "WideText");
            Check(ascii.Length == 8 && wide.Length == 8, "scanner found ASCII and UTF-16LE allocations", ref pass);

            bool asciiOk = StringEditCodec.TryEncode("Short", ascii.Length, wide: false, out var asciiBytes, out _);
            Check(asciiOk && asciiBytes.Length == 8 && asciiBytes.AsSpan(0, 5).SequenceEqual("Short"u8)
                && asciiBytes.AsSpan(5).IndexOfAnyExcept((byte)0) < 0, "short ASCII edit is NUL-padded", ref pass);
            Check(img.PatchVa(ascii.Va, asciiBytes), "ASCII bytes patched", ref pass);
            var afterAscii = StringScanner.Scan(img, includeExecutable: true);
            Check(afterAscii.Any(s => !s.Wide && s.Va == ascii.Va && s.Text == "Short"), "ASCII rescan sees edited value", ref pass);
            Check(img.Undo(), "ASCII patch undo recorded", ref pass);
            var afterUndo = StringScanner.Scan(img, includeExecutable: true);
            Check(afterUndo.Any(s => !s.Wide && s.Va == ascii.Va && s.Text == "Original"), "undo restores scanned value", ref pass);

            bool wideOk = StringEditCodec.TryEncode("Edit", wide.Length, wide: true, out var wideBytes, out _);
            Check(wideOk && wideBytes.Length == 16 && wideBytes.AsSpan(0, 8).SequenceEqual(Encoding.Unicode.GetBytes("Edit"))
                && wideBytes.AsSpan(8).IndexOfAnyExcept((byte)0) < 0, "short UTF-16LE edit is NUL-padded", ref pass);
            Check(img.PatchVa(wide.Va, wideBytes), "UTF-16LE bytes patched", ref pass);
            var afterWide = StringScanner.Scan(img, includeExecutable: true);
            Check(afterWide.Any(s => s.Wide && s.Va == wide.Va && s.Text == "Edit"), "UTF-16LE rescan sees edited value", ref pass);
            Check(img.Undo(), "UTF-16LE patch undo recorded", ref pass);

            Check(!StringEditCodec.TryEncode("Too long!", 4, wide: false, out _, out _), "growth is rejected", ref pass);
            Check(!StringEditCodec.TryEncode("café", 8, wide: true, out _, out _), "unsupported Unicode is rejected", ref pass);
            Check(!StringEditCodec.TryEncode("line\nfeed", 16, wide: false, out _, out _), "control characters are rejected", ref pass);
            Check(StringEditCodec.TryEncode("line\r\nfeed", 12, wide: false, allowLineBreaks: true,
                    out var liveAnsi, out _)
                && liveAnsi.AsSpan(0, 10).SequenceEqual(Encoding.ASCII.GetBytes("line\r\nfeed"))
                && liveAnsi.AsSpan(10).IndexOfAnyExcept((byte)0) < 0,
                "live ANSI CR/LF edit is accepted and NUL-padded", ref pass);
            Check(!StringEditCodec.TryEncode("line\nfeed", 16, wide: true, allowLineBreaks: true,
                out _, out _), "UTF-16LE line breaks remain rejected", ref pass);
            Check(StringEditCodec.TryEncode("", ascii.Length, wide: false, out var empty, out _)
                && empty.Length == ascii.Length && empty.AsSpan().IndexOfAnyExcept((byte)0) < 0,
                "empty replacement clears the allocation", ref pass);

            const ulong snapshotBase = 0x700000;
            var snapshotData = new byte[64];
            Encoding.ASCII.GetBytes("Snapshot").CopyTo(snapshotData, 16);
            ProcessSnapshotImage.Write(snapshotPath, 64, snapshotBase, snapshotBase,
                [new SnapshotSegment(snapshotBase, snapshotData, 0xC0000040, ".data")]);
            var snapshot = ProcessSnapshotImage.Load(snapshotPath);
            ulong snapshotStringVa = snapshotBase + 16;
            byte[] snapshotEdit = "Changed!"u8.ToArray();
            byte[] snapshotOriginal = snapshot.ReadBytesAtVa(snapshotStringVa, snapshotEdit.Length);
            int snapshotOffset = snapshot.VaToOffset(snapshotStringVa);
            Check(snapshot.PatchVa(snapshotStringVa, snapshotEdit)
                && snapshot.CanUndo && snapshot.IsDirty && snapshot.PatchCount == snapshotEdit.Length
                && snapshot.IsPatchedAt(snapshotOffset),
                "memory-backed snapshot records patch state", ref pass);
            Check(snapshot.Patches.Count == snapshotEdit.Length
                && snapshot.ReadBytesAtVa(snapshotStringVa, snapshotEdit.Length).AsSpan().SequenceEqual(snapshotEdit),
                "memory-backed snapshot exposes project patches", ref pass);
            Check(snapshot.Undo() && !snapshot.CanUndo && !snapshot.IsDirty
                && snapshot.ReadBytesAtVa(snapshotStringVa, snapshotOriginal.Length).AsSpan().SequenceEqual(snapshotOriginal),
                "memory-backed snapshot undo restores bytes and clears patches", ref pass);
            snapshot.PatchVa(snapshotStringVa, snapshotEdit);
            snapshot.SavePatchedAs(savedSnapshotPath);
            var savedSnapshot = ProcessSnapshotImage.Load(savedSnapshotPath);
            Check(savedSnapshot.ReadBytesAtVa(snapshotStringVa, snapshotEdit.Length).AsSpan().SequenceEqual(snapshotEdit),
                "memory-backed snapshot saves edited bytes", ref pass);

            var truncatedSnapshot = new byte[40];
            ProcessSnapshotImage.Magic.CopyTo(truncatedSnapshot);
            BitConverter.GetBytes(1u).CopyTo(truncatedSnapshot, 8);
            BitConverter.GetBytes(64u).CopyTo(truncatedSnapshot, 12);
            BitConverter.GetBytes(1u).CopyTo(truncatedSnapshot, 32);   // claims one entry, but has no table
            File.WriteAllBytes(truncatedSnapshotPath, truncatedSnapshot);
            bool rejectedTruncated;
            try { _ = ProcessSnapshotImage.Load(truncatedSnapshotPath); rejectedTruncated = false; }
            catch (BinaryFormatException) { rejectedTruncated = true; }
            Check(rejectedTruncated, "snapshot rejects a truncated segment table", ref pass);

            var invalidRangeSnapshot = new byte[88];
            ProcessSnapshotImage.Magic.CopyTo(invalidRangeSnapshot);
            BitConverter.GetBytes(1u).CopyTo(invalidRangeSnapshot, 8);
            BitConverter.GetBytes(64u).CopyTo(invalidRangeSnapshot, 12);
            BitConverter.GetBytes(1u).CopyTo(invalidRangeSnapshot, 32);
            BitConverter.GetBytes(1UL).CopyTo(invalidRangeSnapshot, 48);            // segment size
            BitConverter.GetBytes(ulong.MaxValue).CopyTo(invalidRangeSnapshot, 56); // overflowing data offset
            File.WriteAllBytes(invalidRangeSnapshotPath, invalidRangeSnapshot);
            bool rejectedRange;
            try { _ = ProcessSnapshotImage.Load(invalidRangeSnapshotPath); rejectedRange = false; }
            catch (BinaryFormatException) { rejectedRange = true; }
            Check(rejectedRange, "snapshot rejects an overflowing segment range", ref pass);

            var peMemory = PeMemoryImage.Load(typeof(StringEditSmoke).Assembly.Location);
            ulong peHeaderVa = peMemory.ImageBase + 8;
            byte[] peOriginal = peMemory.ReadBytesAtVa(peHeaderVa, 2);
            byte[] peEdit = [(byte)(peOriginal[0] ^ 0xFF), (byte)(peOriginal[1] ^ 0xFF)];
            Check(peMemory.PatchVa(peHeaderVa, peEdit) && peMemory.CanUndo && peMemory.Patches.Count == 2
                && peMemory.ReadBytesAtVa(peHeaderVa, 2).AsSpan().SequenceEqual(peEdit),
                "PE memory image records editable patch state", ref pass);
            Check(peMemory.Undo() && !peMemory.IsDirty
                && peMemory.ReadBytesAtVa(peHeaderVa, 2).AsSpan().SequenceEqual(peOriginal),
                "PE memory image undo restores bytes", ref pass);
        }
        catch (Exception ex)
        {
            Log($"  EXCEPTION: {ex}");
            pass = false;
        }
        finally
        {
            try { File.Delete(path); } catch { }
            try { File.Delete(snapshotPath); } catch { }
            try { File.Delete(savedSnapshotPath); } catch { }
            try { File.Delete(truncatedSnapshotPath); } catch { }
            try { File.Delete(invalidRangeSnapshotPath); } catch { }
        }

        Log(pass ? "RESULT: PASS" : "RESULT: FAIL");
        return pass ? 0 : 1;
    }
}

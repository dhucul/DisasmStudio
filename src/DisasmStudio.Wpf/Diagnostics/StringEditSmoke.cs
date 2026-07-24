using System.IO;
using System.Text;
using DisasmStudio.Core.Analysis;
using DisasmStudio.Core.Formats;
using DisasmStudio.Core.Unpacking;

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
        string chunkBoundaryPath = Path.Combine(Path.GetTempPath(), "ds_smoke_string_chunk_boundary.bin");
        string truncatedSnapshotPath = Path.Combine(Path.GetTempPath(), "ds_smoke_snapshot_truncated.dssnap");
        string invalidRangeSnapshotPath = Path.Combine(Path.GetTempPath(), "ds_smoke_snapshot_range.dssnap");
        string samePageSnapshotPath = Path.Combine(Path.GetTempPath(), "ds_smoke_snapshot_same_page.dssnap");
        string invalidPePath = Path.Combine(Path.GetTempPath(), "ds_smoke_invalid_pe.bin");
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
            Check(img.PatchVa(ascii.Va, asciiBytes)
                && img.IsDirty && img.PatchCount == asciiBytes.Length,
                "ASCII bytes patched and unique patch count published", ref pass);
            var afterAscii = StringScanner.Scan(img, includeExecutable: true);
            Check(afterAscii.Any(s => !s.Wide && s.Va == ascii.Va && s.Text == "Short"), "ASCII rescan sees edited value", ref pass);
            Check(img.Undo() && !img.IsDirty && img.PatchCount == 0,
                "ASCII patch undo clears published patch state", ref pass);
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
            Check(StringEditCodec.TryValidate("line\r\nfeed", 12, wide: false, allowLineBreaks: true, out _),
                "per-keystroke validation succeeds without encoding", ref pass);
            Check(!StringEditCodec.TryValidate("\nleading", 12, wide: false, allowLineBreaks: true, out _),
                "live ANSI edit rejects a leading line break", ref pass);
            Check(StringEditCodec.TryValidate("\tleading", 12, wide: false, allowLineBreaks: true, out _),
                "live ANSI edit keeps scanner-supported leading tabs", ref pass);
            Check(!StringEditCodec.TryEncode("line\nfeed", 16, wide: true, allowLineBreaks: true,
                out _, out _), "UTF-16LE line breaks remain rejected", ref pass);
            Check(StringEditCodec.TryEncode("", ascii.Length, wide: false, out var empty, out _)
                && empty.Length == ascii.Length && empty.AsSpan().IndexOfAnyExcept((byte)0) < 0,
                "empty replacement clears the allocation", ref pass);

            const int scanChunk = 1024 * 1024;
            var chunkBoundaryData = new byte[scanChunk + 64];
            Encoding.ASCII.GetBytes("CrossChunkText").CopyTo(chunkBoundaryData, scanChunk - 4);
            File.WriteAllBytes(chunkBoundaryPath, chunkBoundaryData);
            using (var chunkBoundaryImage = RawImage.Load(chunkBoundaryPath, 0x500000, 64))
            {
                var chunkBoundaryStrings = StringScanner.Scan(chunkBoundaryImage, includeExecutable: true);
                Check(chunkBoundaryStrings.Any(s => s.Va == 0x500000UL + scanChunk - 4
                    && s.Text == "CrossChunkText"),
                    "chunked string scan preserves a run crossing a read boundary", ref pass);
            }

            const ulong snapshotBase = 0x700000;
            const ulong secondSnapshotBase = 0x710000;
            var snapshotData = new byte[64];
            byte[] secondSnapshotData = [1, 2, 3, 4];
            Encoding.ASCII.GetBytes("Snapshot").CopyTo(snapshotData, 16);
            ProcessSnapshotImage.Write(snapshotPath, 64, snapshotBase, snapshotBase,
                [
                    new SnapshotSegment(snapshotBase, snapshotData, 0xC0000040, ".data"),
                    new SnapshotSegment(secondSnapshotBase, secondSnapshotData, 0xC0000040, ".next"),
                ]);
            var snapshot = ProcessSnapshotImage.Load(snapshotPath);
            byte firstSegmentTail = snapshot.ReadBytesAtVa(snapshotBase + 63, 1)[0];
            byte secondSegmentHead = snapshot.ReadBytesAtVa(secondSnapshotBase, 1)[0];
            Check(!snapshot.PatchVa(snapshotBase + 63, [0xAA, 0xBB])
                && snapshot.ReadBytesAtVa(snapshotBase + 63, 1)[0] == firstSegmentTail
                && snapshot.ReadBytesAtVa(secondSnapshotBase, 1)[0] == secondSegmentHead
                && !snapshot.IsDirty,
                "snapshot rejects a VA patch that crosses into the next disjoint segment", ref pass);
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
            Check(savedSnapshot.ReadBytesAtVa(secondSnapshotBase, secondSnapshotData.Length).AsSpan()
                    .SequenceEqual(secondSnapshotData),
                "saving a patched snapshot preserves the adjacent segment", ref pass);

            using var stringScanCts = new CancellationTokenSource();
            var stringProbe = new ScanProbeImage(stringScanCts);
            _ = StringScanner.Scan(stringProbe, token: stringScanCts.Token);
            Check(stringProbe.ReadCalls == 1 && stringProbe.MaxReadRequest < stringProbe.BackingLength,
                "string scan observes cancellation between bounded section reads", ref pass);

            using var pointerScanCts = new CancellationTokenSource();
            var pointerProbe = new ScanProbeImage(pointerScanCts);
            _ = PointerScanner.BuildStringPointerMap(
                pointerProbe, new HashSet<ulong> { pointerProbe.ImageBase }, token: pointerScanCts.Token);
            Check(pointerProbe.ReadCalls == 1 && pointerProbe.MaxReadRequest < pointerProbe.BackingLength,
                "pointer scan observes cancellation between bounded section reads", ref pass);

            var pointerResultProbe = new ScanProbeImage(cancel: null, seedPointer: true);
            var pointerMap = PointerScanner.BuildStringPointerMap(
                pointerResultProbe, new HashSet<ulong> { pointerResultProbe.PointerValue });
            Check(pointerMap.GetValueOrDefault(pointerResultProbe.PointerValue) == pointerResultProbe.PointerSlotVa
                && pointerResultProbe.MaxReadRequest < pointerResultProbe.BackingLength,
                "chunked pointer scan finds an aligned pointer in a later chunk", ref pass);

            var codePointerProbe = new ScanProbeImage(cancel: null, seedPointer: true);
            var codePointers = PointerScanner.CollectCodePointers(codePointerProbe);
            Check(codePointers.Contains(codePointerProbe.PointerValue)
                && codePointerProbe.MaxReadRequest < codePointerProbe.BackingLength,
                "chunked code-pointer scan finds an aligned pointer in a later chunk", ref pass);

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

            const ulong samePageBase = 0x720000;
            byte[] samePageNeedle = [0xDE, 0xAD, 0xBE, 0xEF];
            ProcessSnapshotImage.Write(samePageSnapshotPath, 64, samePageBase, samePageBase,
                [
                    new SnapshotSegment(samePageBase, new byte[0x50], 0x40000040, ".first"),
                    new SnapshotSegment(samePageBase + 0x80, samePageNeedle, 0x40000040, ".second"),
                ]);
            var samePageSnapshot = ProcessSnapshotImage.Load(samePageSnapshotPath);
            Check(ByteSearch.Find(samePageSnapshot, samePageBase, samePageNeedle, null, forward: true)
                    == samePageBase + 0x80,
                "byte search finds a later same-page mapping after an unmapped gap", ref pass);

            byte[] invalidPe = new byte[0x40];
            invalidPe[0] = (byte)'M';
            invalidPe[1] = (byte)'Z';
            BitConverter.GetBytes(int.MaxValue).CopyTo(invalidPe, PeConstants.DosLfanewOffset);
            Check(!PeView.TryParse(invalidPe, out _),
                "PE view rejects an overflowing header offset without throwing", ref pass);
            File.WriteAllBytes(invalidPePath, invalidPe);
            bool rejectedInvalidPe;
            try { _ = PeImage.Load(invalidPePath); rejectedInvalidPe = false; }
            catch (BinaryFormatException) { rejectedInvalidPe = true; }
            Check(rejectedInvalidPe, "file PE loader rejects an overflowing header offset", ref pass);

            Check(!Patcher.Assemble(64, 0x1000, "add rax, 0x100000000").Ok
                    && !Patcher.Assemble(32, 0x1000, "mov eax, 0x100000000").Ok
                    && Patcher.Assemble(32, 0x1000, "mov eax, 0xFFFFFFFF").Ok,
                "assembler rejects truncated immediates and accepts a 32-bit bit pattern", ref pass);

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
            try { File.Delete(chunkBoundaryPath); } catch { }
            try { File.Delete(truncatedSnapshotPath); } catch { }
            try { File.Delete(invalidRangeSnapshotPath); } catch { }
            try { File.Delete(samePageSnapshotPath); } catch { }
            try { File.Delete(invalidPePath); } catch { }
        }

        Log(pass ? "RESULT: PASS" : "RESULT: FAIL");
        return pass ? 0 : 1;
    }

    /// <summary>A deterministic large-section probe that cancels after its first read. It verifies scanners
    /// issue bounded reads and observe cancellation before requesting the rest of the section.</summary>
    private sealed class ScanProbeImage : IBinaryImage
    {
        private const int Size = 3 * 1024 * 1024;
        private static readonly IReadOnlyDictionary<ulong, ImportEntry> NoImports =
            new Dictionary<ulong, ImportEntry>();
        private static readonly IReadOnlyDictionary<int, byte> NoPatches =
            new Dictionary<int, byte>();
        private readonly CancellationTokenSource? _cancel;
        private readonly bool _seedPointer;
        private readonly Section _section;

        public ScanProbeImage(CancellationTokenSource? cancel, bool seedPointer = false)
        {
            _cancel = cancel;
            _seedPointer = seedPointer;
            _section = new Section
            {
                Name = ".probe",
                StartVa = ImageBase,
                VirtualSize = Size,
                FileOffset = 0,
                FileSize = Size,
                IsReadable = true,
            };
            Sections = [_section];
        }

        public int ReadCalls { get; private set; }
        public int MaxReadRequest { get; private set; }
        public ulong PointerValue => ImageBase + 0x20;
        public ulong PointerSlotVa => ImageBase + 1024 * 1024 + 8;
        public string FilePath => "";
        public BinaryFormat Format => BinaryFormat.Raw;
        public string FormatName => "probe";
        public int Bitness => 64;
        public string ArchName => "x64";
        public ulong ImageBase => 0x1000;
        public ulong EntryVa => ImageBase;
        public bool IsDll => false;
        public IReadOnlyList<Section> Sections { get; }
        public IReadOnlyList<NamedSymbol> Symbols => [];
        public IReadOnlyList<ImportEntry> Imports => [];
        public Section? HeaderRegion => null;
        public ResourceTree? Resources => null;
        public IReadOnlyList<ulong> FunctionStarts => [];
        public IReadOnlyDictionary<ulong, ImportEntry> ImportsByIatVa => NoImports;
        public ulong MinVa => ImageBase;
        public ulong MaxVa => ImageBase + Size;
        public int BackingLength => Size;

        public int VaToOffset(ulong va) =>
            va >= ImageBase && va - ImageBase < Size ? (int)(va - ImageBase) : -1;
        public bool IsMappedVa(ulong va) => VaToOffset(va) >= 0;
        public bool IsExecutableVa(ulong va) => _seedPointer && va == PointerValue;
        public Section? SectionAt(ulong va) => _section.ContainsVa(va) ? _section : null;
        public byte ReadByteAtOffset(int offset) => (uint)offset < (uint)Size ? (byte)'A' : (byte)0;

        public byte[] ReadBytesAtVa(ulong va, int count)
        {
            int offset = VaToOffset(va);
            if (offset < 0 || count <= 0) return [];
            count = Math.Min(count, Size - offset);
            ReadCalls++;
            MaxReadRequest = Math.Max(MaxReadRequest, count);
            var bytes = new byte[count];
            bytes.AsSpan().Fill((byte)'A');
            if (_seedPointer)
            {
                int pointerOffset = (int)(PointerSlotVa - ImageBase);
                if (pointerOffset >= offset && pointerOffset + sizeof(ulong) <= offset + count)
                    BitConverter.GetBytes(PointerValue).CopyTo(bytes, pointerOffset - offset);
            }
            if (ReadCalls == 1) _cancel?.Cancel();
            return bytes;
        }

        public int ReadVa(ulong va, Span<byte> dest)
        {
            int offset = VaToOffset(va);
            if (offset < 0 || dest.Length == 0) return 0;
            int count = Math.Min(dest.Length, Size - offset);
            dest[..count].Fill((byte)'A');
            return count;
        }

        public void Patch(int offset, ReadOnlySpan<byte> bytes) { }
        public bool PatchVa(ulong va, ReadOnlySpan<byte> bytes) => false;
        public void RevertPatch(int offset, int count) { }
        public bool IsPatchedAt(int offset) => false;
        public bool IsDirty => false;
        public int PatchCount => 0;
        public IReadOnlyDictionary<int, byte> Patches => NoPatches;
        public bool Undo() => false;
        public bool CanUndo => false;
        public void SavePatchedAs(string path) { }
    }
}

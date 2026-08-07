using DisasmStudio.Core.Analysis;
using DisasmStudio.Core.Disasm;
using DisasmStudio.Core.Export;
using DisasmStudio.Core.Formats;
using DisasmStudio.Core.IL;
using DisasmStudio.Core.Unpacking;
using DisasmStudio.Core.Unpacking.Lzma;
using Iced.Intel;
using System.Reflection;
using Xunit;

namespace DisasmStudio.Core.Tests;

public sealed class RegressionTests : IDisposable
{
    private readonly string _directory = Path.Combine(Path.GetTempPath(), "DisasmStudio.Tests", Guid.NewGuid().ToString("N"));

    public RegressionTests() => Directory.CreateDirectory(_directory);

    public void Dispose()
    {
        try { Directory.Delete(_directory, recursive: true); }
        catch { /* the OS may still be releasing a mapped test file */ }
    }

    [Fact]
    public void LzmaRejectsTruncatedRangeStream()
    {
        byte[] properties = [0x5D, 0x00, 0x10, 0x00, 0x00];
        Assert.Throws<EndOfStreamException>(() => LzmaCodec.Decode(properties, [], -1));
    }

    [Fact]
    public void LzmaRejectsOversizedDictionary()
    {
        byte[] properties = [0x5D, 0x00, 0x00, 0x00, 0x20]; // 512 MiB, over the 256 MiB limit
        Assert.Throws<InvalidDataException>(() => LzmaCodec.Decode(properties, [0, 0, 0, 0, 0], -1));
    }

    [Fact]
    public void LzmaRejectsOversizedDeclaredOutputBeforeAllocation()
    {
        byte[] properties = [0x5D, 0x00, 0x10, 0x00, 0x00];
        Assert.Throws<InvalidDataException>(() =>
            LzmaCodec.Decode(properties, [0, 0, 0, 0, 0], 512L * 1024 * 1024 + 1));
    }

    [Fact]
    public void DemanglerBoundsRecursiveTypePrefixes()
    {
        string hostile = "_Z1f" + new string('P', 100_000) + "i";
        Assert.Equal(hostile, Demangler.Demangle(hostile));
    }

    [Fact]
    public void UpxLzmaDecodesCompactTwoByteProperties()
    {
        // Official UPX method-14 decoder test vector: compact properties 1A 03 followed by a raw range stream.
        byte[] packed = [0x1A, 0x03, 0x00, 0x7F, 0xED, 0x3C, 0x00, 0x00, 0x00];
        byte[] plain = InvokeUpxLzma(packed, 16)!;

        Assert.Equal(Enumerable.Repeat((byte)0xFF, 16), plain);
    }

    [Fact]
    public void UpxLzmaRejectsInvalidCompactProperties()
    {
        Assert.Null(InvokeUpxLzma([0x1F, 0x03, 0x00], 16)); // pb=7 is outside LZMA's 0..4 range
    }

    [Fact]
    public void UpxLzmaRejectsTruncatedOrTrailingInput()
    {
        byte[] packed = [0x1A, 0x03, 0x00, 0x7F, 0xED, 0x3C, 0x00, 0x00, 0x00];
        var truncated = Assert.Throws<TargetInvocationException>(
            () => InvokeUpxLzma(packed[..^1], 16));
        Assert.IsType<EndOfStreamException>(truncated.InnerException);

        var trailing = Assert.Throws<TargetInvocationException>(
            () => InvokeUpxLzma([.. packed, 0x00], 16));
        Assert.IsType<InvalidDataException>(trailing.InnerException);
    }

    [Fact]
    public void UpxStaticUnpackVerifiesAndReconstructsAnalysisImage()
    {
        byte[] packed = MinimalStaticallyUnpackableUpxPe();

        StaticUnpackResult result = new UpxStaticUnpacker().Unpack(packed);

        Assert.True(result.Applicable);
        Assert.True(result.Ok, result.Error);
        Assert.False(result.CanExecute);
        byte[] output = Assert.IsType<byte[]>(result.Image);
        Assert.Equal(0x400, output.Length);
        Assert.True(PeView.TryParse(output, out var rebuilt));
        Assert.Equal(0x1000u, rebuilt.EntryRva);
        Assert.Single(rebuilt.Sections);
    }

    [Fact]
    public void UpxStaticUnpackRebuildsExecutionReadyImageEndToEnd()
    {
        byte[] packed = MinimalRunnableUpxPe();

        StaticUnpackResult result = new UpxStaticUnpacker().Unpack(packed);

        Assert.True(result.Applicable);
        Assert.True(result.Ok, result.Error);
        Assert.True(result.CanExecute, result.Log);
        byte[] output = Assert.IsType<byte[]>(result.Image);
        Assert.Equal(0xE00, output.Length);
        Assert.True(PeView.TryParse(output, out PeView rebuilt));
        Assert.Equal((0x2200u, 40u), rebuilt.DataDir(PeConstants.DirImport));
        Assert.Equal((0x3000u, 0x104u), rebuilt.DataDir(PeConstants.DirResource));
        Assert.Equal((0x4000u, 8u), rebuilt.DataDir(PeConstants.DirBaseReloc));
        Assert.Equal("KERNEL32.DLL\0",
            System.Text.Encoding.ASCII.GetString(output, 0x780, 13));
        Assert.Equal("ExitProcess\0",
            System.Text.Encoding.ASCII.GetString(output, 0x762, 12));
        Assert.Equal(new byte[] { 1, 2, 3, 4 }, output[0xB00..0xB04]);
        Assert.Equal(new byte[] { 0, 0, 0, 0, 8, 0, 0, 0 }, output[0xC00..0xC08]);
    }

    [Fact]
    public void UpxStaticUnpackRejectsNrvReadPastCompressedBlock()
    {
        byte[] packed = MinimalStaticallyUnpackableUpxPe();
        const int header = 0x1E0;
        uint shortened = BitConverter.ToUInt32(packed, header + 20) - 1;
        Put32(packed, header + 20, shortened);
        Put32(packed, header + 12,
            Adler32ForTest(packed.AsSpan(0x200, (int)shortened)));

        StaticUnpackResult result = new UpxStaticUnpacker().Unpack(packed);

        Assert.False(result.Ok);
        Assert.Null(result.Image);
    }

    [Fact]
    public void UpxStaticUnpackRejectsSectionOverlappingHeaders()
    {
        byte[] packed = MinimalStaticallyUnpackableUpxPe(originalRawOffset: 0x100);

        StaticUnpackResult result = new UpxStaticUnpacker().Unpack(packed);

        Assert.False(result.Ok);
        Assert.Contains("raw-data range", result.Log);
    }

    [Fact]
    public void UpxStaticUnpackHonorsPreCancelledToken()
    {
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        byte[] packed = MinimalStaticallyUnpackableUpxPe();

        Assert.Throws<OperationCanceledException>(
            () => StaticUnpackerRegistry.FindApplicable(packed, cancellation.Token));
        Assert.Throws<OperationCanceledException>(
            () => new UpxStaticUnpacker().Unpack(packed, cancellation.Token));
    }

    [Fact]
    public void UpxRuntimeRebuildRestoresOrdinaryImports()
    {
        byte[] packed = MinimalMappedPe();
        const int packedRaw = 0x200;
        "KERNEL32.DLL\0"u8.CopyTo(packed.AsSpan(packedRaw + 0x20));
        Assert.True(PeView.TryParse(packed, out PeView packedPe));

        byte[] recovered = new byte[0x500];
        const int extra = 0x20;
        Put32(recovered, extra, 0x300);
        Put32(recovered, extra + 4, 0);
        Put32(recovered, 0x300, 0x20);
        Put32(recovered, 0x304, 0x100);
        recovered[0x308] = 1;
        "ExitProcess\0"u8.CopyTo(recovered.AsSpan(0x309));
        Put32(recovered, 0x200 + 12, 0x1180);
        BitConverter.GetBytes(0x1160UL).CopyTo(recovered, 0x100);

        object?[] arguments =
        [
            packed, packedPe, recovered, extra, 0x1000u, 0x1200u, 40u, true,
            new System.Text.StringBuilder(), CancellationToken.None,
        ];
        Assert.True(InvokeUpxPrivate("TryRebuildImports", arguments));

        Assert.Equal(0x28, Assert.IsType<int>(arguments[3]));
        Assert.Equal(0x1100u, BitConverter.ToUInt32(recovered, 0x200 + 16));
        Assert.Equal("KERNEL32.DLL\0",
            System.Text.Encoding.ASCII.GetString(recovered, 0x180, 13));
        Assert.Equal("ExitProcess\0",
            System.Text.Encoding.ASCII.GetString(recovered, 0x162, 12));
        Assert.Equal(0x1160UL, BitConverter.ToUInt64(recovered, 0x100));
        Assert.Equal(0UL, BitConverter.ToUInt64(recovered, 0x108));
    }

    [Fact]
    public void UpxRuntimeRebuildReservesNullImportDescriptor()
    {
        byte[] packed = MinimalMappedPe();
        const int packedRaw = 0x200;
        "FIRST.DLL\0"u8.CopyTo(packed.AsSpan(packedRaw + 0x20));
        "SECOND.DLL\0"u8.CopyTo(packed.AsSpan(packedRaw + 0x30));
        Assert.True(PeView.TryParse(packed, out PeView packedPe));

        byte[] recovered = new byte[0x500];
        const int extra = 0x20;
        Put32(recovered, extra, 0x300);
        Put32(recovered, 0x300, 0x20);
        Put32(recovered, 0x304, 0x100);
        Put32(recovered, 0x309, 0x30);
        Put32(recovered, 0x30D, 0x120);

        object?[] arguments =
        [
            packed, packedPe, recovered, extra, 0x1000u, 0x1200u, 40u, true,
            new System.Text.StringBuilder(), CancellationToken.None,
        ];
        Assert.False(InvokeUpxPrivate("TryRebuildImports", arguments));
    }

    [Fact]
    public void UpxRuntimeRebuildRejectsPackedStringCrossingSectionEnd()
    {
        byte[] packed = [.. MinimalMappedPe(), .. new byte[0x100]];
        "NO-NULL!"u8.CopyTo(packed.AsSpan(0x3F8));
        Assert.True(PeView.TryParse(packed, out PeView packedPe));

        byte[] recovered = new byte[0x500];
        const int extra = 0x20;
        Put32(recovered, extra, 0x300);
        Put32(recovered, 0x300, 0x1F8);
        Put32(recovered, 0x304, 0x100);

        object?[] arguments =
        [
            packed, packedPe, recovered, extra, 0x1000u, 0x1200u, 40u, true,
            new System.Text.StringBuilder(), CancellationToken.None,
        ];
        Assert.False(InvokeUpxPrivate("TryRebuildImports", arguments));
    }

    [Fact]
    public void UpxExecutionReadyValidationRejectsDirectoryInVirtualOnlyTail()
    {
        byte[] output = MinimalMappedPe();
        int opt = 0x80 + PeConstants.OptHeaderFromSig;
        int section = opt + 0xF0;
        Put32(output, section + PeConstants.Sec_VirtualSize, 0x400);
        Put32(output, opt + PeConstants.DataDirBase64 + PeConstants.DirImport * 8, 0x2200);
        Put32(output, opt + PeConstants.DataDirBase64 + PeConstants.DirImport * 8 + 4, 40);
        Assert.True(PeView.TryParse(output, out PeView outputPe));

        object?[] arguments =
        [
            new byte[0x1400], output, outputPe, 0x1000u,
            new System.Text.StringBuilder(), CancellationToken.None,
        ];
        Assert.False(InvokeUpxPrivate("ValidateSerializedDirectories", arguments));
    }

    [Fact]
    public void UpxRuntimeRebuildRestoresRelocationValuesAndBlocks()
    {
        byte[] recovered = new byte[0x500];
        const int extra = 0x20;
        Put32(recovered, extra, 0x300);
        recovered[extra + 4] = 0;
        recovered[0x300] = 0xF0;
        recovered[0x301] = 0x04;
        recovered[0x302] = 0x01; // delta 0x104: initial -4 -> target offset 0x100
        recovered[0x303] = 0;
        new byte[] { 0, 0, 0, 0, 0, 0, 0x12, 0x34 }.CopyTo(recovered, 0x100);

        object?[] arguments =
        [
            recovered, extra, 0x1000u, 0x1200u, 0x100u, 0x140000000UL, true,
            0x10, new System.Text.StringBuilder(), CancellationToken.None,
        ];
        Assert.True(InvokeUpxPrivate("TryRebuildRelocations", arguments));

        Assert.Equal(0x25, Assert.IsType<int>(arguments[1]));
        Assert.Equal(0x140002234UL, BitConverter.ToUInt64(recovered, 0x100));
        Assert.Equal(0x1000u, BitConverter.ToUInt32(recovered, 0x200));
        Assert.Equal(12u, BitConverter.ToUInt32(recovered, 0x204));
        Assert.Equal((ushort)0xA100, BitConverter.ToUInt16(recovered, 0x208));
    }

    [Fact]
    public void UpxRuntimeRebuildRestoresMovedResourcePayload()
    {
        byte[] packed = MinimalMappedPe();
        const int raw = 0x200;
        Put16(packed, raw + 14, 1);
        Put32(packed, raw + 16, 10);
        Put32(packed, raw + 20, 0x80000018);
        Put16(packed, raw + 0x18 + 14, 1);
        Put32(packed, raw + 0x18 + 16, 1);
        Put32(packed, raw + 0x18 + 20, 0x80000030);
        Put16(packed, raw + 0x30 + 14, 1);
        Put32(packed, raw + 0x30 + 16, 1033);
        Put32(packed, raw + 0x30 + 20, 0x48);
        Put32(packed, raw + 0x48, 0x2060);
        Put32(packed, raw + 0x4C, 4);
        Put32(packed, raw + 0x5C, 0x1280);
        new byte[] { 1, 2, 3, 4 }.CopyTo(packed, raw + 0x60);
        Assert.True(PeView.TryParse(packed, out PeView packedPe));

        byte[] recovered = new byte[0x500];
        Array originalSections = UpxOriginalSections(
            (0x1200u, 0x200u, 0x200u, 0x200u, 0x4000_0040u));
        object?[] arguments =
        [
            packed, packedPe, recovered, 0x1000u, 0x1200u, 0x100u, 0x2000u, 0x100u,
            (ushort)0, new System.Text.StringBuilder(), originalSections, CancellationToken.None,
        ];
        Assert.True(InvokeUpxPrivate("TryRebuildResources", arguments));

        Assert.Equal(0x1280u, BitConverter.ToUInt32(recovered, 0x200 + 0x48));
        Assert.Equal(new byte[] { 1, 2, 3, 4 }, recovered[0x280..0x284]);

        Put32(packed, raw + 0x5C, 0x1100);
        arguments[2] = new byte[0x500];
        Assert.False(InvokeUpxPrivate("TryRebuildResources", arguments));

        Put32(packed, raw + 0x5C, 0x1220);
        arguments[2] = new byte[0x500];
        Assert.False(InvokeUpxPrivate("TryRebuildResources", arguments));
    }

    private static byte[]? InvokeUpxLzma(byte[] packed, int outputLength)
    {
        MethodInfo decode = typeof(UpxStaticUnpacker).GetMethod(
            "DecodeUpxLzma", BindingFlags.NonPublic | BindingFlags.Static)
            ?? throw new MissingMethodException(typeof(UpxStaticUnpacker).FullName, "DecodeUpxLzma");
        return (byte[]?)decode.Invoke(
            null, [packed, 0, packed.Length, outputLength, CancellationToken.None]);
    }

    private static bool InvokeUpxPrivate(string methodName, object?[] arguments)
    {
        MethodInfo method = typeof(UpxStaticUnpacker).GetMethod(
            methodName, BindingFlags.NonPublic | BindingFlags.Static)
            ?? throw new MissingMethodException(typeof(UpxStaticUnpacker).FullName, methodName);
        return Assert.IsType<bool>(method.Invoke(null, arguments));
    }

    private static Array UpxOriginalSections(
        params (uint VirtualAddress, uint VirtualSize, uint RawOffset, uint RawSize, uint Characteristics)[] sections)
    {
        Type sectionType = typeof(UpxStaticUnpacker).GetNestedType(
            "OriginalSection", BindingFlags.NonPublic)
            ?? throw new MissingMemberException(typeof(UpxStaticUnpacker).FullName, "OriginalSection");
        Array result = Array.CreateInstance(sectionType, sections.Length);
        for (int i = 0; i < sections.Length; i++)
        {
            var section = sections[i];
            object value = Activator.CreateInstance(
                sectionType,
                [
                    section.VirtualAddress, section.VirtualSize, section.RawOffset,
                    section.RawSize, section.Characteristics,
                ])!;
            result.SetValue(value, i);
        }
        return result;
    }

    [Fact]
    public void ByteSearchRejectsMismatchedMask()
    {
        string path = Write("search.bin", [0x10, 0x20, 0x30]);
        using var image = RawImage.Load(path, 0, 32);
        Assert.Throws<ArgumentException>(() => ByteSearch.Find(image, 0, [0x10, 0x20], [true], true));
    }

    [Fact]
    public void ByteSearchFindsAddressZero()
    {
        string path = Write("base-zero.bin", [0x48, 0x8B, 0x01]);
        using var image = RawImage.Load(path, 0, 64);
        Assert.Equal(0UL, ByteSearch.Find(image, 0, [0x48, 0x8B], null, true));
    }

    [Fact]
    public void CallGraphKeepsCallerAtAddressZero()
    {
        string path = Write("callgraph-zero.bin", [0xC3, 0xC3]);
        using var image = RawImage.Load(path, 0, 64);
        var caller = new Function { Va = 0, Name = "zero" };
        var xrefs = new XrefDatabase();
        xrefs.Add(0, 1, XrefKind.Call);
        var result = new AnalysisResult
        {
            Image = image,
            Linear = new LinearIndex(),
            Functions = [caller],
            FunctionByVa = new Dictionary<ulong, Function> { [0] = caller },
            Xrefs = xrefs,
            Strings = [],
            JumpTables = new Dictionary<ulong, ulong[]>(),
            StringPointerSlots = new Dictionary<ulong, ulong>(),
            Warnings = [],
            Names = new Dictionary<ulong, string> { [0] = "zero" },
            Comments = new Dictionary<ulong, string>(),
        };

        CallGraph graph = CallGraph.Build(result);
        Assert.Equal(0UL, graph.ContainingFunction(0));
        Assert.Equal([1UL], graph.Callees(0));
        Assert.Equal([0UL], graph.Callers(1));
    }

    [Fact]
    public void PatchVaRejectsPartialSpanWithoutChangingBytes()
    {
        string path = Write("patch.bin", [1, 2, 3, 4]);
        using var image = RawImage.Load(path, 0x1000, 32);
        Assert.False(image.PatchVa(0x1002, [9, 9, 9]));
        Assert.Equal(new byte[] { 1, 2, 3, 4 }, image.ReadBytesAtVa(0x1000, 4));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public void StringScannerRejectsInvalidMinimumLength(int minimum)
    {
        string path = Write("strings.bin", "hello\0"u8.ToArray());
        using var image = RawImage.Load(path, 0, 32);
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            StringScanner.Scan(image, minLength: minimum, includeExecutable: true));
    }

    [Fact]
    public void StringScannerRejectsNegativeResultLimit()
    {
        string path = Write("strings-limit.bin", "hello\0"u8.ToArray());
        using var image = RawImage.Load(path, 0, 32);
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            StringScanner.Scan(image, maxResults: -1, includeExecutable: true));
    }

    [Fact]
    public void ExecutableStringScanDoesNotSpendLimitOnUnreferencedCandidates()
    {
        byte[] bytes = Enumerable.Range(0, 24)
            .SelectMany(i => System.Text.Encoding.ASCII.GetBytes($"text{i:D2}\0"))
            .ToArray();
        string path = Write("referenced-string.bin", bytes);
        using var image = RawImage.Load(path, 0, 32);
        ulong wanted = (ulong)(23 * 7);
        var found = StringScanner.Scan(image, new HashSet<ulong> { wanted },
            minLength: 4, maxResults: 1);
        Assert.Collection(found, value => Assert.Equal(wanted, value.Va));
    }

    [Fact]
    public void Arm64PeRoutesToArm64DecoderArchitecture()
    {
        string path = Write("arm64.exe", MinimalArm64Pe());
        using var image = PeImage.Load(path);
        Assert.Equal(Architecture.Arm64, image.Arch);
        Assert.Equal("arm64", image.ArchName);
        Assert.Equal(64, image.Bitness);
    }

    [Fact]
    public void KnownPackedPeOpensByAnalyzingItsEntryStub()
    {
        string path = Write("packed.exe", MinimalUpxPe());
        using var image = PeImage.Load(path);

        AnalysisResult result = AnalysisEngine.Analyze(image);

        Assert.Same(image, result.Image);
        Assert.NotSame(image, result.AnalysisImage);
        Assert.True(result.PackedAnalysisRestricted);
        Assert.Equal("UPX", result.PackerVerdict?.Name);
        Assert.Contains(result.Warnings, warning => warning.Contains("UPX", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(image.EntryVa, result.FunctionByVa.Keys);
        Assert.True(result.Linear.Count < 20_000,
            $"Packed payload should not become a multi-hundred-thousand-line code listing (actual {result.Linear.Count:N0}).");
    }

    [Fact]
    public void AssumeUnpackedSkipsEntryStubNarrowing()
    {
        // Same packed file as above, but analysed as already-unpacked (the "run to OEP" re-analysis path).
        // Detection must still report UPX, while the loader-stub restriction is skipped.
        string path = Write("packed-unpacked.exe", MinimalUpxPe());
        using var image = PeImage.Load(path);

        AnalysisResult result = AnalysisEngine.Analyze(image, new AnalysisOptions { AssumeUnpacked = true });

        Assert.Same(image, result.Image);
        Assert.Same(image, result.AnalysisImage);      // NOT narrowed to the stub window
        Assert.False(result.PackedAnalysisRestricted);
        Assert.Equal("UPX", result.PackerVerdict?.Name);
        Assert.Contains(result.Warnings, w => w.Contains("analysed as unpacked", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void MemoryImageEntryOverrideSeedsAnalysisAtTheOep()
    {
        // The shape a "run to OEP" dump has: memory layout, headers still naming the packer stub as the entry.
        const ulong imageBase = 0x140000000UL;
        const uint oepRva = 0x1000, stubRva = 0x3000;
        ulong oepVa = imageBase + oepRva;

        Assert.True(PeMemoryImage.TryLoadFromBytes(UnpackedMemoryImagePe(oepRva, stubRva), imageBase,
            "(unpacked process)", out var image, entryVaOverride: oepVa));

        Assert.Equal(oepVa, image.EntryVa);   // the override wins over AddressOfEntryPoint (the stub)

        AnalysisResult result = AnalysisEngine.Analyze(image, new AnalysisOptions { AssumeUnpacked = true });

        // The override is what seeds naming, recursive descent and the function list.
        Assert.True(result.Names.TryGetValue(oepVa, out string? entryName));
        Assert.Equal("start", entryName);
        Assert.Contains(oepVa, result.FunctionByVa.Keys);
        Assert.False(result.PackedAnalysisRestricted);
    }

    [Fact]
    public void MemoryImageWithoutEntryOverrideStillReportsTheHeaderEntry()
    {
        const ulong imageBase = 0x140000000UL;
        const uint oepRva = 0x1000, stubRva = 0x3000;

        Assert.True(PeMemoryImage.TryLoadFromBytes(UnpackedMemoryImagePe(oepRva, stubRva), imageBase,
            "(process)", out var image));

        Assert.Equal(imageBase + stubRva, image.EntryVa);   // unchanged for every existing caller
    }

    [Fact]
    public void PackedAnalysisBoundaryIsUsedByLazyDecompiler()
    {
        string path = Write("packed-jump.exe", MinimalUpxPe(jumpOutsideWindow: true));
        using var image = PeImage.Load(path);
        AnalysisResult result = AnalysisEngine.Analyze(image);
        Function entry = result.FunctionByVa[image.EntryVa];

        DecompiledFunction decompiled = Decompiler.Decompile(entry, result);

        Assert.NotEmpty(entry.Blocks);
        Assert.All(entry.Blocks.SelectMany(block => block.InstrVas),
            va => Assert.True(result.AnalysisImage.IsExecutableVa(va),
                $"Lazy CFG escaped the packed analysis range at {va:X}."));
        string pseudoC = string.Concat(decompiled.PseudoC.SelectMany(line => line.Tokens).Select(token => token.Text));
        Assert.DoesNotContain("decompilation error", pseudoC, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Arm64PackedPeUsesEntryStubAnalysis()
    {
        string path = Write("packed-arm64.exe", MinimalUpxPe(machine: 0xAA64));
        using var image = PeImage.Load(path);

        AnalysisResult result = AnalysisEngine.Analyze(image);

        Assert.Same(image, result.Image);
        Assert.NotSame(image, result.AnalysisImage);
        Assert.True(result.PackedAnalysisRestricted);
        Assert.Equal(Architecture.Arm64, result.AnalysisImage.Arch);
        Assert.Contains(image.EntryVa, result.FunctionByVa.Keys);
    }

    [Fact]
    public void PackedPeWithoutFileBackedEntryFallsBackSafely()
    {
        string path = Write("packed-no-entry.dll", MinimalUpxPe(includeEntry: false));
        using var image = PeImage.Load(path);

        AnalysisResult result = AnalysisEngine.Analyze(image);

        Assert.Same(image, result.AnalysisImage);
        Assert.False(result.PackedAnalysisRestricted);
        Assert.Equal("UPX", result.PackerVerdict?.Name);
        Assert.DoesNotContain(result.Warnings,
            warning => warning.Contains("limited to", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void HeuristicPackedPeAlsoUsesEntryStubAnalysis()
    {
        string path = Write("renamed-packer.exe", MinimalUpxPe(knownSectionNames: false, highEntropy: true));
        using var image = PeImage.Load(path);

        AnalysisResult result = AnalysisEngine.Analyze(image);

        Assert.Null(result.PackerVerdict?.Name);
        Assert.True(result.PackerVerdict?.IsPacked == true);
        Assert.True(result.PackedAnalysisRestricted);
        Assert.NotSame(image, result.AnalysisImage);
    }

    [Fact]
    public void MinimalElf32HeaderLoads()
    {
        byte[] elf = new byte[0x34];
        elf[0] = 0x7F; elf[1] = (byte)'E'; elf[2] = (byte)'L'; elf[3] = (byte)'F';
        elf[4] = 1; elf[5] = 1;
        Put16(elf, 0x12, 0x03);
        Put16(elf, 0x28, 0x34);
        string path = Write("minimal32.elf", elf);

        using var image = ElfImage.Load(path);
        Assert.Equal(32, image.Bitness);
        Assert.Equal(Architecture.X86, image.Arch);
        Assert.Empty(image.Sections);
    }

    [Fact]
    public void UnknownMachOCpuIsRejected()
    {
        byte[] mach = new byte[0x20];
        Put32(mach, 0, 0xFEEDFACF);
        Put32(mach, 4, 0x1234);
        Put32(mach, 0x0C, 2);
        string path = Write("unknown-cpu.macho", mach);
        Assert.Throws<BinaryFormatException>(() => MachOImage.Load(path));
    }

    [Fact]
    public void X64CallingConventionMatchesContainerAbi()
    {
        var windows = new X86Model(is64: true, sysv: false);
        var sysv = new X86Model(is64: true, sysv: true);
        Assert.Equal(["rcx", "rdx", "r8", "r9"], windows.ArgRegs.Select(r => r.Name));
        Assert.Equal(["rdi", "rsi", "rdx", "rcx", "r8", "r9"], sysv.ArgRegs.Select(r => r.Name));
        Assert.DoesNotContain(windows.CallerSaved, r => r.Name == "rdi");
        Assert.Contains(sysv.CallerSaved, r => r.Name == "rdi");
        Assert.True(windows.IsCalleeSaved(X86Model.FromIced(Register.RDI)));
        Assert.False(sysv.IsCalleeSaved(X86Model.FromIced(Register.RDI)));
    }

    [Fact]
    public void SignedDivisionOverflowAtUnknownWidthDoesNotThrow()
    {
        string path = Write("emulator.bin", [0xC3]);
        using var image = RawImage.Load(path, 0, 64);
        var rax = new RegExpr(new RegId("rax", 0, (int)Register.RAX));
        var block = new LiftedBlock { Start = 0, End = 1, Out = [] };
        block.Stmts.Add(new AssignStmt
        {
            Va = 0,
            Dest = rax,
            Src = new BinExpr(BinOp.SDiv, new Const(long.MinValue, 0), new Const(-1, 0), 0),
        });
        block.Stmts.Add(new ReturnStmt { Va = 0, Value = rax });
        var lifted = new LiftedFunction { Va = 0, Name = "overflow", Blocks = [block] };
        lifted.ByStart[0] = block;

        EmulationResult result = IlEmulator.Run(lifted, image);
        Assert.Equal(EmuStatus.Returned, result.Status);
        Assert.Empty(result.Values);
    }

    [Fact]
    public void X86ReturnCarriesReturnRegisterValue()
    {
        string path = Write("return.bin", [0xB8, 0x2A, 0, 0, 0, 0xC3]); // mov eax,42; ret
        using var image = RawImage.Load(path, 0, 64);
        var function = new Function { Va = 0, Name = "return_42" };
        CfgBuilder.Build(image, function);

        var lifted = new Lifter(image, new Dictionary<ulong, string>(),
            new Dictionary<ulong, ulong[]>()).Lift(function);
        var ret = Assert.IsType<ReturnStmt>(lifted.Blocks.Single().Stmts.Last());
        var value = Assert.IsType<RegExpr>(ret.Value);
        Assert.Equal(Register.RAX, (Register)value.Reg.Tag);
    }

    [Fact]
    public void NoReturnAnalysisPropagatesThroughDirectCallsAndStopsCfgFallthrough()
    {
        byte[] bytes =
        [
            0xE8, 0x0B, 0x00, 0x00, 0x00,             // 1000: call 1010
            0xB8, 0x2A, 0x00, 0x00, 0x00,             // unreachable mov eax,42
            0xC3,                                     // unreachable ret
            0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
            0xEB, 0xFE,                               // 1010: jmp 1010
        ];
        string path = Write("noreturn-direct.bin", bytes);
        using var image = RawImage.Load(path, 0x1000, 64);

        NoReturnInfo info = NoReturnAnalyzer.Analyze(image, [0x1000, 0x1010]);

        Assert.Contains(0x1000UL, info.Functions);
        Assert.Contains(0x1010UL, info.Functions);
        Assert.Contains(0x1000UL, info.CallSites);

        var caller = new Function { Va = 0x1000, Name = "caller", IsNoReturn = true };
        CfgBuilder.Build(image, caller, noReturn: info);
        BasicBlock block = Assert.Single(caller.Blocks);
        Assert.Equal([0x1000UL], block.InstrVas);
        Assert.Empty(block.Out);

        var code = CodeMap.Compute(image, [0x1000], new Dictionary<ulong, ulong[]>(), info);
        Assert.True(code.IsCode(0x1000));
        Assert.True(code.IsCode(0x1010));
        Assert.False(code.IsCode(0x1005));

        CodeMap.GapScan(image, code, new Dictionary<ulong, ulong[]>(), info);
        for (ulong va = 0x1005; va <= 0x100A; va++)
            Assert.False(code.IsCode(va)); // gap recovery must not resurrect any no-return fallthrough byte
    }

    [Fact]
    public void AnalysisEnginePublishesNoReturnFunctionsAndClassifiesFallthroughAsData()
    {
        byte[] bytes =
        [
            0xE8, 0x0B, 0x00, 0x00, 0x00,             // 1000: call 1010
            0xB8, 0x2A, 0x00, 0x00, 0x00, 0xC3,       // unreachable
            0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
            0xEB, 0xFE,                               // 1010: jmp 1010
        ];
        string path = Write("noreturn-engine.bin", bytes);
        NamedSymbol[] symbols =
        [
            new(0x1000, "caller", NamedSymbolKind.Function),
            new(0x1010, "halt_forever", NamedSymbolKind.Function),
        ];
        using var image = RawImage.Load(path, 0x1000, 64, 0x1000, symbols);

        AnalysisResult result = AnalysisEngine.Analyze(image);

        Assert.True(result.FunctionByVa[0x1000].IsNoReturn);
        Assert.True(result.FunctionByVa[0x1010].IsNoReturn);
        Assert.Contains(0x1000UL, result.NoReturn.CallSites);
        long fallthroughLine = result.Linear.IndexOf(0x1005);
        Assert.Equal(0x1005UL, result.Linear.VaAt(fallthroughLine));
        Assert.True(result.Linear.IsDataAt(fallthroughLine));
    }

    [Fact]
    public void NoReturnAnalysisRetainsFallthroughWhenCalleeCanReturn()
    {
        byte[] bytes =
        [
            0xE8, 0x0B, 0x00, 0x00, 0x00,             // 1000: call 1010
            0xC3,                                     // 1005: ret
            0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
            0xC3,                                     // 1010: ret
        ];
        string path = Write("returns-direct.bin", bytes);
        using var image = RawImage.Load(path, 0x1000, 64);

        NoReturnInfo info = NoReturnAnalyzer.Analyze(image, [0x1000, 0x1010]);

        Assert.Empty(info.Functions);
        Assert.Empty(info.CallSites);
        var caller = new Function { Va = 0x1000, Name = "caller" };
        CfgBuilder.Build(image, caller, noReturn: info);
        Assert.Equal([0x1000UL, 0x1005UL], Assert.Single(caller.Blocks).InstrVas);
    }

    [Fact]
    public void KnownExitProcessImportTerminatesControlFlow()
    {
        byte[] bytes = Enumerable.Repeat((byte)0xCC, 0x28).ToArray();
        new byte[] { 0xFF, 0x15, 0x1A, 0x00, 0x00, 0x00, 0xC3 }.CopyTo(bytes, 0);
        string path = Write("noreturn-import.bin", bytes);
        using var raw = RawImage.Load(path, 0x1000, 64);
        using var image = new ImportedImage(raw, new ImportEntry("kernel32.dll", "ExitProcess", 0x1020));

        NoReturnInfo info = NoReturnAnalyzer.Analyze(image, [0x1000]);

        Assert.Contains(0x1000UL, info.Functions);
        Assert.Contains(0x1000UL, info.CallSites);
        var caller = new Function { Va = 0x1000, Name = "caller", IsNoReturn = true };
        CfgBuilder.Build(image, caller, noReturn: info);
        Assert.Equal([0x1000UL], Assert.Single(caller.Blocks).InstrVas);
    }

    [Theory]
    [InlineData("ExitProcess")]
    [InlineData("__imp_ExitProcess@4")]
    [InlineData("libc!abort")]
    [InlineData("exit@@GLIBC_2.2.5")]
    [InlineData("std::terminate()")]
    public void KnownNoReturnNamesTolerateCommonDecoration(string name)
    {
        Assert.True(KnownNoReturnNames.IsKnown(name));
        Assert.True(ApiDatabase.Lookup("ExitProcess")!.NoReturn);
        Assert.False(ApiDatabase.Lookup("TerminateProcess")!.NoReturn);
    }

    [Fact]
    public void NoReturnInfoDoesNotExposeMutableSets()
    {
        var info = new NoReturnInfo([0x1000], [0x1010]);

        Assert.False(info.Functions is HashSet<ulong>);
        Assert.False(info.CallSites is HashSet<ulong>);
        Assert.Throws<NotSupportedException>(() => ((ISet<ulong>)info.Functions).Add(0x2000));
        Assert.Throws<NotSupportedException>(() => ((ISet<ulong>)info.CallSites).Clear());
    }

    [Fact]
    public void ReturningSoftwareInterruptDoesNotMakeFunctionNoReturn()
    {
        string path = Write("returning-interrupt.bin", [0xCD, 0x80, 0xC3]); // int 80h; ret
        using var image = RawImage.Load(path, 0x1000, 64);

        NoReturnInfo info = NoReturnAnalyzer.Analyze(image, [0x1000]);

        Assert.Empty(info.Functions);
        Assert.Empty(info.CallSites);
    }

    [Fact]
    public void GapScanIgnoresUnreachedNoReturnCallSiteDecodedInsideCodeBytes()
    {
        byte[] bytes =
        [
            0xC7, 0x80, 0x00, 0x00, 0x00, 0xE8, 0x00, 0x00, 0x00, 0x00,
            0x48, 0x89, 0xC8, 0xC3, // 100A: mov rax,rcx; ret
            0xCC,                   // confirmed boundary for gap-run recovery
        ];
        string path = Write("noreturn-speculative-call.bin", bytes);
        using var image = RawImage.Load(path, 0x1000, 64);
        var code = new CodeBitmap(image);
        code.Mark(0x1000, 10); // the E8 at 1005 is an operand byte, not a reached call instruction
        var speculative = new NoReturnInfo([], [0x1005]);

        CodeMap.GapScan(image, code, new Dictionary<ulong, ulong[]>(), speculative);

        Assert.True(code.IsCode(0x100A));
        Assert.True(code.IsCode(0x100D));
    }

    [Fact]
    public void ShortJumpSkippedInstructionRendersAsUnreachableDisassembly()
    {
        byte[] bytes =
        [
            0xEB, 0x02,             // 1000: jmp short 1004
            0x33, 0xC0,             // 1002: xor eax,eax (not reached)
            0x48, 0x83, 0xC4, 0x28, // 1004: add rsp,28h
            0xC3,                   // 1008: ret
        ];
        string path = Write("unreachable-short-jump.bin", bytes);
        using var image = RawImage.Load(path, 0x1000, 64);

        AnalysisResult result = AnalysisEngine.Analyze(image);
        long line = result.Linear.IndexOf(0x1002);

        Assert.Equal(0x1002UL, result.Linear.VaAt(line));
        Assert.False(result.Linear.IsDataAt(line));
        Assert.True(result.Linear.IsUnreachableAt(line));
        Assert.False(result.Linear.IsReachableCodeAt(line));
        Assert.Equal(LinearLineKind.UnreachableDecode, result.Linear.KindAt(line));

        Function function = result.FunctionByVa[0x1000];
        CfgBuilder.Build(image, function, noReturn: result.NoReturn);
        Assert.DoesNotContain(function.Blocks.SelectMany(b => b.InstrVas), va => va == 0x1002);

        using var writer = new StringWriter();
        SourceExporter.WriteAsm(writer, result);
        string exportedLine = Assert.Single(writer.ToString().Split(Environment.NewLine),
            x => x.Contains(LinearIndex.UnreachableComment, StringComparison.Ordinal));
        Assert.Contains("xor", exportedLine.ToLowerInvariant());
        Assert.Contains("may be inline data", exportedLine);
    }

    [Fact]
    public void LinearIndexPreservesBit62AndRejectsReservedBit63()
    {
        const ulong highVa = (1UL << 62) + 0x1234;
        var index = new LinearIndex();

        index.AddUnreachable(highVa);
        index.Add(highVa + 2, isData: true);

        Assert.Equal(highVa, index.VaAt(0));
        Assert.True(index.IsUnreachableAt(0));
        Assert.Equal(highVa + 2, index.VaAt(1));
        Assert.True(index.IsDataAt(1));
        Assert.Throws<ArgumentOutOfRangeException>(() => index.Add(1UL << 63));
    }

    [Fact]
    public void LinearIndexClonePreservesUnreachableKindOutsideReplacement()
    {
        var index = new LinearIndex();
        index.Add(0x1000);
        index.AddUnreachable(0x1002);
        index.Add(0x1004, isData: true);

        LinearIndex clone = index.CloneWithRegion(0x1000, 0x1001, [0x1000]);

        long line = clone.IndexOf(0x1002);
        Assert.Equal(0x1002UL, clone.VaAt(line));
        Assert.Equal(LinearLineKind.UnreachableDecode, clone.KindAt(line));
    }

    [Fact]
    public void UnreachableCandidateDoesNotHideOverlappingReachableInstruction()
    {
        byte[] bytes =
        [
            0xEB, 0x02, // 1000: jmp 1004
            0xEB, 0x00, // 1002: candidate, but a separate symbol enters at 1003
            0xC3,
            0xCC,
        ];
        NamedSymbol[] symbols = [new(0x1003, "overlap", NamedSymbolKind.Function)];
        string path = Write("unreachable-overlap.bin", bytes);
        using var image = RawImage.Load(path, 0x1000, 64, 0x1000, symbols);

        AnalysisResult result = AnalysisEngine.Analyze(image);
        long dataLine = result.Linear.IndexOf(0x1002);
        long codeLine = result.Linear.IndexOf(0x1003);

        Assert.Equal(0x1002UL, result.Linear.VaAt(dataLine));
        Assert.True(result.Linear.IsDataAt(dataLine));
        Assert.False(result.Linear.IsUnreachableAt(dataLine));
        Assert.Equal(0x1003UL, result.Linear.VaAt(codeLine));
        Assert.True(result.Linear.IsReachableCodeAt(codeLine));
    }

    [Fact]
    public void UnreachableCandidateRequiresRecoveredJumpTarget()
    {
        byte[] bytes =
        [
            0xEB, 0x02, // 1000: jmp 1004
            0x33, 0xC0, // clean skipped decode
            0x0F,       // truncated/invalid target
        ];
        string path = Write("unreachable-invalid-target.bin", bytes);
        using var image = RawImage.Load(path, 0x1000, 64);

        AnalysisResult result = AnalysisEngine.Analyze(image);
        long line = result.Linear.IndexOf(0x1002);

        Assert.Equal(0x1002UL, result.Linear.VaAt(line));
        Assert.True(result.Linear.IsDataAt(line));
        Assert.False(result.Linear.IsUnreachableAt(line));
    }

    [Fact]
    public void Arm64NoReturnCallSuppressesLinearFallthrough()
    {
        byte[] bytes =
        [
            0x04, 0x00, 0x00, 0x94, // 1000: bl 1010
            0x40, 0x05, 0x80, 0x52, // unreachable mov w0,#42
            0xC0, 0x03, 0x5F, 0xD6, // unreachable ret
            0x1F, 0x20, 0x03, 0xD5, // unreachable nop
            0x00, 0x00, 0x00, 0x14, // 1010: b 1010
        ];
        string path = Write("noreturn-arm64.bin", bytes);
        using var image = RawImage.Load(path, 0x1000, 64, 0x1000, Architecture.Arm64, null);

        AnalysisResult result = ArmAnalyzer.Analyze(image);

        Assert.True(result.FunctionByVa[0x1000].IsNoReturn);
        Assert.True(result.FunctionByVa[0x1010].IsNoReturn);
        long fallthroughLine = result.Linear.IndexOf(0x1004);
        Assert.Equal(0x1004UL, result.Linear.VaAt(fallthroughLine));
        Assert.True(result.Linear.IsDataAt(fallthroughLine));
    }

    [Fact]
    public void I8051NoReturnCallSuppressesLinearFallthrough()
    {
        byte[] bytes =
        [
            0x12, 0x00, 0x08, // 1000: lcall 1008
            0x74, 0x2A,       // unreachable mov A,#2Ah
            0x22,             // unreachable ret
            0x00, 0x00,
            0x80, 0xFE,       // 1008: sjmp 1008
        ];
        string path = Write("noreturn-8051.bin", bytes);
        using var image = RawImage.Load(path, 0x1000, 16, 0x1000, Architecture.I8051, null);

        AnalysisResult result = I8051Analyzer.Analyze(image);

        Assert.True(result.FunctionByVa[0x1000].IsNoReturn);
        Assert.True(result.FunctionByVa[0x1008].IsNoReturn);
        long fallthroughLine = result.Linear.IndexOf(0x1003);
        Assert.Equal(0x1003UL, result.Linear.VaAt(fallthroughLine));
        Assert.True(result.Linear.IsDataAt(fallthroughLine));
    }

    [Fact]
    public void I8051RelativeTargetIncludesImageBase()
    {
        string path = Write("jump.8051", [0x80, 0x02]); // sjmp +2 -> offset 4
        using var image = RawImage.Load(path, 0x1000, 16, 0x1000, Architecture.I8051, null);
        using var disassembler = new I8051Disassembler(image, null);
        Assert.True(disassembler.TryDecode(0x1000, out var instruction));
        Assert.Equal(0x1004UL, instruction.DirectTarget);
    }

    private string Write(string name, byte[] bytes)
    {
        string path = Path.Combine(_directory, name);
        File.WriteAllBytes(path, bytes);
        return path;
    }

    private static byte[] MinimalArm64Pe()
    {
        byte[] pe = new byte[0x200];
        pe[0] = (byte)'M'; pe[1] = (byte)'Z';
        Put32(pe, 0x3C, 0x80);
        Put32(pe, 0x80, 0x00004550);
        Put16(pe, 0x84, 0xAA64);
        Put16(pe, 0x94, 0xF0);
        Put16(pe, 0x98, 0x20B);
        BitConverter.GetBytes(0x140000000UL).CopyTo(pe, 0xB0);
        Put32(pe, 0xD4, 0x200);
        return pe;
    }

    private static byte[] MinimalUpxPe(ushort machine = 0x8664, bool includeEntry = true,
        bool knownSectionNames = true, bool highEntropy = false, bool jumpOutsideWindow = false)
    {
        const int headers = 0x200;
        const int packedSize = 0x80_000;
        const uint packedRva = 0x81_000;
        byte[] pe = new byte[headers + packedSize];
        if (highEntropy)
            for (int i = headers; i < pe.Length; i++) pe[i] = (byte)(i - headers);
        pe[0] = (byte)'M'; pe[1] = (byte)'Z';
        Put32(pe, 0x3C, 0x80);
        Put32(pe, 0x80, 0x00004550);
        Put16(pe, 0x84, machine);
        Put16(pe, 0x86, 2);
        Put16(pe, 0x94, 0xF0);
        Put16(pe, 0x96, 0x0022);
        Put16(pe, 0x98, 0x20B);
        uint entryRva = includeEntry ? packedRva + packedSize - 0x1000 : 0;
        Put32(pe, 0xA8, entryRva);
        BitConverter.GetBytes(0x140000000UL).CopyTo(pe, 0xB0);
        Put32(pe, 0xB8, 0x1000);
        Put32(pe, 0xBC, 0x200);
        Put32(pe, 0xD0, packedRva + packedSize);
        Put32(pe, 0xD4, headers);

        int upx0 = 0x188;
        (knownSectionNames ? "UPX0"u8 : "STUB0"u8).CopyTo(pe.AsSpan(upx0));
        Put32(pe, upx0 + 8, 0x80_000);
        Put32(pe, upx0 + 12, 0x1000);
        Put32(pe, upx0 + 20, headers);
        Put32(pe, upx0 + 36, 0xE0000080);

        int upx1 = upx0 + 40;
        (knownSectionNames ? "UPX1"u8 : "CRYPT"u8).CopyTo(pe.AsSpan(upx1));
        Put32(pe, upx1 + 8, packedSize);
        Put32(pe, upx1 + 12, packedRva);
        Put32(pe, upx1 + 16, packedSize);
        Put32(pe, upx1 + 20, headers);
        Put32(pe, upx1 + 36, 0xE0000040);

        if (includeEntry)
        {
            // A tiny valid loader stub at the entry; the preceding bytes stand in for the compressed payload.
            int entryOffset = headers + packedSize - 0x1000;
            if (machine == 0xAA64)
            {
                // ret
                pe[entryOffset] = 0xC0; pe[entryOffset + 1] = 0x03;
                pe[entryOffset + 2] = 0x5F; pe[entryOffset + 3] = 0xD6;
            }
            else if (jumpOutsideWindow)
            {
                // jmp to the beginning of UPX1, well before the retained 64 KiB look-behind window.
                pe[entryOffset] = 0xE9;
                long displacement = (long)packedRva - ((long)entryRva + 5);
                Put32(pe, entryOffset + 1, unchecked((uint)(int)displacement));
            }
            else pe[entryOffset] = 0xC3;
        }
        return pe;
    }

    private static byte[] MinimalStaticallyUnpackableUpxPe(uint originalRawOffset = 0x200)
    {
        const int storedHeader = 0x300;
        byte[] plain = new byte[0x500];
        Put32(plain, storedHeader, PeConstants.PeSignature);
        Put16(plain, storedHeader + 4, PeConstants.Machine_x64);
        Put16(plain, storedHeader + 6, 1);
        Put16(plain, storedHeader + 20, 0xF0);
        Put16(plain, storedHeader + 22,
            PeConstants.IMAGE_FILE_EXECUTABLE_IMAGE);
        int opt = storedHeader + PeConstants.OptHeaderFromSig;
        Put16(plain, opt, PeConstants.Pe32PlusMagic);
        Put32(plain, opt + 4, 0x200);
        Put32(plain, opt + PeConstants.Opt_AddressOfEntryPoint, 0x1000);
        Put32(plain, opt + 20, 0x1000);
        BitConverter.GetBytes(0x140000000UL).CopyTo(plain, opt + PeConstants.Opt_ImageBase64);
        Put32(plain, opt + PeConstants.Opt_SectionAlignment, 0x1000);
        Put32(plain, opt + PeConstants.Opt_FileAlignment, 0x200);
        Put32(plain, opt + PeConstants.Opt_SizeOfImage, 0x2000);
        Put32(plain, opt + PeConstants.Opt_SizeOfHeaders, 0x200);
        Put32(plain, opt + PeConstants.Opt_NumberOfRvaAndSizes64, 16);
        int section = opt + 0xF0;
        ".text"u8.CopyTo(plain.AsSpan(section));
        Put32(plain, section + PeConstants.Sec_VirtualSize, 0x200);
        Put32(plain, section + PeConstants.Sec_VirtualAddress, 0x1000);
        Put32(plain, section + PeConstants.Sec_SizeOfRawData, 0x200);
        Put32(plain, section + PeConstants.Sec_PointerToRawData, originalRawOffset);
        Put32(plain, section + PeConstants.Sec_Characteristics,
            PeConstants.SCN_CNT_CODE | PeConstants.SCN_MEM_EXECUTE | PeConstants.SCN_MEM_READ);
        Put32(plain, plain.Length - 4, storedHeader);

        byte[] compressed = NrvLiteralStream(plain);
        byte[] packed = new byte[0x200 + compressed.Length];
        packed[0] = (byte)'M'; packed[1] = (byte)'Z';
        Put32(packed, PeConstants.DosLfanewOffset, 0x80);
        Put32(packed, 0x80, PeConstants.PeSignature);
        Put16(packed, 0x84, PeConstants.Machine_x64);
        Put16(packed, 0x86, 2);
        Put16(packed, 0x94, 0xF0);
        Put16(packed, 0x96, PeConstants.IMAGE_FILE_EXECUTABLE_IMAGE);
        int packedOpt = 0x80 + PeConstants.OptHeaderFromSig;
        Put16(packed, packedOpt, PeConstants.Pe32PlusMagic);
        Put32(packed, packedOpt + PeConstants.Opt_AddressOfEntryPoint, 0x2000);
        BitConverter.GetBytes(0x140000000UL).CopyTo(packed, packedOpt + PeConstants.Opt_ImageBase64);
        Put32(packed, packedOpt + PeConstants.Opt_SectionAlignment, 0x1000);
        Put32(packed, packedOpt + PeConstants.Opt_FileAlignment, 0x200);
        Put32(packed, packedOpt + PeConstants.Opt_SizeOfImage, 0x3000);
        Put32(packed, packedOpt + PeConstants.Opt_SizeOfHeaders, 0x200);
        int upx0 = packedOpt + 0xF0;
        "UPX0"u8.CopyTo(packed.AsSpan(upx0));
        Put32(packed, upx0 + PeConstants.Sec_VirtualSize, 0x1000);
        Put32(packed, upx0 + PeConstants.Sec_VirtualAddress, 0x1000);
        Put32(packed, upx0 + PeConstants.Sec_Characteristics, 0xE0000080);
        int upx1 = upx0 + PeConstants.SectionHeaderSize;
        "UPX1"u8.CopyTo(packed.AsSpan(upx1));
        Put32(packed, upx1 + PeConstants.Sec_VirtualSize, (uint)compressed.Length);
        Put32(packed, upx1 + PeConstants.Sec_VirtualAddress, 0x2000);
        Put32(packed, upx1 + PeConstants.Sec_SizeOfRawData, (uint)compressed.Length);
        Put32(packed, upx1 + PeConstants.Sec_PointerToRawData, 0x200);
        Put32(packed, upx1 + PeConstants.Sec_Characteristics, 0xE0000040);

        int header = 0x1E0;
        "UPX!"u8.CopyTo(packed.AsSpan(header));
        packed[header + 4] = 13;
        packed[header + 5] = 36;
        packed[header + 6] = 3; // M_NRV2B_8
        packed[header + 7] = 9;
        Put32(packed, header + 8, Adler32ForTest(plain));
        Put32(packed, header + 12, Adler32ForTest(compressed));
        Put32(packed, header + 16, (uint)plain.Length);
        Put32(packed, header + 20, (uint)compressed.Length);
        Put32(packed, header + 24, 0x400);
        compressed.CopyTo(packed, 0x200);
        return packed;
    }

    private static byte[] MinimalRunnableUpxPe()
    {
        const int storedHeader = 0x4400;
        const int originalSectionCount = 4;
        const int originalFileSize = 0xE00;
        byte[] plain = new byte[storedHeader + PeConstants.OptHeaderFromSig + 0xF0 +
                                originalSectionCount * PeConstants.SectionHeaderSize + 14];
        plain[0] = 0xC3;

        Put32(plain, storedHeader, PeConstants.PeSignature);
        Put16(plain, storedHeader + 4, PeConstants.Machine_x64);
        Put16(plain, storedHeader + 6, originalSectionCount);
        Put16(plain, storedHeader + 20, 0xF0);
        Put16(plain, storedHeader + 22, PeConstants.IMAGE_FILE_EXECUTABLE_IMAGE);
        int opt = storedHeader + PeConstants.OptHeaderFromSig;
        Put16(plain, opt, PeConstants.Pe32PlusMagic);
        Put32(plain, opt + 4, 0x200);
        Put32(plain, opt + PeConstants.Opt_AddressOfEntryPoint, 0x1000);
        Put32(plain, opt + 20, 0x1000);
        BitConverter.GetBytes(0x140000000UL).CopyTo(plain, opt + PeConstants.Opt_ImageBase64);
        Put32(plain, opt + PeConstants.Opt_SectionAlignment, 0x1000);
        Put32(plain, opt + PeConstants.Opt_FileAlignment, 0x200);
        Put32(plain, opt + PeConstants.Opt_SizeOfImage, 0x5000);
        Put32(plain, opt + PeConstants.Opt_SizeOfHeaders, 0x400);
        Put32(plain, opt + PeConstants.Opt_NumberOfRvaAndSizes64, 16);
        int dirs = opt + PeConstants.DataDirBase64;
        Put32(plain, dirs + PeConstants.DirImport * 8, 0x2200);
        Put32(plain, dirs + PeConstants.DirImport * 8 + 4, 40);
        Put32(plain, dirs + PeConstants.DirResource * 8, 0x3000);
        Put32(plain, dirs + PeConstants.DirResource * 8 + 4, 0x104);
        Put32(plain, dirs + PeConstants.DirBaseReloc * 8, 0x4000);
        Put32(plain, dirs + PeConstants.DirBaseReloc * 8 + 4, 8);

        int section = opt + 0xF0;
        PutOriginalSection(
            plain, section, ".text", 0x1000, 0x200, 0x400, 0x200,
            PeConstants.SCN_CNT_CODE | PeConstants.SCN_MEM_EXECUTE | PeConstants.SCN_MEM_READ);
        PutOriginalSection(
            plain, section + 40, ".rdata", 0x2000, 0x400, 0x600, 0x400,
            PeConstants.SCN_CNT_INITIALIZED_DATA | PeConstants.SCN_MEM_READ);
        PutOriginalSection(
            plain, section + 80, ".rsrc", 0x3000, 0x200, 0xA00, 0x200,
            PeConstants.SCN_CNT_INITIALIZED_DATA | PeConstants.SCN_MEM_READ);
        PutOriginalSection(
            plain, section + 120, ".reloc", 0x4000, 0x200, 0xC00, 0x200,
            PeConstants.SCN_CNT_INITIALIZED_DATA | PeConstants.SCN_MEM_READ);

        Put32(plain, 0x1200 + 12, 0x2180);
        Put32(plain, 0x1200 + 16, 0x2100);
        BitConverter.GetBytes(0x2160UL).CopyTo(plain, 0x1100);

        const int importStream = 0x4000;
        Put32(plain, importStream, 0x20);
        Put32(plain, importStream + 4, 0x1100);
        plain[importStream + 8] = 1;
        "ExitProcess\0"u8.CopyTo(plain.AsSpan(importStream + 9));

        int extra = section + originalSectionCount * PeConstants.SectionHeaderSize;
        Put32(plain, extra, importStream);
        Put32(plain, extra + 4, 0);
        Put16(plain, extra + 8, 0);
        Put32(plain, extra + 10, storedHeader);

        byte[] compressed = NrvLiteralStream(plain);
        int packedResourceRaw = (0x400 + compressed.Length + 0x1FF) & ~0x1FF;
        byte[] packed = new byte[packedResourceRaw + 0x200];
        packed[0] = (byte)'M';
        packed[1] = (byte)'Z';
        Put32(packed, PeConstants.DosLfanewOffset, 0x80);
        Put32(packed, 0x80, PeConstants.PeSignature);
        Put16(packed, 0x84, PeConstants.Machine_x64);
        Put16(packed, 0x86, 3);
        Put16(packed, 0x94, 0xF0);
        Put16(packed, 0x96, PeConstants.IMAGE_FILE_EXECUTABLE_IMAGE);
        int packedOpt = 0x80 + PeConstants.OptHeaderFromSig;
        Put16(packed, packedOpt, PeConstants.Pe32PlusMagic);
        Put32(packed, packedOpt + PeConstants.Opt_AddressOfEntryPoint, 0x5000);
        BitConverter.GetBytes(0x140000000UL).CopyTo(packed, packedOpt + PeConstants.Opt_ImageBase64);
        Put32(packed, packedOpt + PeConstants.Opt_SectionAlignment, 0x1000);
        Put32(packed, packedOpt + PeConstants.Opt_FileAlignment, 0x200);
        Put32(packed, packedOpt + PeConstants.Opt_SizeOfImage, 0xB000);
        Put32(packed, packedOpt + PeConstants.Opt_SizeOfHeaders, 0x400);
        Put32(packed, packedOpt + PeConstants.Opt_NumberOfRvaAndSizes64, 16);
        int packedDirs = packedOpt + PeConstants.DataDirBase64;
        Put32(packed, packedDirs + PeConstants.DirImport * 8, 0xA080);
        Put32(packed, packedDirs + PeConstants.DirImport * 8 + 4, 0x40);
        Put32(packed, packedDirs + PeConstants.DirResource * 8, 0xA100);
        Put32(packed, packedDirs + PeConstants.DirResource * 8 + 4, 0x100);

        int upx0 = packedOpt + 0xF0;
        PutPackedSection(packed, upx0, "UPX0", 0x1000, 0x4000, 0, 0, 0xE0000080);
        PutPackedSection(
            packed, upx0 + 40, "UPX1", 0x5000, 0x5000, 0x400,
            (uint)(packedResourceRaw - 0x400), 0xE0000040);
        PutPackedSection(
            packed, upx0 + 80, ".rsrc", 0xA000, 0x200,
            (uint)packedResourceRaw, 0x200, 0xC0000040);

        const int packHeader = 0x3E0;
        "UPX!"u8.CopyTo(packed.AsSpan(packHeader));
        packed[packHeader + 4] = 13;
        packed[packHeader + 5] = 36;
        packed[packHeader + 6] = 3;
        packed[packHeader + 7] = 9;
        Put32(packed, packHeader + 8, Adler32ForTest(plain));
        Put32(packed, packHeader + 12, Adler32ForTest(compressed));
        Put32(packed, packHeader + 16, (uint)plain.Length);
        Put32(packed, packHeader + 20, (uint)compressed.Length);
        Put32(packed, packHeader + 24, originalFileSize);
        compressed.CopyTo(packed, 0x400);

        int packedResource = packedResourceRaw + 0x100;
        Put16(packed, packedResource + 14, 1);
        Put32(packed, packedResource + 16, 10);
        Put32(packed, packedResource + 20, 0x80000018);
        Put16(packed, packedResource + 0x18 + 14, 1);
        Put32(packed, packedResource + 0x18 + 16, 1);
        Put32(packed, packedResource + 0x18 + 20, 0x80000030);
        Put16(packed, packedResource + 0x30 + 14, 1);
        Put32(packed, packedResource + 0x30 + 16, 1033);
        Put32(packed, packedResource + 0x30 + 20, 0x48);
        Put32(packed, packedResource + 0x48, 0xA160);
        Put32(packed, packedResource + 0x4C, 4);
        Put32(packed, packedResource + 0x5C, 0x3100);
        new byte[] { 1, 2, 3, 4 }.CopyTo(packed, packedResource + 0x60);
        "KERNEL32.DLL\0"u8.CopyTo(packed.AsSpan(packedResourceRaw + 0xA0));
        return packed;
    }

    private static void PutOriginalSection(
        byte[] bytes, int offset, string name, uint virtualAddress, uint virtualSize,
        uint rawOffset, uint rawSize, uint characteristics)
    {
        System.Text.Encoding.ASCII.GetBytes(name).CopyTo(bytes, offset);
        Put32(bytes, offset + PeConstants.Sec_VirtualSize, virtualSize);
        Put32(bytes, offset + PeConstants.Sec_VirtualAddress, virtualAddress);
        Put32(bytes, offset + PeConstants.Sec_SizeOfRawData, rawSize);
        Put32(bytes, offset + PeConstants.Sec_PointerToRawData, rawOffset);
        Put32(bytes, offset + PeConstants.Sec_Characteristics, characteristics);
    }

    private static void PutPackedSection(
        byte[] bytes, int offset, string name, uint virtualAddress, uint virtualSize,
        uint rawOffset, uint rawSize, uint characteristics) =>
        PutOriginalSection(
            bytes, offset, name, virtualAddress, virtualSize, rawOffset, rawSize, characteristics);

    /// <summary>A packed PE laid out the way <c>DumpImage</c> produces it (file offset == RVA), with the
    /// header's entry still pointing at the loader stub in UPX1 and a recovered function prologue at
    /// <paramref name="oepRva"/> in UPX0 — the shape of an image dumped from a process stopped at its OEP.</summary>
    private static byte[] UnpackedMemoryImagePe(uint oepRva, uint stubRva)
    {
        byte[] pe = new byte[0x4000];
        pe[0] = (byte)'M';
        pe[1] = (byte)'Z';
        Put32(pe, PeConstants.DosLfanewOffset, 0x80);
        Put32(pe, 0x80, PeConstants.PeSignature);
        Put16(pe, 0x84, PeConstants.Machine_x64);
        Put16(pe, 0x86, 2);
        Put16(pe, 0x94, 0xF0);
        Put16(pe, 0x96, PeConstants.IMAGE_FILE_EXECUTABLE_IMAGE);
        int opt = 0x80 + PeConstants.OptHeaderFromSig;
        Put16(pe, opt, PeConstants.Pe32PlusMagic);
        Put32(pe, opt + PeConstants.Opt_AddressOfEntryPoint, stubRva);   // the packer stub, not the OEP
        BitConverter.GetBytes(0x140000000UL).CopyTo(pe, opt + PeConstants.Opt_ImageBase64);
        Put32(pe, opt + PeConstants.Opt_SectionAlignment, 0x1000);
        Put32(pe, opt + PeConstants.Opt_FileAlignment, 0x1000);   // == SectionAlignment: a memory layout
        Put32(pe, opt + PeConstants.Opt_SizeOfImage, 0x4000);
        Put32(pe, opt + PeConstants.Opt_SizeOfHeaders, 0x1000);
        Put32(pe, opt + PeConstants.Opt_NumberOfRvaAndSizes64, 16);

        int upx0 = opt + 0xF0;
        "UPX0"u8.CopyTo(pe.AsSpan(upx0));
        Put32(pe, upx0 + PeConstants.Sec_VirtualSize, 0x2000);
        Put32(pe, upx0 + PeConstants.Sec_VirtualAddress, 0x1000);
        Put32(pe, upx0 + PeConstants.Sec_SizeOfRawData, 0x2000);
        Put32(pe, upx0 + PeConstants.Sec_PointerToRawData, 0x1000);
        Put32(pe, upx0 + PeConstants.Sec_Characteristics, 0xE0000080);

        int upx1 = upx0 + 40;
        "UPX1"u8.CopyTo(pe.AsSpan(upx1));
        Put32(pe, upx1 + PeConstants.Sec_VirtualSize, 0x1000);
        Put32(pe, upx1 + PeConstants.Sec_VirtualAddress, 0x3000);
        Put32(pe, upx1 + PeConstants.Sec_SizeOfRawData, 0x1000);
        Put32(pe, upx1 + PeConstants.Sec_PointerToRawData, 0x3000);
        Put32(pe, upx1 + PeConstants.Sec_Characteristics, 0xE0000040);

        // The recovered program at the OEP: push rbp; mov rbp,rsp; xor eax,eax; pop rbp; ret
        new byte[] { 0x55, 0x48, 0x89, 0xE5, 0x31, 0xC0, 0x5D, 0xC3 }.CopyTo(pe, (int)oepRva);
        pe[(int)stubRva] = 0xC3;   // the spent loader stub
        return pe;
    }

    private static byte[] MinimalMappedPe()
    {
        byte[] pe = new byte[0x400];
        pe[0] = (byte)'M';
        pe[1] = (byte)'Z';
        Put32(pe, PeConstants.DosLfanewOffset, 0x80);
        Put32(pe, 0x80, PeConstants.PeSignature);
        Put16(pe, 0x84, PeConstants.Machine_x64);
        Put16(pe, 0x86, 1);
        Put16(pe, 0x94, 0xF0);
        Put16(pe, 0x96, PeConstants.IMAGE_FILE_EXECUTABLE_IMAGE);
        int opt = 0x80 + PeConstants.OptHeaderFromSig;
        Put16(pe, opt, PeConstants.Pe32PlusMagic);
        BitConverter.GetBytes(0x140000000UL).CopyTo(pe, opt + PeConstants.Opt_ImageBase64);
        Put32(pe, opt + PeConstants.Opt_SectionAlignment, 0x1000);
        Put32(pe, opt + PeConstants.Opt_FileAlignment, 0x200);
        Put32(pe, opt + PeConstants.Opt_SizeOfImage, 0x3000);
        Put32(pe, opt + PeConstants.Opt_SizeOfHeaders, 0x200);
        Put32(pe, opt + PeConstants.Opt_NumberOfRvaAndSizes64, 16);
        Put32(pe, opt + PeConstants.DataDirBase64 + PeConstants.DirImport * 8, 0x2000);
        Put32(pe, opt + PeConstants.DataDirBase64 + PeConstants.DirImport * 8 + 4, 0x100);
        int section = opt + 0xF0;
        ".data"u8.CopyTo(pe.AsSpan(section));
        Put32(pe, section + PeConstants.Sec_VirtualSize, 0x200);
        Put32(pe, section + PeConstants.Sec_VirtualAddress, 0x2000);
        Put32(pe, section + PeConstants.Sec_SizeOfRawData, 0x200);
        Put32(pe, section + PeConstants.Sec_PointerToRawData, 0x200);
        Put32(pe, section + PeConstants.Sec_Characteristics,
            PeConstants.SCN_CNT_INITIALIZED_DATA | PeConstants.SCN_MEM_READ);
        return pe;
    }

    private static byte[] NrvLiteralStream(byte[] plain)
    {
        var compressed = new List<byte>(plain.Length + (plain.Length + 7) / 8);
        for (int offset = 0; offset < plain.Length; offset += 8)
        {
            compressed.Add(0xFF);
            int count = Math.Min(8, plain.Length - offset);
            for (int i = 0; i < count; i++) compressed.Add(plain[offset + i]);
        }
        // The decoder asks for the next control bit before noticing that the requested output is complete.
        compressed.Add(0xFF);
        return compressed.ToArray();
    }

    private static uint Adler32ForTest(byte[] bytes) => Adler32ForTest(bytes.AsSpan());

    private static uint Adler32ForTest(ReadOnlySpan<byte> bytes)
    {
        const uint mod = 65521;
        uint a = 1, sum = 0;
        foreach (byte value in bytes)
        {
            a = (a + value) % mod;
            sum = (sum + a) % mod;
        }
        return sum << 16 | a;
    }

    private static void Put16(byte[] bytes, int offset, ushort value) =>
        BitConverter.GetBytes(value).CopyTo(bytes, offset);

    private static void Put32(byte[] bytes, int offset, uint value) =>
        BitConverter.GetBytes(value).CopyTo(bytes, offset);

    private sealed class ImportedImage(RawImage inner, ImportEntry import) : IBinaryImage, IDisposable
    {
        private readonly IReadOnlyList<ImportEntry> _imports = [import];
        private readonly IReadOnlyDictionary<ulong, ImportEntry> _byIat =
            new Dictionary<ulong, ImportEntry> { [import.IatVa] = import };

        public void Dispose() { } // the test owns and disposes the wrapped RawImage
        public string FilePath => inner.FilePath;
        public BinaryFormat Format => inner.Format;
        public string FormatName => inner.FormatName;
        public int Bitness => inner.Bitness;
        public string ArchName => inner.ArchName;
        public Architecture Arch => inner.Arch;
        public ulong ImageBase => inner.ImageBase;
        public ulong EntryVa => inner.EntryVa;
        public bool IsDll => inner.IsDll;
        public IReadOnlyList<Section> Sections => inner.Sections;
        public IReadOnlyList<NamedSymbol> Symbols => inner.Symbols;
        public IReadOnlyList<ImportEntry> Imports => _imports;
        public Section? HeaderRegion => inner.HeaderRegion;
        public ResourceTree? Resources => inner.Resources;
        public IReadOnlyList<ulong> FunctionStarts => inner.FunctionStarts;
        public IReadOnlyDictionary<ulong, ImportEntry> ImportsByIatVa => _byIat;
        public ulong MinVa => inner.MinVa;
        public ulong MaxVa => inner.MaxVa;
        public int VaToOffset(ulong va) => inner.VaToOffset(va);
        public bool IsMappedVa(ulong va) => inner.IsMappedVa(va);
        public bool IsExecutableVa(ulong va) => inner.IsExecutableVa(va);
        public Section? SectionAt(ulong va) => inner.SectionAt(va);
        public byte ReadByteAtOffset(int offset) => inner.ReadByteAtOffset(offset);
        public int BackingLength => inner.BackingLength;
        public byte[] ReadBytesAtVa(ulong va, int count) => inner.ReadBytesAtVa(va, count);
        public int ReadVa(ulong va, Span<byte> dest) => inner.ReadVa(va, dest);
        public void Patch(int offset, ReadOnlySpan<byte> bytes) => inner.Patch(offset, bytes);
        public bool PatchVa(ulong va, ReadOnlySpan<byte> bytes) => inner.PatchVa(va, bytes);
        public void RevertPatch(int offset, int count) => inner.RevertPatch(offset, count);
        public bool IsPatchedAt(int offset) => inner.IsPatchedAt(offset);
        public bool IsDirty => inner.IsDirty;
        public int PatchCount => inner.PatchCount;
        public IReadOnlyDictionary<int, byte> Patches => inner.Patches;
        public bool Undo() => inner.Undo();
        public bool CanUndo => inner.CanUndo;
        public void SavePatchedAs(string path) => inner.SavePatchedAs(path);
    }
}

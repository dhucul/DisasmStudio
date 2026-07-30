using DisasmStudio.Core.Analysis;
using DisasmStudio.Core.Disasm;
using DisasmStudio.Core.Formats;
using DisasmStudio.Core.IL;
using DisasmStudio.Core.Unpacking.Lzma;
using Iced.Intel;
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

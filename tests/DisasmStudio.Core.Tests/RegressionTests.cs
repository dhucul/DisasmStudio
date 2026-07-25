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
}

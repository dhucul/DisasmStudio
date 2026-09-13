using System.Collections;
using System.Reflection;
using System.Runtime.InteropServices;
using DisasmStudio.Core.Analysis;
using DisasmStudio.Core.Disasm;
using DisasmStudio.Core.Export;
using DisasmStudio.Core.Formats;
using DisasmStudio.Core.IL;
using DisasmStudio.Debug;
using DisasmStudio.Debug.Unpacking;
using Iced.Intel;
using Xunit;
using Architecture = DisasmStudio.Core.Formats.Architecture;

namespace DisasmStudio.Core.Tests;

public sealed class LogicAuditTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "DisasmStudio.Tests", Guid.NewGuid().ToString("N"));
    public LogicAuditTests() => Directory.CreateDirectory(_dir);
    public void Dispose() { Directory.Delete(_dir, true); }
    private RawImage Image(byte[] bytes, int bits = 64, ulong address = 0x1000, Architecture arch = Architecture.X64)
    {
        string path = Path.Combine(_dir, Guid.NewGuid() + ".bin"); File.WriteAllBytes(path, bytes);
        return RawImage.Load(path, address, bits, address, arch, null);
    }
    private static RegExpr R(Register r) => new(X86Model.FromIced(r));
    private static LiftedFunction Function(params Stmt[] statements)
    {
        var block = new LiftedBlock { Start = 0x1000, Out = [] }; block.Stmts.AddRange(statements);
        var fn = new LiftedFunction { Va = 0x1000, Name = "test", Blocks = [block] }; fn.ByStart[block.Start] = block; return fn;
    }
    private static LiftedFunction Lift(IBinaryImage image)
    {
        var fn = new Function { Va = image.EntryVa, Name = "test" }; CfgBuilder.Build(image, fn);
        return new Lifter(image, new Dictionary<ulong, string>(), new Dictionary<ulong, ulong[]>()).Lift(fn);
    }

    [Fact]
    public void FlagsUseValuesAtCompareNotAtBranch()
    {
        using var image = Image([0xB8,0,0,0,0,0x83,0xF8,0,0xB8,1,0,0,0,0x74,1,0xC3,0xC3]);
        var low = Lift(image);
        Assert.True(Assert.Single(IlEmulator.Run(low, image).Branches).Taken);
        var mid = MediumLifter.Transform(low, image, ArchModel.For(image));
        Assert.True(Assert.Single(IlEmulator.Run(mid, image).Branches).Taken);
    }

    [Fact]
    public void SignExtendingMovePreservesNegativeByte()
    {
        using var image = Image([0xB8,0x80,0,0,0,0x0F,0xBE,0xC0,0x83,0xF8,0x80,0x74,1,0xC3,0xC3]);
        Assert.True(Assert.Single(IlEmulator.Run(Lift(image), image).Branches).Taken);
    }

    [Fact]
    public void PartialRegisterSubstitutionPreservesParent()
    {
        using var image = Image([0xC3]);
        var low = Function(new AssignStmt { Dest=R(Register.EAX), Src=new Const(0x123400,4) },
            new AssignStmt { Dest=R(Register.AL), Src=new Const(0x56,1) },
            new AssignStmt { Va=3, Dest=R(Register.EBX), Src=new BinExpr(BinOp.Add,R(Register.EAX),new Const(0,4),4) },
            new ReturnStmt { Value=R(Register.EBX) });
        var mid = MediumLifter.Transform(low,image,ArchModel.For(image));
        // The transformed return must still depend on the merged register, not on the last byte literal.
        Assert.IsNotType<Const>(Assert.IsType<ReturnStmt>(mid.Blocks[0].Stmts[^1]).Value);
        Assert.Equal(0x123456, IlEmulator.Run(low,image).Values[3].Value);
        var ret = Assert.IsType<ReturnStmt>(mid.Blocks[0].Stmts[^1]);
        mid.Blocks[0].Stmts.Insert(mid.Blocks[0].Stmts.Count-1,new AssignStmt { Va=4, Dest=R(Register.ECX), Src=new BinExpr(BinOp.Add,ret.Value!,new Const(0,4),4) });
        Assert.Equal(0x123456,IlEmulator.Run(mid,image).Values[4].Value);
    }

    [Fact]
    public void HighByteReadAndWriteUseBitOffsetEight()
    {
        using var image = Image([0xB8,0x34,0x12,0,0,0xB4,0x56,0x83,0xC0,0,0xC3]);
        Assert.Equal(0x5634, IlEmulator.Run(Lift(image),image).Values[0x1007].Value);
    }

    [Fact]
    public void SelfReferentialAssignmentIsNotSubstitutedAgain()
    {
        using var image = Image([0xC3]);
        var low = Function(new AssignStmt { Dest=R(Register.EAX), Src=new BinExpr(BinOp.Add,R(Register.EAX),new Const(1,4),4) },
            new ReturnStmt { Value=R(Register.EAX) });
        var mid = MediumLifter.Transform(low,image,ArchModel.For(image));
        Assert.Equal(R(Register.EAX),Assert.IsType<ReturnStmt>(mid.Blocks[0].Stmts[^1]).Value);
        Assert.Single(mid.Blocks[0].Stmts.OfType<AssignStmt>());
    }

    [Theory]
    [InlineData(0)] [InlineData(1)] [InlineData(2)]
    public void UnknownMemoryEffectsNeverReviveOriginalBytes(int effect)
    {
        using var image = Image(Enumerable.Repeat((byte)0x41,32).ToArray());
        Stmt unknown = effect switch {
            0 => new AssignStmt { Dest=new LoadExpr(new Const(0x1010,8),1), Src=R(Register.CL) },
            1 => new AssignStmt { Dest=new LoadExpr(R(Register.RCX),1), Src=new Const(1,1) },
            _ => new CallStmt { Call=new CallExpr(new Const(0x2000,8),[],null) }
        };
        var low = Function(unknown,new AssignStmt { Va=2, Dest=R(Register.EAX), Src=new LoadExpr(new Const(0x1010,8),1) },new ReturnStmt());
        Assert.False(IlEmulator.Run(low,image).Values.ContainsKey(2));
    }

    [Theory]
    [InlineData(1,8,0)] [InlineData(2,16,0)] [InlineData(4,32,1)] [InlineData(8,64,1)]
    public void ShiftCountsAndFoldingAgree(int width,int count,long expected)
    {
        using var image=Image([0xC3]);
        var low=Function(new AssignStmt { Va=1,Dest=R(Register.RAX),Src=new BinExpr(BinOp.Shl,new Const(1,width),new Const(count,4),width) },new ReturnStmt { Value=R(Register.RAX) });
        Assert.Equal(expected,IlEmulator.Run(low,image).Values[1].Value);
        var mid=MediumLifter.Transform(low,image,ArchModel.For(image));
        Assert.Equal(expected,Assert.IsType<Const>(Assert.IsType<ReturnStmt>(mid.Blocks[0].Stmts[^1]).Value).Value);
    }

    [Fact]
    public void ConstantAdditionWrapsToDestinationWidth()
    {
        using var image=Image([0xC3]);
        var low=Function(new AssignStmt { Dest=R(Register.EAX),Src=new BinExpr(BinOp.Add,new Const(0xFFFFFFFF,4),new Const(1,4),4) },new ReturnStmt { Value=R(Register.EAX) });
        var mid=MediumLifter.Transform(low,image,ArchModel.For(image));
        Assert.Equal(0,Assert.IsType<Const>(Assert.IsType<ReturnStmt>(mid.Blocks[0].Stmts[^1]).Value).Value);
    }

    [Fact]
    public void ZeroIsAValid8051Entry()
    {
        using var image=Image([0x74,1,0x22],16,0,Architecture.I8051);
        Assert.True(AnalysisEngine.Analyze(image).FunctionByVa.ContainsKey(0));
    }

    [Fact]
    public void InvalidatingAnalysisRebuildsPatchedCfg()
    {
        using var image=Image([0x75,1,0x90,0xC3]);
        var analysis=AnalysisEngine.Analyze(image);
        var fn=analysis.FunctionByVa[0x1000]; CfgBuilder.Build(image,fn);
        Assert.Equal(2,fn.Blocks[0].Out.Count);
        image.PatchVa(0x1000,[0xEB]); analysis.InvalidateCode(); CfgBuilder.Build(image,fn);
        Assert.Single(fn.Blocks[0].Out);
        Assert.Equal(EdgeKind.Jump,fn.Blocks[0].Out[0].Kind);
    }

    [Fact]
    public async Task ExhaustedUnpackerCompletesWithoutWaitingForAnotherStop()
    {
        var session=new UnpackSession("unused",new UnpackOptions(OepMethod.TailJumpScan,null,false,Path.Combine(_dir,"out.exe")));
        typeof(UnpackSession).GetMethod("OnStopped",BindingFlags.Instance|BindingFlags.NonPublic)!.Invoke(session,[new StopInfo(StopReason.EntryPoint,1,0,0)]);
        var completion=(TaskCompletionSource<UnpackResult>)typeof(UnpackSession).GetField("_tcs",BindingFlags.Instance|BindingFlags.NonPublic)!.GetValue(session)!;
        Assert.True(completion.Task.IsCompletedSuccessfully);
        Assert.False((await completion.Task).Ok);
    }

    [Fact]
    public void BulkBreakpointsPreserveExistingSoftwareAndTemporaryTraps()
    {
        if (!OperatingSystem.IsWindows()) return;
        using var page=new TestMemory(); var eng=page.Engine;
        Assert.True(eng.TrySetBreakpoint(page.Va+16));
        Assert.True(eng.SetTemporaryBreakpoint(page.Va+24));
        Assert.Single(eng.SetBreakpoints([page.Va+32]));
        Assert.Equal(0xCC,page.ByteAt(16)); Assert.Equal(0xCC,page.ByteAt(24)); Assert.Equal(0xCC,page.ByteAt(32));
    }

    [Fact]
    public void LivePatchPreservesTrapAndSurvivesRemoval()
    {
        if (!OperatingSystem.IsWindows()) return;
        using var page=new TestMemory(); var eng=page.Engine; ulong va=page.Va+16;
        Assert.True(eng.TrySetBreakpoint(va)); Assert.True(eng.WriteMemory(va,[0xC3]));
        Assert.Equal(0xCC,page.ByteAt(16)); Assert.Equal(0xC3,eng.ReadMemory(va,1)[0]);
        eng.RemoveBreakpoint(va); Assert.Equal(0xC3,page.ByteAt(16));
    }

    [Fact]
    public void ResumeClaimsStopOnceAndInspectionsDelayIt()
    {
        if (!OperatingSystem.IsWindows()) return;
        using var page=new TestMemory(); var eng=page.Engine;
        using (var inspection=eng.TryAcquireInspection()) { Assert.NotNull(inspection); Assert.False(eng.TryResume(ResumeMode.Go)); }
        Assert.True(eng.TryResume(ResumeMode.Go)); Assert.False(eng.TryResume(ResumeMode.StepInto));
        Assert.False(eng.IsStopped); Assert.False(eng.WriteMemory(page.Va,[0xC3])); Assert.Empty(eng.ReadMemory(page.Va,1));
        Assert.Equal(0x90,page.ByteAt(0));
    }

    [Theory]
    [InlineData(false)] [InlineData(true)]
    public void MemoryStepReprotectsEveryPageAndCompletesUserRearm(bool matchingWatch)
    {
        if (!OperatingSystem.IsWindows()) return;
        using var memory=new TestMemory(8192); var eng=memory.Engine;
        Assert.True(eng.TrySetBreakpoint(memory.Va+16));
        typeof(DebuggerEngine).GetMethod("DisarmAddr",BindingFlags.Instance|BindingFlags.NonPublic)!.Invoke(eng,[memory.Va+16]);
        Assert.True(eng.TrySetMemoryBreakpoint(memory.Va,8192,MemAccess.Write));
        Native.VirtualProtectEx(new IntPtr(-1),memory.Va,8192,Native.PAGE_EXECUTE_READWRITE,out _);
        var stepType=typeof(DebuggerEngine).GetNestedType("MemStepState",BindingFlags.NonPublic)!;
        var steps=(IDictionary)Field(eng,"_memStep");
        steps[(uint)1]=Activator.CreateInstance(stepType,BindingFlags.Instance|BindingFlags.Public|BindingFlags.NonPublic,null,
            [new HashSet<ulong>{memory.Va,memory.Va+4096},matchingWatch,memory.Va,memory.Va,1,Array.Empty<IntPtr>()],null)!;
        var userSteps=(IDictionary)Field(eng,"_stepping");
        userSteps[(uint)1]=Activator.CreateInstance(typeof(DebuggerEngine).GetNestedType("StepState",BindingFlags.NonPublic)!,memory.Va+16,true)!;
        StopInfo? stopped=null; eng.Stopped+=s=>stopped=s;
        var ev=new Native.DEBUG_EVENT { dwDebugEventCode=Native.EXCEPTION_DEBUG_EVENT,dwThreadId=1,
            Exception=new Native.EXCEPTION_DEBUG_INFO { ExceptionRecord=new Native.EXCEPTION_RECORD { ExceptionCode=Native.EXCEPTION_SINGLE_STEP } } };
        typeof(DebuggerEngine).GetMethod("HandleException",BindingFlags.Instance|BindingFlags.NonPublic)!.Invoke(eng,[ev,Native.DBG_CONTINUE]);
        Assert.Empty(steps); Assert.Empty(userSteps);
        Assert.Equal(matchingWatch?StopReason.MemoryBreakpoint:StopReason.Step,stopped!.Value.Reason);
        Assert.Equal(0xCC,memory.ByteAt(16));
        foreach(ulong va in new[]{memory.Va,memory.Va+4096}) {
            Native.VirtualQueryEx(new IntPtr(-1),va,out var mbi,(nuint)Marshal.SizeOf<Native.MEMORY_BASIC_INFORMATION>());
            Assert.NotEqual(Native.PAGE_EXECUTE_READWRITE,mbi.Protect);
        }
    }

    [Fact]
    public void WholeProgramExportsUseSuppliedLiveDecoder()
    {
        if (!OperatingSystem.IsWindows()) return;
        using var memory=new TestMemory(); using var image=Image([0x90,0xC3]);
        var eng=memory.Engine;
        typeof(DebuggerEngine).GetProperty(nameof(DebuggerEngine.ImageBase))!.SetValue(eng,memory.Va);
        eng.WriteMemory(memory.Va,[0x90,0xC3]);
        var result=LiveAnalysis.Build(eng,AnalysisEngine.Analyze(image)).Result;
        using var writer=new StringWriter();
        SourceExporter.WriteAsm(writer,result,decoder:new LiveDisassembler(eng));
        Assert.Contains("nop",writer.ToString()); Assert.Contains("ret",writer.ToString()); Assert.DoesNotContain("??",writer.ToString());
        writer.GetStringBuilder().Clear(); SourceExporter.WriteC(writer,result,decoder:new LiveDisassembler(eng));
        Assert.DoesNotContain("no code recovered",writer.ToString()); Assert.Contains("return",writer.ToString());
    }

    private static object Field(object target,string field)=>target.GetType().GetField(field,BindingFlags.Instance|BindingFlags.NonPublic)!.GetValue(target)!;
    private sealed class TestMemory : IDisposable
    {
        [DllImport("kernel32.dll")] private static extern IntPtr VirtualAlloc(IntPtr address,nuint size,uint type,uint protect);
        [DllImport("kernel32.dll")] private static extern bool VirtualFree(IntPtr address,nuint size,uint type);
        private readonly IntPtr _page;
        public ulong Va=>(ulong)_page.ToInt64();
        public DebuggerEngine Engine { get; }=new() { SmcTrackingEnabled=false };
        public TestMemory(int length=4096)
        {
            _page=VirtualAlloc(IntPtr.Zero,(nuint)length,0x3000,0x40); Assert.NotEqual(IntPtr.Zero,_page);
            Marshal.Copy(Enumerable.Repeat((byte)0x90,length).ToArray(),0,_page,length);
            foreach(var (name,value) in new (string,object)[]{("_proc",new IntPtr(-1)),("_eventHeld",true),("_isStopped",true)})
                typeof(DebuggerEngine).GetField(name,BindingFlags.Instance|BindingFlags.NonPublic)!.SetValue(Engine,value);
        }
        public byte ByteAt(int offset)=>Marshal.ReadByte(_page,offset);
        public void Dispose()=>VirtualFree(_page,0,0x8000);
    }
}

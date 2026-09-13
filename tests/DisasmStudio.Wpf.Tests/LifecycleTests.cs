using System.IO;
using System.Reflection;
using System.Windows;
using System.Windows.Threading;
using DisasmStudio.Core.Analysis;
using DisasmStudio.Core.Disasm;
using DisasmStudio.Core.Formats;
using DisasmStudio.Core.IL;
using DisasmStudio.ManagedDebug;
using DisasmStudio.Wpf;
using DisasmStudio.Wpf.Controls;
using DisasmStudio.Wpf.Services;
using Iced.Intel;
using Xunit;

[assembly: CollectionBehavior(DisableTestParallelization = true)]
namespace DisasmStudio.Wpf.Tests;

public sealed class LifecycleTests
{
    private static object? Field(object owner,string name) => owner.GetType().GetField(name,BindingFlags.Instance|BindingFlags.NonPublic)!.GetValue(owner);
    private static object? Call(object owner,string name,params object?[] args) => owner.GetType().GetMethod(name,BindingFlags.Instance|BindingFlags.NonPublic)!.Invoke(owner,args);

    [Fact]
    public Task CachedNavigationSupersedesPendingDecompilation() => Sta.Run(async () =>
    {
        using var file=new TestImage();
        var result=AnalysisEngine.Analyze(file.Image);
        var a=result.AddFunction(0x1000).Fn; var b=result.AddFunction(0x1002).Fn;
        CfgBuilder.Build(file.Image,a); CfgBuilder.Build(file.Image,b);
        var view=new DecompilerView();
        view.SetFunction(result,a); await view.PendingBuild;
        var decoder=new BlockingDecoder(file.Image,0x1002); view.LiveDecoder=decoder;
        view.SetFunction(result,b); var pending=view.PendingBuild;
        await decoder.Entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
        view.SetFunction(result,a);
        decoder.Release.Set(); await pending.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal(a.Va,Assert.IsType<DecompiledFunction>(Field(view,"_dc")).Va);
        view.Clear();
    });

    [Fact]
    public Task RetiredManagedSessionDropsAlreadyQueuedEvents() => Sta.Run(async () =>
    {
        using var session=new ManagedDebugSession(Dispatcher.CurrentDispatcher,"unused",false);
        int calls=0; session.Stopped+=_=>calls++; session.Exited+=_=>calls++;
        Call(session,"OnEvent",new MdbgEvent { Ev=Mdbg.Stopped });
        Call(session,"OnEvent",new MdbgEvent { Ev=Mdbg.Exited });
        session.Retire();
        await Dispatcher.Yield(DispatcherPriority.ContextIdle);
        Assert.Equal(0,calls); Assert.False(session.IsStopped);
    });

    [Fact]
    public Task FailedManagedResumeRestoresUiStop() => Sta.Run(async () =>
    {
        using var session=new ManagedDebugSession(Dispatcher.CurrentDispatcher,"unused",false);
        Call(session,"OnEvent",new MdbgEvent { Ev=Mdbg.Stopped });
        await Dispatcher.Yield(DispatcherPriority.ContextIdle);
        session.Go(); Assert.False(session.IsStopped);
        Call(session,"OnEvent",new MdbgEvent { Ev=Mdbg.ResumeFailed, Message="test failure" });
        await Dispatcher.Yield(DispatcherPriority.ContextIdle);
        Assert.True(session.IsStopped); Assert.NotNull(session.LastStop);
    });

    [Fact]
    public Task ImageReplacementWaitsForExportReader() => Sta.Run(async () =>
    {
        using var file=new TestImage(); using var replacement=new TestImage();
        var window=new MainWindow();
        try
        {
            await Analyze(window,file.Image);
            var entered=new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            var release=new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            string output=Path.Combine(Path.GetDirectoryName(file.Path)!,"export.txt");
            Action<TextWriter,IProgress<int>,CancellationToken> exportBody=(writer,progress,token)=>
            {
                entered.SetResult(); release.Task.GetAwaiter().GetResult();
                writer.Write(file.Image.ReadBytesAtVa(0x1000,1)[0]);
            };
            var export=(Task)Call(window,"RunExport",output,"test",exportBody)!;
            await entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
            await Analyze(window,replacement.Image);
            Assert.True(file.Image.BackingLength>0);
            release.SetResult(); await export;
            Assert.Equal("144",File.ReadAllText(output));
        }
        finally { window.Close(); }
    });

    [Fact]
    public Task PendingDocumentLoadBlocksDebugAndRejectsStaleCommit() => Sta.Run(async () =>
    {
        using var oldFile=new TestImage(); using var newFile=new TestImage(); var window=new MainWindow();
        try
        {
            var type=typeof(MainWindow).GetNestedType("DocumentLoad",BindingFlags.NonPublic)!;
            using var first=(IDisposable)Activator.CreateInstance(type,window)!;
            long generation=(long)type.GetProperty("Generation")!.GetValue(first)!;
            Assert.False((bool)Call(window,"CanStartDebug")!);
            using var second=(IDisposable)Activator.CreateInstance(type,window)!;
            await Analyze(window,newFile.Image);
            await (Task)Call(window,"StartAnalysis",oldFile.Image,null,0,true,null,null,generation)!;
            Assert.Same(newFile.Image,Field(window,"_image"));
        }
        finally { window.Close(); }
    });

    private static Task Analyze(MainWindow window,IBinaryImage image) => (Task)Call(window,"StartAnalysis",image,null,0,true,null,null,null)!;

    [Fact]
    public Task ByteEditRebuildsDerivedAnalysis() => Sta.Run(async () =>
    {
        using var file=new TestImage(); var window=new MainWindow();
        try
        {
            await Analyze(window,file.Image);
            var before=Assert.IsType<AnalysisResult>(Field(window,"_result"));
            file.Image.PatchVa(0x1000,[0xC3]);
            Call(window,"OnHexEdited",0x1000UL);
            Assert.True((bool)Field(window,"_analysisStale")!);
            var deadline=DateTime.UtcNow.AddSeconds(10);
            while((bool)Field(window,"_analysisStale")! && DateTime.UtcNow<deadline) await Task.Delay(20);
            Assert.False((bool)Field(window,"_analysisStale")!);
            Assert.NotSame(before,Field(window,"_result"));
            var after=Assert.IsType<AnalysisResult>(Field(window,"_result"));
            var fn=after.FunctionByVa[0x1000]; CfgBuilder.Build(file.Image,fn);
            Assert.Single(fn.Blocks[0].InstrVas);
        }
        finally
        {
            typeof(MainWindow).GetField("_sessionDirty",BindingFlags.Instance|BindingFlags.NonPublic)!.SetValue(window,false);
            window.Close();
        }
    });

    [Fact]
    public Task SessionStopCancelsExportBeforePublication() => Sta.Run(async () =>
    {
        using var file=new TestImage(); var window=new MainWindow();
        var session=new DebugSession(Dispatcher.CurrentDispatcher,null);
        typeof(DisasmStudio.Debug.DebuggerEngine).GetField("_eventHeld",BindingFlags.Instance|BindingFlags.NonPublic)!.SetValue(session.Engine,true);
        typeof(DisasmStudio.Debug.DebuggerEngine).GetField("_isStopped",BindingFlags.Instance|BindingFlags.NonPublic)!.SetValue(session.Engine,true);
        typeof(MainWindow).GetField("_dbg",BindingFlags.Instance|BindingFlags.NonPublic)!.SetValue(window,session);
        typeof(MainWindow).GetField("_dbgViewLive",BindingFlags.Instance|BindingFlags.NonPublic)!.SetValue(window,true);
        var release=new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        try
        {
            string output=Path.Combine(Path.GetDirectoryName(file.Path)!,"export.txt"); File.WriteAllText(output,"original");
            var entered=new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            Action<TextWriter,IProgress<int>,CancellationToken> body=(writer,progress,token)=>
            { entered.SetResult(); release.Task.GetAwaiter().GetResult(); writer.Write("incomplete"); };
            var export=(Task)Call(window,"RunExport",output,"test",body)!;
            await entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
            session.Stop(); release.SetResult(); await export;
            Assert.Equal("original",File.ReadAllText(output));
        }
        finally { release.TrySetResult(); window.Close(); }
    });

    private sealed class BlockingDecoder(IBinaryImage image,ulong blockAt) : IInstructionDecoder
    {
        public TaskCompletionSource Entered { get; }=new(TaskCreationOptions.RunContinuationsAsynchronously);
        public ManualResetEventSlim Release { get; }=new(false);
        private readonly Disassembler _decoder=new(image);
        public bool TryDecodeAt(ulong va,out Instruction instruction)
        {
            if(va==blockAt) { Entered.TrySetResult(); if(!Release.Wait(TimeSpan.FromSeconds(5))) throw new TimeoutException(); }
            return _decoder.TryDecodeAt(va,out instruction);
        }
    }
    private sealed class TestImage : IDisposable
    {
        public string Path { get; }
        public RawImage Image { get; }
        public TestImage()
        {
            string dir=System.IO.Path.Combine(System.IO.Path.GetTempPath(),"DisasmStudio.Tests",Guid.NewGuid().ToString("N")); Directory.CreateDirectory(dir);
            Path=System.IO.Path.Combine(dir,"test.bin"); File.WriteAllBytes(Path,[0x90,0xC3,0x90,0xC3]); Image=RawImage.Load(Path,0x1000,64);
        }
        public void Dispose() { Image.Dispose(); Directory.Delete(System.IO.Path.GetDirectoryName(Path)!,true); }
    }
    private static class Sta
    {
        private static readonly TaskCompletionSource<Dispatcher> Ready=new(TaskCreationOptions.RunContinuationsAsynchronously);
        static Sta()
        {
            var thread=new Thread(() =>
            {
                try { var app=new App { ShutdownMode=ShutdownMode.OnExplicitShutdown }; app.InitializeComponent(); Ready.SetResult(Dispatcher.CurrentDispatcher); Dispatcher.Run(); }
                catch(Exception ex) { Ready.TrySetException(ex); }
            }) { IsBackground=true };
            thread.SetApartmentState(ApartmentState.STA); thread.Start();
        }
        public static async Task Run(Func<Task> action)
        {
            var dispatcher=await Ready.Task.WaitAsync(TimeSpan.FromSeconds(10));
            var done=new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            _ = dispatcher.BeginInvoke(new Action(async () => { try { await action(); done.SetResult(); } catch(Exception ex) { done.SetException(ex); } }));
            await done.Task.WaitAsync(TimeSpan.FromSeconds(30));
        }
    }
}

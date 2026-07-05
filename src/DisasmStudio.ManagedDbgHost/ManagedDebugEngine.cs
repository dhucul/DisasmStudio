using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using ClrDebug;
using DisasmStudio.ManagedDebug;
using static ClrDebug.Extensions;

namespace DisasmStudio.ManagedDbgHost;

/// <summary>
/// The out-of-process managed (.NET Core/5+) debugger: drives ICorDebug (via ClrDebug + dbgshim) for one
/// target process and turns callbacks into <see cref="MdbgEvent"/>s. Launches suspended, registers for
/// runtime startup, attaches, arms source-level breakpoints (method token + IL offset) as modules load, and
/// on a stop reports the managed call stack (module + token + IL offset per frame) so the app can map each
/// frame back to a decompiled C# line. The host process bitness matches the target (chosen by the app).
/// </summary>
internal sealed class ManagedDebugEngine
{
    private readonly Action<MdbgEvent> _emit;
    private readonly DbgShim _dbgshim;

    private CorDebug? _cordebug;
    private CorDebugProcess? _process;
    private CorDebugManagedCallback? _cb;
    private Process? _osProc;
    private int _pid;

    private readonly object _gate = new();
    private CorDebugController? _stoppedController;   // non-null while the target is stopped
    private CorDebugThread? _stoppedThread;

    private readonly Dictionary<string, CorDebugModule> _modules = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<BpLoc> _pending = [];                          // breakpoints not yet armed (module not loaded)
    private readonly Dictionary<int, CorDebugFunctionBreakpoint> _armed = [];   // id -> live breakpoint

    public ManagedDebugEngine(Action<MdbgEvent> emit)
    {
        _emit = emit;
        _dbgshim = new DbgShim(NativeLibrary.Load(DbgShimResolver.Resolve()));
    }

    // ---- lifecycle ----

    public void Launch(string target, string? args, string? cwd, BpLoc[]? pending, bool framework)
    {
        if (pending is { Length: > 0 }) lock (_gate) _pending.AddRange(pending);

        string cmdline = string.IsNullOrEmpty(args) ? Quote(target) : $"{Quote(target)} {args}";
        string workdir = cwd ?? Path.GetDirectoryName(target) ?? Environment.CurrentDirectory;

        if (framework) { LaunchFramework(target, cmdline, workdir); return; }

        CreateProcessForLaunchResult proc;
        try
        {
            proc = _dbgshim.CreateProcessForLaunch(cmdline, bSuspendProcess: true, IntPtr.Zero, workdir);
        }
        catch (Exception ex) when (ex.HResult == unchecked((int)0x800702E4)   // ERROR_ELEVATION_REQUIRED
                                   || (ex.Message?.Contains("0x800702E4", StringComparison.OrdinalIgnoreCase) ?? false))
        {
            // The target's manifest asks for administrator rights, but this host (and DisasmStudio) is not
            // elevated. CreateProcess can't elevate — the app must relaunch elevated. Signal that, don't crash.
            _emit(new MdbgEvent { Ev = Mdbg.Error, Message = "ELEVATION_REQUIRED" });
            return;
        }
        _pid = proc.ProcessId;
        try { _osProc = Process.GetProcessById(_pid); } catch { /* best-effort for exit code */ }

        CorDebug? cordebug = null;
        HRESULT hr = HRESULT.E_FAIL;
        var ready = new AutoResetEvent(false);
        IntPtr token = IntPtr.Zero;
        try
        {
            try
            {
                // Register before resuming so the CLR can't finish starting before we're listening.
                token = _dbgshim.RegisterForRuntimeStartup(proc.ProcessId, (pCordb, parameter, callbackHr) =>
                {
                    cordebug = pCordb;
                    hr = callbackHr;
                    ready.Set();
                });
                _dbgshim.ResumeProcess(proc.ResumeHandle);
                if (!ready.WaitOne(TimeSpan.FromSeconds(30)))
                    throw new TimeoutException("the target's .NET (Core/5+) runtime did not start within 30s — is it a supported .NET Core app?");
            }
            finally
            {
                if (token != IntPtr.Zero) _dbgshim.UnregisterForRuntimeStartup(token);
                _dbgshim.CloseResumeHandle(proc.ResumeHandle);
            }
            if (cordebug is null || hr != HRESULT.S_OK)
                throw new InvalidOperationException($"runtime startup failed (hr={hr}). Is the target a .NET Core/5+ app matching this host's bitness?");
        }
        catch
        {
            KillTarget();   // we resumed the target but couldn't attach — don't leave it running orphaned
            throw;
        }

        _cordebug = cordebug;
        _cb = BuildCallback();
        cordebug.Initialize();
        cordebug.SetManagedHandler(_cb);
        _process = cordebug.DebugActiveProcess(proc.ProcessId, false);

        _emit(new MdbgEvent { Ev = Mdbg.Launched, Pid = _pid });
    }

    // CLSID_CLRDebuggingLegacy — ICLRRuntimeInfo.GetInterface(this, IID_ICorDebug) yields the desktop CLR's ICorDebug.
    private static readonly Guid CLSID_CLRDebuggingLegacy = new("DF8395B5-A4BA-450B-A77C-A9A47762C520");

    /// <summary>Launch a .NET Framework (desktop CLR) target. dbgshim/CoreCLR can't debug it, so obtain ICorDebug
    /// from the OS desktop runtime via ICLRMetaHost, then launch + attach in one step with ICorDebug.CreateProcess
    /// (the desktop CLR does not use dbgshim's runtime-startup notification). Everything after this — module loads,
    /// breakpoints, stepping, stacks, locals — is the same ICorDebug machinery as the Core path.</summary>
    private void LaunchFramework(string target, string cmdline, string workdir)
    {
        CorDebug cordebug;
        try
        {
            var metahost = CLRCreateInstance().CLRMetaHost;
            var runtimeInfo = new CLRRuntimeInfo((ICLRRuntimeInfo)metahost.GetRuntime("v4.0.30319", typeof(ICLRRuntimeInfo).GUID));
            cordebug = new CorDebug((ICorDebug)runtimeInfo.GetInterface(CLSID_CLRDebuggingLegacy, typeof(ICorDebug).GUID));
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException("could not initialize the .NET Framework debugger (desktop CLR v4.0.30319): " + ex.Message);
        }

        _cordebug = cordebug;
        _cb = BuildCallback();
        cordebug.Initialize();
        cordebug.SetManagedHandler(_cb);

        var si = new STARTUPINFOW { cb = Marshal.SizeOf<STARTUPINFOW>() };
        PROCESS_INFORMATION pi = default;
        try
        {
            _process = cordebug.CreateProcess(
                lpApplicationName: target,
                lpCommandLine: cmdline,
                lpProcessAttributes: default,
                lpThreadAttributes: default,
                bInheritHandles: false,
                dwCreationFlags: default,        // inherit the host's console (or lack of one) — matches the Core path
                lpEnvironment: IntPtr.Zero,
                lpCurrentDirectory: workdir,
                lpStartupInfo: si,
                lpProcessInformation: ref pi,
                debuggingFlags: CorDebugCreateProcessFlags.DEBUG_NO_SPECIAL_OPTIONS);
        }
        catch (Exception ex) when (ex.HResult == unchecked((int)0x800702E4)   // ERROR_ELEVATION_REQUIRED
                                   || (ex.Message?.Contains("0x800702E4", StringComparison.OrdinalIgnoreCase) ?? false))
        {
            _emit(new MdbgEvent { Ev = Mdbg.Error, Message = "ELEVATION_REQUIRED" });
            return;
        }

        _pid = _process.Id;
        try { _osProc = Process.GetProcessById(_pid); } catch { /* best-effort for exit code */ }
        _emit(new MdbgEvent { Ev = Mdbg.Launched, Pid = _pid });
    }

    private CorDebugManagedCallback BuildCallback()
    {
        var cb = new CorDebugManagedCallback();
        cb.OnLoadModule += (_, e) => Guard(() => OnModule(e));
        cb.OnBreakpoint += (_, e) => Guard(() => OnStop(e, e.Thread, Mdbg.ReasonBreakpoint));
        cb.OnStepComplete += (_, e) => Guard(() => OnStop(e, e.Thread, Mdbg.ReasonStep));
        cb.OnException2 += (_, e) => Guard(() => OnException2(e));
        cb.OnExitProcess += (_, _) => Guard(OnExit);
        // Single continue point: resume unless a specific handler asked to stay stopped (Continue=false).
        cb.OnAnyEvent += (_, e) =>
        {
            if (e.Kind == CorDebugManagedCallbackKind.ExitProcess) return;   // process gone — never continue
            if (e.Continue) SafeContinue(e.Controller);
        };
        return cb;
    }

    private void OnModule(LoadModuleCorDebugManagedCallbackEventArgs e)
    {
        var module = e.Module;
        string full = module.Name;
        string name = Path.GetFileName(full);

        // Publish the module AND take-and-clear its pending breakpoints in ONE critical section, so a concurrent
        // SetBreakpoint (pipe thread) can't slip its "module absent → add to pending" between the two and be lost.
        List<BpLoc> toArm;
        lock (_gate)
        {
            _modules[name] = module;
            bool Matches(BpLoc b) => string.Equals(b.Module, name, StringComparison.OrdinalIgnoreCase);
            toArm = _pending.Where(Matches).ToList();
            _pending.RemoveAll(Matches);
        }
        // Mark the target's own modules as "my code" and the framework as not — so JMC stepping steps into the
        // user's methods and steps over Console.WriteLine etc.
        try { module.SetJMCStatus(IsUserModule(full, name), 0, []); } catch { }
        _emit(new MdbgEvent { Ev = Mdbg.ModuleLoaded, Module = name, Path = full });
        foreach (var bp in toArm) TryArm(module, bp);
    }

    private bool TryArm(CorDebugModule module, BpLoc bp)
    {
        try
        {
            var func = module.GetFunctionFromToken(new mdMethodDef(bp.Token));
            var code = func.ILCode;
            var fbp = code.CreateBreakpoint(bp.IlOffset);
            lock (_gate)
            {
                if (_armed.Remove(bp.Id, out var old)) { try { old.Raw.Activate(false); } catch { } }   // id reused → drop the old bp
                _armed[bp.Id] = fbp;
            }
            return true;
        }
        catch (Exception ex)
        {
            _emit(new MdbgEvent { Ev = Mdbg.Error, Message = $"failed to arm breakpoint {bp.Module}!0x{bp.Token:X8}+{bp.IlOffset}: {ex.Message}" });
            return false;
        }
    }

    // Shared stop handler: capture the stopped controller/thread, ask to stay stopped, and report the stack.
    private void OnStop(CorDebugManagedCallbackEventArgs baseArgs, CorDebugThread thread, string reason)
    {
        lock (_gate) { _stoppedController = baseArgs.Controller; _stoppedThread = thread; }
        baseArgs.Continue = false;                       // stay stopped; OnAnyEvent won't resume
        _emit(BuildStopped(thread, reason));
    }

    private void OnException2(Exception2CorDebugManagedCallbackEventArgs e)
    {
        // Only surface an UNHANDLED (fatal) managed exception as a stop; first-chance/handled ones keep running.
        if (e.EventType != CorDebugExceptionCallbackType.DEBUG_EXCEPTION_UNHANDLED) return;
        lock (_gate) { _stoppedController = e.Controller; _stoppedThread = e.Thread; }
        e.Continue = false;
        _emit(BuildStopped(e.Thread, Mdbg.ReasonException));
    }

    private void OnExit()
    {
        int code = 0;
        try { if (_osProc is { HasExited: true }) code = _osProc.ExitCode; } catch { }   // best-effort, never block
        _emit(new MdbgEvent { Ev = Mdbg.Exited, Code = code });
    }

    // ---- resume / step / control (called from the pipe-command thread) ----

    public void Go()
    {
        CorDebugController? c;
        lock (_gate) { c = _stoppedController; _stoppedController = null; _stoppedThread = null; }
        if (c is not null) SafeContinue(c);
    }

    public void Step(string kind, int[]? range)
    {
        CorDebugThread? t; CorDebugController? c;
        lock (_gate) { t = _stoppedThread; c = _stoppedController; _stoppedController = null; _stoppedThread = null; }
        if (t is null || c is null) return;
        try
        {
            var stepper = t.CreateStepper();
            try { stepper.SetJMC(true); } catch { }                                       // step into MY code, over the framework
            try { stepper.SetUnmappedStopMask(CorDebugUnmappedStop.STOP_NONE); } catch { } // never stop in unmapped/compiler IL
            if (kind == Mdbg.StepOut)
            {
                stepper.StepOut();
            }
            else if (range is { Length: 2 } && range[1] > range[0])
            {
                stepper.SetRangeIL(true);
                var ranges = new[] { new COR_DEBUG_STEP_RANGE { startOffset = range[0], endOffset = range[1] } };
                stepper.StepRange(kind == Mdbg.StepInto, ranges, 1);   // step over the whole C# statement (its IL range)
            }
            else
            {
                stepper.Step(kind == Mdbg.StepInto);                   // no range → single-IL step fallback
            }
        }
        catch (Exception ex) { _emit(new MdbgEvent { Ev = Mdbg.Error, Message = "step failed: " + ex.Message }); }
        SafeContinue(c);
    }

    private static readonly string[] FrameworkNamePrefixes =
        ["System.", "Microsoft.", "netstandard", "mscorlib", "WindowsBase", "PresentationCore", "PresentationFramework"];

    private static bool IsUserModule(string path, string name)
    {
        string p = path.Replace('/', '\\');
        if (p.IndexOf("\\dotnet\\", StringComparison.OrdinalIgnoreCase) >= 0
            || p.IndexOf("Microsoft.NETCore.App", StringComparison.OrdinalIgnoreCase) >= 0
            || p.IndexOf("\\shared\\", StringComparison.OrdinalIgnoreCase) >= 0)
            return false;   // framework-dependent: BCL sits under the shared runtime
        // Self-contained/single-file apps ship the BCL in the app folder, so also exclude by assembly name.
        foreach (var prefix in FrameworkNamePrefixes)
            if (name.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)) return false;
        return true;
    }

    public void Pause()
    {
        var p = _process;
        if (p is null) return;
        lock (_gate) { if (_stoppedController is not null) return; }   // already stopped → don't double the stop count
        try
        {
            p.Stop(0);   // synchronous async-break (adds one to the stop count; balanced by the next Go/Continue)
            CorDebugThread? thread = null;
            try { thread = p.Threads.FirstOrDefault(); } catch { }
            bool own;
            lock (_gate)
            {
                // A real callback stop may have landed in the same instant — if so it owns the stop; otherwise, if
                // there's no thread to present, don't leave the target frozen. Either way, undo our extra Stop.
                if (_stoppedController is not null || thread is null) own = false;
                else { _stoppedController = p; _stoppedThread = thread; own = true; }
            }
            if (own) _emit(BuildStopped(thread!, Mdbg.ReasonPause));
            else { try { p.Continue(false); } catch { } }
        }
        catch (Exception ex) { _emit(new MdbgEvent { Ev = Mdbg.Error, Message = "pause failed: " + ex.Message }); }
    }

    public void SetBreakpoint(BpLoc bp)
    {
        CorDebugModule? module;
        lock (_gate)
        {
            // Check-and-add atomically vs OnModule's publish-and-take, so this bp can't be lost to a race with a
            // module load happening on the callback thread at the same instant.
            if (!_modules.TryGetValue(bp.Module, out module)) { _pending.Add(bp); return; }
        }
        TryArm(module, bp);   // module already loaded — arm now (outside the lock; does COM calls)
    }

    public void RemoveBreakpoint(int id)
    {
        CorDebugFunctionBreakpoint? fbp;
        lock (_gate)
        {
            _pending.RemoveAll(b => b.Id == id);
            _armed.Remove(id, out fbp);
        }
        try { fbp?.Raw.Activate(false); } catch { }
    }

    public void Stop()
    {
        try { _process?.Stop(0); } catch { }
        try { _process?.Terminate(0); } catch { }
        if (_process is null) KillTarget();   // launch failed before attach → kill the orphaned target
    }

    public void Detach()
    {
        try { _process?.Stop(0); } catch { }
        try { _process?.Detach(); } catch { }
        if (_process is null) KillTarget();
    }

    /// <summary>Terminate the target via the OS handle — the fallback when we resumed it but never attached
    /// (so <see cref="_process"/> is null and Terminate/Detach are no-ops).</summary>
    private void KillTarget()
    {
        try { if (_osProc is { HasExited: false }) _osProc.Kill(); } catch { }
    }

    // ---- stack / locals snapshot ----

    private MdbgEvent BuildStopped(CorDebugThread thread, string reason)
    {
        var frames = new List<MdbgFrame>();
        try
        {
            foreach (var chain in thread.Chains)
            {
                foreach (var f in chain.Frames)
                {
                    int tok = SafeToken(f);
                    if (tok == 0) continue;                       // internal/native frame with no method token
                    string mod = SafeModuleName(f);
                    int il = SafeIlOffset(f);
                    frames.Add(new MdbgFrame(mod, tok, il, ""));  // method label resolved app-side from (mod,tok)
                    if (frames.Count >= 64) break;
                }
                if (frames.Count >= 64) break;
            }
        }
        catch { /* best-effort stack */ }

        MdbgLocal[]? locals = null;
        try { locals = ReadLocals(thread); } catch { }

        return new MdbgEvent
        {
            Ev = Mdbg.Stopped,
            Reason = reason,
            Thread = thread.Id,
            Frames = frames.ToArray(),
            Locals = locals,
        };
    }

    private static int SafeToken(CorDebugFrame f)
    {
        try { return (int)f.FunctionToken.Value; } catch { return 0; }
    }

    private static string SafeModuleName(CorDebugFrame f)
    {
        try { return Path.GetFileName(f.Function.Module.Name); } catch { return ""; }
    }

    private static int SafeIlOffset(CorDebugFrame f)
    {
        try
        {
            var il = new CorDebugILFrame((ICorDebugILFrame)f.Raw);
            return (int)il.IP.pnOffset;
        }
        catch { return -1; }
    }

    private static MdbgLocal[]? ReadLocals(CorDebugThread thread)
    {
        CorDebugILFrame il;
        try { il = new CorDebugILFrame((ICorDebugILFrame)thread.ActiveFrame.Raw); }
        catch { return null; }

        var list = new List<MdbgLocal>();
        Add(list, il.Arguments, "arg", isArg: true);
        Add(list, il.LocalVariables, "local", isArg: false);
        return list.ToArray();

        static void Add(List<MdbgLocal> list, CorDebugValue[]? values, string prefix, bool isArg)
        {
            if (values is null) return;
            for (int i = 0; i < values.Length; i++)
            {
                string type, val;
                try { type = values[i].Type.ToString(); } catch { type = "?"; }
                try { val = FormatValue(values[i]); } catch { val = "<?>"; }
                list.Add(new MdbgLocal($"{prefix}_{i}", val, type, isArg));
            }
        }
    }

    /// <summary>Best-effort display string for a managed value: null / string / array-summary / primitive /
    /// object placeholder. Falls back to the element-type name on any failure.</summary>
    private static string FormatValue(CorDebugValue v)
    {
        try
        {
            return v switch
            {
                CorDebugReferenceValue r => r.IsNull ? "null" : FormatValue(r.Dereference()),
                CorDebugStringValue s => "\"" + Truncate(s.GetString(Math.Min(Math.Max(s.Length, 0), 256))) + "\"",
                CorDebugArrayValue a => $"{a.ElementType}[{a.Count}]",
                CorDebugBoxValue b => "{" + (b.Object.IsValueClass ? "struct" : "object") + "}",
                CorDebugObjectValue o => "{" + (o.IsValueClass ? "struct" : "object") + "}",
                CorDebugGenericValue g => ReadPrimitive(g, v.Type, v.Size),
                _ => v.Type.ToString(),
            };
        }
        catch { return "<?>"; }
    }

    private static string ReadPrimitive(CorDebugGenericValue g, CorElementType et, int size)
    {
        IntPtr buf = Marshal.AllocHGlobal(Math.Max(size, 8));
        try
        {
            g.GetValue(buf);
            return et switch
            {
                CorElementType.Boolean => (Marshal.ReadByte(buf) != 0).ToString(),
                CorElementType.Char => ((char)(ushort)Marshal.ReadInt16(buf)).ToString(),
                CorElementType.I1 => ((sbyte)Marshal.ReadByte(buf)).ToString(),
                CorElementType.U1 => Marshal.ReadByte(buf).ToString(),
                CorElementType.I2 => Marshal.ReadInt16(buf).ToString(),
                CorElementType.U2 => ((ushort)Marshal.ReadInt16(buf)).ToString(),
                CorElementType.I4 => Marshal.ReadInt32(buf).ToString(),
                CorElementType.U4 => ((uint)Marshal.ReadInt32(buf)).ToString(),
                CorElementType.I8 => Marshal.ReadInt64(buf).ToString(),
                CorElementType.U8 => ((ulong)Marshal.ReadInt64(buf)).ToString(),
                CorElementType.R4 => BitConverter.Int32BitsToSingle(Marshal.ReadInt32(buf)).ToString(),
                CorElementType.R8 => BitConverter.Int64BitsToDouble(Marshal.ReadInt64(buf)).ToString(),
                CorElementType.I or CorElementType.U => Marshal.ReadIntPtr(buf).ToString(),
                _ => et.ToString(),
            };
        }
        finally { Marshal.FreeHGlobal(buf); }
    }

    private static string Truncate(string s) => s.Length <= 200 ? s : s[..200] + "…";

    // ---- helpers ----

    private void SafeContinue(CorDebugController c)
    {
        try { c.Continue(false); }
        catch (Exception ex) { _emit(new MdbgEvent { Ev = Mdbg.Error, Message = "continue failed: " + ex.Message }); }
    }

    private void Guard(Action a)
    {
        try { a(); }
        catch (Exception ex) { _emit(new MdbgEvent { Ev = Mdbg.Error, Message = ex.GetType().Name + ": " + ex.Message }); }
    }

    private static string Quote(string s) => s.Contains(' ') && !s.StartsWith('"') ? $"\"{s}\"" : s;
}

using System.Text;

namespace DisasmStudio.Debug;

/// <summary>One captured event: a function call (with its arguments) or its return (with the value).</summary>
public sealed class CaptureRecord
{
    public bool IsReturn;
    public ulong CalleeVa;
    public string CalleeName = "";
    public ulong CallerVa;            // return address — the instruction after the call
    public string CallerName = "";
    public ulong CallerFuncVa;        // entry of the function the call was made from
    public uint ThreadId;
    public int Depth;
    public List<(string Name, ulong Value, string Deref)> Args = [];
    public ulong RetValue;
    public string RetDeref = "";
}

/// <summary>
/// Captures function inputs/outputs during a live session — a C# port of FunCap. It breakpoints function
/// entries; on each hit it records the argument registers/stack (dereferenced x64dbg-style), schedules a
/// breakpoint at the return address to capture the return value, records a caller→callee edge, then
/// auto-resumes so the program keeps running. <see cref="Handle"/> runs entirely on the engine thread.
/// </summary>
public sealed class FunctionCapture
{
    private readonly DebuggerEngine _eng;
    private readonly DereferenceResolver _deref;
    private readonly Dictionary<ulong, string> _names;     // entry VA -> function name
    private readonly ulong[] _sorted;                      // entry VAs sorted, for caller lookup
    private readonly object _lock = new();
    private readonly HashSet<ulong> _entries = [];          // function-entry breakpoints we set
    private readonly HashSet<ulong> _retBps = [];           // return-address breakpoints we added
    private readonly Dictionary<ulong, Stack<CaptureRecord>> _pending = [];   // retAddr -> calls awaiting return
    private readonly List<CaptureRecord> _records = [];     // all records (guarded by _lock)
    private readonly Dictionary<ulong, HashSet<ulong>> _edges = [];  // caller-func VA -> set of callee-func VAs
    private int _edgeCount;                                 // distinct caller->callee edges (cheap change check)
    private readonly bool _once;                            // capture each function once, then drop its entry bp
    private readonly bool _argsOnly;                        // skip return capture (no return breakpoints) for speed
    private readonly bool _annotate;                        // dereference values (slower) vs raw hex only (faster)
    private readonly object _logLock = new();               // serialize log writes (engine) vs flush (UI)
    private StreamWriter? _log;

    public bool Active { get; private set; }
    public bool Draining { get; private set; }      // stop requested; waiting for a frozen stop to remove bps
    public bool ResumeAfter { get; private set; }   // resume the debuggee after the teardown

    /// <summary>Raised (engine thread) after each captured record so the UI can refresh on its own cadence.</summary>
    public event Action? Captured;

    public FunctionCapture(DebuggerEngine eng, DereferenceResolver deref, IEnumerable<(ulong Va, string Name)> funcs, bool captureOnce, bool argsOnly, bool annotate)
    {
        _eng = eng;
        _deref = deref;
        _once = captureOnce;
        _argsOnly = argsOnly;
        _annotate = annotate;
        _names = new Dictionary<ulong, string>();
        foreach (var (va, name) in funcs) _names[va] = name;
        _sorted = _names.Keys.ToArray();
        Array.Sort(_sorted);
    }

    // Dereference a value (x64dbg-style annotation), or "" when annotation is off — the per-argument
    // memory reads + symbol/string lookups here are the dominant per-capture cost.
    private string Annotate(ulong v) => _annotate ? _deref.Describe(v) : "";

    public IReadOnlyList<CaptureRecord> Snapshot() { lock (_lock) return _records.ToList(); }

    /// <summary>Copy only the records added since <paramref name="from"/> (the UI appends incrementally).</summary>
    public IReadOnlyList<CaptureRecord> SnapshotFrom(int from)
    {
        lock (_lock) return from < _records.Count ? _records.GetRange(from, _records.Count - from) : [];
    }

    public Dictionary<ulong, HashSet<ulong>> EdgesSnapshot()
    {
        lock (_lock) return _edges.ToDictionary(k => k.Key, v => new HashSet<ulong>(v.Value));
    }

    /// <summary>Number of distinct caller→callee edges — a cheap value to detect call-graph changes.</summary>
    public int EdgeCount { get { lock (_lock) return _edgeCount; } }

    public string NameOf(ulong va) => _names.TryGetValue(va, out var n) && !string.IsNullOrEmpty(n) ? n : $"sub_{va:X}";

    public void SetLogFile(string path)
    {
        // Buffered (no per-line flush) for speed; flushed on StopCapture. 64 KiB buffer.
        try { _log = new StreamWriter(path, append: false, System.Text.Encoding.UTF8, 1 << 16) { AutoFlush = false }; }
        catch { _log = null; }
    }

    /// <summary>Capture every known function.</summary>
    public void StartAll()
    {
        var toArm = new List<ulong>(_names.Count);
        lock (_lock) foreach (var va in _names.Keys) if (_entries.Add(va)) toArm.Add(va);
        try { _eng.SetBreakpoints(toArm); } catch { }   // page-batched arming (fast for thousands of bps)
        _eng.PassFirstChanceExceptions = true;          // don't stop on the program's own exceptions
        Active = true;
    }

    /// <summary>Capture a single function.</summary>
    public void StartFunction(ulong va)
    {
        lock (_lock)
        {
            if (_entries.Add(va)) { try { _eng.SetBreakpoint(va); } catch { } }
            Active = true;
        }
        _eng.PassFirstChanceExceptions = true;
    }

    /// <summary>Mark capture for teardown on the upcoming Pause stop, when the debuggee is frozen and
    /// removing the breakpoints is safe (writing breakpoint bytes into a running process is what
    /// corrupts/crashes it). Capture stays active through the brief drain window so its own breakpoints are
    /// still consumed (and don't surface as stray stops) until the Pause arrives.</summary>
    public void BeginDraining(bool resumeAfter) { lock (_lock) { Draining = true; ResumeAfter = resumeAfter; } }

    /// <summary>Remove all capture breakpoints and close the log. Must be called while the debuggee is
    /// frozen (or already exited) — never while it is running.</summary>
    public void StopCapture()
    {
        lock (_lock)
        {
            Active = false; Draining = false;
            foreach (var va in _entries) { try { _eng.RemoveBreakpoint(va); } catch { } }
            foreach (var va in _retBps) { try { _eng.RemoveBreakpoint(va); } catch { } }
            _entries.Clear(); _retBps.Clear(); _pending.Clear();
        }
        _eng.PassFirstChanceExceptions = false;   // restore normal stop-on-exception behavior
        lock (_logLock) { try { _log?.Flush(); _log?.Dispose(); } catch { } _log = null; }
    }

    /// <summary>
    /// Engine-thread stop handler. Returns true if this was one of our capture breakpoints (in which case
    /// we captured it and auto-resumed); false to let the normal interactive stop handling proceed.
    /// </summary>
    public bool Handle(StopInfo s)
    {
        if (!Active || s.Reason != StopReason.Breakpoint) return false;
        ulong ea = s.Address;
        bool isEntry, isRet, ours;
        lock (_lock) { isEntry = _entries.Contains(ea); isRet = _pending.ContainsKey(ea); ours = isEntry || _retBps.Contains(ea); }
        if (!isEntry && !isRet) return false;

        var regs = _eng.GetRegisters();
        if (regs is null) return false;

        if (isRet) HandleReturn(ea, regs);   // a stop can be both (recursion / tail) — return first
        if (isEntry) HandleEntry(ea, regs);

        // If a user breakpoint also sits here, capture but let the stop surface (don't auto-resume).
        if (!ours) return false;
        _eng.Go();   // queued; the loop consumes it right after this handler returns
        return true;
    }

    private void HandleEntry(ulong ea, RegisterSet regs)
    {
        ulong retAddr = ReadPtr(regs.Sp);
        ulong callerFunc = FuncContaining(retAddr);
        // Only capture a return when [rsp] looks like a real return address (executable). When a function is
        // reached by a jump/tail-call rather than a call, [rsp] is unrelated data, and writing a breakpoint
        // there would corrupt the debuggee.
        bool captureReturn = !_argsOnly && _eng.IsExecutable(retAddr);
        var rec = new CaptureRecord
        {
            CalleeVa = ea,
            CalleeName = NameOf(ea),
            CallerVa = retAddr,
            CallerFuncVa = callerFunc,
            CallerName = callerFunc != 0 ? NameOf(callerFunc) : $"0x{retAddr:X}",
            ThreadId = _eng.CurrentThreadId,
            Args = CaptureArgs(regs),
        };

        lock (_lock)
        {
            rec.Depth = _pending.Values.Sum(st => st.Count);
            if (captureReturn)
            {
                if (!_pending.TryGetValue(retAddr, out var stack)) { stack = new Stack<CaptureRecord>(); _pending[retAddr] = stack; }
                stack.Push(rec);
                // Own the return breakpoint only if we set it; never touch a pre-existing (user/entry) one.
                if (!_eng.HasBreakpoint(retAddr)) { try { _eng.SetBreakpoint(retAddr); _retBps.Add(retAddr); } catch { } }
            }
            if (callerFunc != 0)
            {
                if (!_edges.TryGetValue(callerFunc, out var set)) { set = []; _edges[callerFunc] = set; }
                if (set.Add(ea)) _edgeCount++;
            }
            // Capture-once: drop this function's entry breakpoint now (we are frozen, so removal is safe).
            // Hot functions then run at full speed, and this resume needs no single-step re-arm.
            if (_once && _entries.Remove(ea)) { try { _eng.RemoveBreakpoint(ea); } catch { } }
            _records.Add(rec);
        }
        WriteLog(rec);
        Captured?.Invoke();
    }

    private void HandleReturn(ulong ea, RegisterSet regs)
    {
        CaptureRecord? call;
        lock (_lock)
        {
            if (!_pending.TryGetValue(ea, out var stack) || stack.Count == 0) return;
            call = stack.Pop();
            if (stack.Count == 0)
            {
                _pending.Remove(ea);
                if (_retBps.Remove(ea) && !_entries.Contains(ea)) { try { _eng.RemoveBreakpoint(ea); } catch { } }
            }
        }

        ulong rv = regs[_eng.Is32 ? "eax" : "rax"];
        var ret = new CaptureRecord
        {
            IsReturn = true,
            CalleeVa = call.CalleeVa,
            CalleeName = call.CalleeName,
            CallerVa = call.CallerVa,
            CallerFuncVa = call.CallerFuncVa,
            CallerName = call.CallerName,
            ThreadId = _eng.CurrentThreadId,
            Depth = call.Depth,
            RetValue = rv,
            RetDeref = Annotate(rv),
            Args = call.Args,
        };
        lock (_lock) _records.Add(ret);
        WriteLog(ret);
        Captured?.Invoke();
    }

    // Win64: rcx, rdx, r8, r9 then [rsp+0x28], [rsp+0x30]. x86 (cdecl/stdcall): [esp+4], [esp+8], …
    private List<(string Name, ulong Value, string Deref)> CaptureArgs(RegisterSet regs)
    {
        var list = new List<(string, ulong, string)>();
        if (_eng.Is32)
        {
            for (int i = 0; i < 6; i++) { ulong v = ReadPtr(regs.Sp + (ulong)(4 * (i + 1))); list.Add(($"arg{i}", v, Annotate(v))); }
        }
        else
        {
            foreach (var r in new[] { "rcx", "rdx", "r8", "r9" }) { ulong v = regs[r]; list.Add((r, v, Annotate(v))); }
            for (int i = 0; i < 2; i++) { ulong v = ReadPtr(regs.Sp + 0x28 + (ulong)(8 * i)); list.Add(($"arg{4 + i}", v, Annotate(v))); }
        }
        return list;
    }

    // nearest function entry at or below addr (binary search over the sorted entry VAs)
    private ulong FuncContaining(ulong addr)
    {
        int lo = 0, hi = _sorted.Length - 1, best = -1;
        while (lo <= hi)
        {
            int mid = (lo + hi) >> 1;
            if (_sorted[mid] <= addr) { best = mid; lo = mid + 1; } else hi = mid - 1;
        }
        return best >= 0 ? _sorted[best] : 0;
    }

    private ulong ReadPtr(ulong addr)
    {
        int n = _eng.Is32 ? 4 : 8;
        var b = _eng.ReadMemory(addr, n);
        if (b.Length < n) return 0;
        return _eng.Is32 ? BitConverter.ToUInt32(b) : BitConverter.ToUInt64(b);
    }

    private void WriteLog(CaptureRecord r)
    {
        if (_log is null) return;
        lock (_logLock) { try { _log?.WriteLine(Format(r, _eng.Is32)); } catch { } }
    }

    /// <summary>Flush the buffered log (called periodically so abnormal termination loses little).</summary>
    public void FlushLog() { lock (_logLock) { try { _log?.Flush(); } catch { } } }

    /// <summary>One-line (multi-line for calls) textual form, used for the log file and the panel.</summary>
    public static string Format(CaptureRecord r, bool is32)
    {
        string Hex(ulong v) => is32 ? $"0x{(uint)v:X8}" : $"0x{v:X16}";
        if (r.IsReturn)
            return $"RET   {r.CalleeName} = {Hex(r.RetValue)}{(string.IsNullOrEmpty(r.RetDeref) ? "" : "  " + r.RetDeref)}";

        var sb = new StringBuilder();
        sb.Append($"CALL  {r.CallerName} -> {r.CalleeName} ({Hex(r.CalleeVa)})");
        foreach (var (n, v, d) in r.Args)
            sb.Append($"\n        {n,-5}: {Hex(v)}{(string.IsNullOrEmpty(d) ? "" : "  " + d)}");
        return sb.ToString();
    }

    /// <summary>Short inline form (the argument list) for an entry comment in the disassembly.</summary>
    public static string ArgComment(CaptureRecord r, bool is32)
    {
        string Hex(ulong v) => is32 ? $"0x{(uint)v:X}" : $"0x{v:X}";
        var parts = r.Args.Select(a => string.IsNullOrEmpty(a.Deref) ? $"{a.Name}={Hex(a.Value)}" : $"{a.Name}={a.Deref}");
        return $"{r.CalleeName}({string.Join(", ", parts)})";
    }
}

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
    private readonly Dictionary<(uint Tid, ulong Ret), Stack<CaptureRecord>> _pending = [];   // (thread, retAddr) -> calls awaiting return
    private readonly Dictionary<uint, int> _depthByTid = [];   // per-thread live nesting depth (sum of _pending stack counts) — maintained on push/pop instead of re-summed every hit
    // Records awaiting display, drained by the UI each tick. Bounded — the complete capture is persisted to the
    // log file, not held in memory; the panel only shows a recent window. Capped so a fast capture with a slow
    // UI can't grow the heap (and slow the GUI) without bound.
    private readonly Queue<CaptureRecord> _pendingUi = new();   // guarded by _lock
    private long _total;                                        // running count of all records (cheap progress)
    private const int MaxPendingUi = 5000;
    private readonly Dictionary<ulong, HashSet<ulong>> _edges = [];  // caller-func VA -> set of callee-func VAs
    private int _edgeCount;                                 // distinct caller->callee edges (cheap change check)
    private readonly bool _once;                            // capture each function once, then drop its entry bp
    private readonly bool _argsOnly;                        // skip return capture (no return breakpoints) for speed
    private readonly bool _annotate;                        // dereference values (slower) vs raw hex only (faster)
    private readonly Func<ulong, bool>? _isCodeStart;       // gate: only arm 0xCC where a real code instruction starts
    private readonly Func<ulong, bool>? _isReachable;       // gate (large images only): function is a real call target / symbol
    private readonly object _logLock = new();               // serialize log writes (engine) vs flush (UI)
    private StreamWriter? _log;
    private string? _logBase, _logExt;     // "<dir>\<name>" and ".ext" for numbered parts
    private int _logPart;                  // current part number (1-based)
    private long _partBytes;               // approx bytes written to the current part (drives rotation)

    /// <summary>Max size of each capture-log part before it rolls to the next numbered file. Default ~5 MB so
    /// any editor can open a part without slowing down. Set before capture starts.</summary>
    public long MaxPartBytes { get; set; } = 5L * 1024 * 1024;

    public bool Active { get; private set; }
    public bool Draining { get; private set; }      // stop requested; waiting for a frozen stop to remove bps
    public bool ResumeAfter { get; private set; }   // resume the debuggee after the teardown

    /// <summary>Raised (engine thread) after each captured record so the UI can refresh on its own cadence.</summary>
    public event Action? Captured;

    public FunctionCapture(DebuggerEngine eng, DereferenceResolver deref, IEnumerable<(ulong Va, string Name)> funcs, bool captureOnce, bool argsOnly, bool annotate, Func<ulong, bool>? isCodeStart = null, Func<ulong, bool>? isReachable = null)
    {
        _eng = eng;
        _deref = deref;
        _once = captureOnce;
        _argsOnly = argsOnly;
        _annotate = annotate;
        _isCodeStart = isCodeStart;
        _isReachable = isReachable;
        _names = new Dictionary<ulong, string>();
        foreach (var (va, name) in funcs) _names[va] = name;
        _sorted = _names.Keys.ToArray();
        Array.Sort(_sorted);
    }

    /// <summary>True when <paramref name="va"/> is a genuine code instruction start per the analysis (or when
    /// no classifier was supplied). Guards against arming a 0xCC inside a jump/lookup table that lives in an
    /// executable section: those bytes pass <see cref="DebuggerEngine.IsExecutable"/> but are read as data,
    /// not executed, so the breakpoint never fires and silently corrupts the table — crashing the debuggee.</summary>
    private bool IsCode(ulong va) => _isCodeStart is null || _isCodeStart(va);

    /// <summary>True when <paramref name="va"/> sits in a dense cluster of entries — at least
    /// <see cref="DenseCount"/> function VAs within +/-<see cref="DenseRadius"/> bytes. Real functions are
    /// never packed that tightly; such a cluster is a jump/lookup table the analysis decoded as code (and
    /// the linear classifier therefore did not flag as data, so <see cref="IsCode"/> alone can't catch it).
    /// Arming a 0xCC inside it corrupts the pointers the program reads through the table and crashes it.</summary>
    private const int DenseRadius = 0x20;
    private const int DenseCount = 6;
    private bool IsDenselyPacked(ulong va)
    {
        ulong lo = va > DenseRadius ? va - DenseRadius : 0;
        ulong hi = va + DenseRadius;
        int i = LowerBound(lo), n = 0;
        for (; i < _sorted.Length && _sorted[i] <= hi; i++)
            if (++n >= DenseCount) return true;
        return false;
    }
    private int LowerBound(ulong x)
    {
        int lo = 0, hi = _sorted.Length;
        while (lo < hi) { int mid = (lo + hi) >> 1; if (_sorted[mid] < x) lo = mid + 1; else hi = mid; }
        return lo;
    }

    // Dereference a value (x64dbg-style annotation), or "" when annotation is off — the per-argument
    // memory reads + symbol/string lookups here are the dominant per-capture cost.
    private string Annotate(ulong v) => _annotate ? _deref.Describe(v) : "";

    /// <summary>Total records captured so far (calls + returns) — a cheap progress counter for the UI.</summary>
    public long TotalCount { get { lock (_lock) return _total; } }

    /// <summary>Remove and return the records queued since the last drain. The UI shows a bounded recent
    /// window and persists nothing itself — the complete capture lives in the log file.</summary>
    public IReadOnlyList<CaptureRecord> DrainPending()
    {
        lock (_lock)
        {
            if (_pendingUi.Count == 0) return [];
            var list = new List<CaptureRecord>(_pendingUi.Count);
            while (_pendingUi.Count > 0) list.Add(_pendingUi.Dequeue());
            return list;
        }
    }

    /// <summary>Queue a record for the UI (bounded) and bump the running total. Caller must hold <c>_lock</c>.</summary>
    private void EnqueueForUi(CaptureRecord r)
    {
        _total++;
        _pendingUi.Enqueue(r);
        if (_pendingUi.Count > MaxPendingUi) _pendingUi.Dequeue();   // drop the oldest; the log file still has it
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
        // Split the capture into numbered, editor-friendly parts ("<name>.001<ext>", ".002<ext>", …) instead
        // of one ever-growing file — so any editor can open a piece without choking. Each part rolls at
        // MaxPartBytes. The chosen path supplies the directory, base name and extension.
        try
        {
            string dir = Path.GetDirectoryName(path) ?? "";
            _logExt = Path.GetExtension(path);                       // includes the dot, e.g. ".txt"
            _logBase = Path.Combine(dir, Path.GetFileNameWithoutExtension(path));
            _logPart = 0;
            lock (_logLock) OpenNextPart();
        }
        catch { _log = null; }
    }

    /// <summary>Path of the part currently being written (for status), or null when no log is set.</summary>
    public string? CurrentLogPart => _logBase is null ? null : $"{_logBase}.{_logPart:D3}{_logExt}";

    /// <summary>Close the current part and open the next. Must be called holding <c>_logLock</c>.</summary>
    private void OpenNextPart()
    {
        try { _log?.Flush(); _log?.Dispose(); } catch { }
        _log = null;
        _logPart++;
        _partBytes = 0;
        // Buffered (no per-line flush) for speed; flushed on FlushLog / StopCapture. 64 KiB buffer.
        try { _log = new StreamWriter(CurrentLogPart!, append: false, Encoding.UTF8, 1 << 16) { AutoFlush = false }; }
        catch { _log = null; }
    }

    public int ArmedCount { get; private set; }
    public int SkippedDense { get; private set; }
    public int SkippedNonCode { get; private set; }
    public int SkippedUnreachable { get; private set; }

    /// <summary>Above this many discovered "functions" the analysis is over-identifying code (treating data
    /// tables as functions). Past it we only arm functions we can prove are reachable code — direct call
    /// targets and named symbols — since arming data the program reads corrupts it and crashes the debuggee.</summary>
    private const int OverIdentifiedThreshold = 50_000;

    /// <summary>Capture every known function.</summary>
    public void StartAll()
    {
        // Only arm entries that are executable AND a genuine code instruction start (IsCode) AND not part of a
        // dense cluster (IsDenselyPacked): a "function" mistakenly identified inside a jump/lookup table in an
        // executable section would otherwise get a 0xCC written into data the program reads as pointers,
        // corrupting it and crashing the debuggee. On binaries where the analysis wildly over-identifies code,
        // also require the function be provably reachable (a real call target / symbol), since the bulk of
        // those false positives are data and density alone can't catch the sparser ones.
        bool requireReachable = _isReachable != null && _names.Count > OverIdentifiedThreshold;
        var toArm = new List<ulong>(_names.Count);
        lock (_lock)
            foreach (var va in _names.Keys)
            {
                if (!_eng.IsExecutable(va)) continue;
                if (!IsCode(va)) { SkippedNonCode++; continue; }
                if (IsDenselyPacked(va)) { SkippedDense++; continue; }
                if (requireReachable && !_isReachable!(va)) { SkippedUnreachable++; continue; }
                if (_entries.Add(va)) toArm.Add(va);
            }
        ArmedCount = toArm.Count;
        try { _eng.SetBreakpoints(toArm); } catch { }   // page-batched arming (fast for thousands of bps)
        _eng.PassFirstChanceExceptions = true;          // don't stop on the program's own exceptions
        Active = true;
    }

    /// <summary>Capture a single function.</summary>
    public void StartFunction(ulong va)
    {
        lock (_lock)
        {
            if (_eng.IsExecutable(va) && IsCode(va) && _entries.Add(va)) { try { _eng.SetBreakpoint(va); } catch { } }
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
            _entries.Clear(); _retBps.Clear(); _pending.Clear(); _depthByTid.Clear();
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
        uint tid = s.ThreadId;
        bool isEntry, isRet, ours;
        lock (_lock) { isEntry = _entries.Contains(ea); isRet = _pending.ContainsKey((tid, ea)); ours = isEntry || _retBps.Contains(ea); }
        if (!isEntry && !isRet) return false;

        var regs = _eng.GetRegisters();
        if (regs is null) return false;

        if (isRet) HandleReturn(tid, ea, regs);   // a stop can be both (recursion / tail) — return first
        if (isEntry) HandleEntry(tid, ea, regs);

        // If a user breakpoint also sits here, capture but let the stop surface (don't auto-resume).
        if (!ours) return false;
        _eng.Go();   // queued; the loop consumes it right after this handler returns
        return true;
    }

    private void HandleEntry(uint tid, ulong ea, RegisterSet regs)
    {
        ulong retAddr = ReadPtr(regs.Sp);
        ulong callerFunc = FuncContaining(retAddr);
        // Only capture a return when [rsp] is a genuine return address (executable and preceded by a call).
        // When a function is reached by a jump/tail-call rather than a call, [rsp] is unrelated stack data,
        // and writing a 0xCC breakpoint there would corrupt the debuggee (an access violation on continue).
        bool captureReturn = !_argsOnly && _eng.IsReturnAddress(retAddr);
        var rec = new CaptureRecord
        {
            CalleeVa = ea,
            CalleeName = NameOf(ea),
            CallerVa = retAddr,
            CallerFuncVa = callerFunc,
            CallerName = callerFunc != 0 ? NameOf(callerFunc) : $"0x{retAddr:X}",
            ThreadId = tid,
            Args = CaptureArgs(regs),
        };

        lock (_lock)
        {
            rec.Depth = _depthByTid.GetValueOrDefault(tid);   // this thread's nesting depth (maintained on push/pop below)
            if (captureReturn)
            {
                if (!_pending.TryGetValue((tid, retAddr), out var stack)) { stack = new Stack<CaptureRecord>(); _pending[(tid, retAddr)] = stack; }
                stack.Push(rec);
                _depthByTid[tid] = _depthByTid.GetValueOrDefault(tid) + 1;   // one more call in flight on this thread
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
            EnqueueForUi(rec);
        }
        WriteLog(rec);
        Captured?.Invoke();
    }

    private void HandleReturn(uint tid, ulong ea, RegisterSet regs)
    {
        CaptureRecord? call;
        lock (_lock)
        {
            if (!_pending.TryGetValue((tid, ea), out var stack) || stack.Count == 0) return;
            call = stack.Pop();
            if (_depthByTid.GetValueOrDefault(tid) > 0) _depthByTid[tid]--;   // matches the push in HandleEntry
            if (stack.Count == 0)
            {
                _pending.Remove((tid, ea));
                // The return breakpoint is shared by all threads — only remove it once no thread is still
                // awaiting a return at this address.
                if (!_pending.Keys.Any(k => k.Ret == ea) && _retBps.Remove(ea) && !_entries.Contains(ea))
                    { try { _eng.RemoveBreakpoint(ea); } catch { } }
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
        lock (_lock) EnqueueForUi(ret);
        WriteLog(ret);
        Captured?.Invoke();
    }

    // Win64: rcx, rdx, r8, r9 then [rsp+0x28], [rsp+0x30]. x86 (cdecl/stdcall): [esp+4], [esp+8], …
    private List<(string Name, ulong Value, string Deref)> CaptureArgs(RegisterSet regs)
    {
        var list = new List<(string, ulong, string)>();
        if (_eng.Is32)
        {
            // All six args are consecutive dwords at [esp+4 .. esp+0x18] — read them in one shot (was 6 syscalls).
            var b = _eng.ReadMemory(regs.Sp + 4, 24);
            for (int i = 0; i < 6; i++)
            {
                int off = i * 4;
                ulong v = off + 4 <= b.Length ? BitConverter.ToUInt32(b, off) : 0;
                list.Add(($"arg{i}", v, Annotate(v)));
            }
        }
        else
        {
            foreach (var r in new[] { "rcx", "rdx", "r8", "r9" }) { ulong v = regs[r]; list.Add((r, v, Annotate(v))); }
            // Args 5 and 6 sit at [rsp+0x28] and [rsp+0x30] — one 16-byte read covers both (was 2 syscalls).
            var b = _eng.ReadMemory(regs.Sp + 0x28, 16);
            for (int i = 0; i < 2; i++)
            {
                int off = i * 8;
                ulong v = off + 8 <= b.Length ? BitConverter.ToUInt64(b, off) : 0;
                list.Add(($"arg{4 + i}", v, Annotate(v)));
            }
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
        string line = Format(r, _eng.Is32);
        lock (_logLock)
        {
            if (_log is null) return;
            try
            {
                _log.WriteLine(line);
                _partBytes += line.Length + Environment.NewLine.Length;   // approx (ASCII log) — drives rotation
                if (_partBytes >= MaxPartBytes) OpenNextPart();           // roll to the next editor-friendly part
            }
            catch { }
        }
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

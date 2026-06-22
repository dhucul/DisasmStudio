using DisasmStudio.Core.Unpacking;
using Iced.Intel;

namespace DisasmStudio.Debug;

/// <summary>
/// Anti-anti-debug ("hide from debugger"), ScyllaHide-style. When <see cref="HideFromDebugger"/> is set
/// before launch, the loader breakpoint triggers <see cref="ApplyAntiAntiDebug"/>, which (1) normalizes the
/// debuggee PEB — clears <c>BeingDebugged</c>, the <c>NtGlobalFlag</c> heap-debug bits, and the process
/// heap's <c>Flags</c>/<c>ForceFlags</c> — and (2) plants silent <i>internal breakpoints</i> on the ntdll
/// query routines a protector uses to detect us, emulating a clean "not debugged" result. The
/// invalid-handle trick is defeated in the exception handler. Internal breakpoints never surface to the UI
/// and are masked from the debuggee's own reads.
/// </summary>
public sealed partial class DebuggerEngine
{
    /// <summary>Enable the anti-anti-debug layer. Set before <see cref="Launch"/>.</summary>
    public bool HideFromDebugger { get; set; }

    private bool _adApplied;
    private long _fakeClock;                                            // monotonic synthetic timer (defeats timing checks)
    private uint _fakeParentPid;                                        // explorer.exe PID, to spoof a parent-process check
    private readonly Dictionary<ulong, InternalBp> _internalBps = [];   // hook addr -> hook state
    private readonly Dictionary<uint, ulong> _internalStep = [];        // thread -> internal hook to re-arm after a step
    private readonly Dictionary<ulong, PendingReturn> _pendingReturns = [];   // return-patch: retaddr -> output to scrub

    /// <summary>A pending return-patch: when execution returns to <see cref="RetAddr"/>, scrub the call's output.</summary>
    private readonly record struct PendingReturn(AdKind Kind, ulong Ptr, ulong Len, byte Orig);

    /// <summary>What an internal anti-debug hook does and how its call frame is shaped.</summary>
    private enum AdKind
    {
        QueryInfoProcess, SetInfoThread, QuerySystemInfo,
        GetContextThread,                                              // return-patch: scrub Dr0-7 from the CONTEXT
        SetContextThread,                                             // edit-input: drop the debug-register group
        QueryObject,                                                 // return-patch: scrub the DebugObject type counts
        FindWindow,                                                  // emulate: hide known debugger window classes
        TickCount, TickCount64, Qpc, NtQpc, SysTimeAsFileTime, NtSystemTime,   // timing: emulate a slow synthetic clock
        Rdtsc, Rdtscp,                                               // instruction hooks: emulate the synthetic TSC
    }

    private sealed class InternalBp
    {
        public required AdKind Kind { get; init; }
        public required int X86Args { get; init; }   // stdcall arg count (for x86 ret cleanup); ignored on x64
        public byte Original { get; set; }
        public bool Armed { get; set; }
    }

    /// <summary>Public count of installed hooks (for diagnostics / smoke tests).</summary>
    public int AntiDebugHookCount { get { lock (_lock) return _internalBps.Count; } }

    /// <summary>The debuggee PEB base (the 32-bit PEB for a WOW64 target), or 0. Safe while stopped.</summary>
    public ulong PebBaseAddress() => GetPebBase(Is32);

    // ---- apply (loader-breakpoint time, debuggee frozen) ----
    private void ApplyAntiAntiDebug()
    {
        try { PatchPeb(); } catch { /* best-effort */ }
        try { InstallNtdllHooks(); } catch { }
        try { InterceptRdtsc(); } catch { }
    }

    // ---- PEB / heap normalization ----
    private void PatchPeb()
    {
        bool peb32 = Is32;                       // WOW64 target checks its 32-bit PEB
        ulong peb = GetPebBase(peb32);
        if (peb == 0) return;
        int ptr = peb32 ? 4 : 8;

        WriteMemory(peb + 0x02, [0]);            // BeingDebugged = 0

        int ngfOff = peb32 ? 0x68 : 0xBC;        // NtGlobalFlag
        uint ngf = ReadU32(peb + (ulong)ngfOff);
        WriteU32(peb + (ulong)ngfOff, ngf & ~0x70u);   // clear FLG_HEAP_ENABLE_TAIL_CHECK|FREE_CHECK|VALIDATE_PARAMETERS

        // Process heap Flags/ForceFlags → a non-debugged heap (Flags = HEAP_GROWABLE, ForceFlags = 0).
        ulong heap = ReadPtr(peb + (ulong)(peb32 ? 0x18 : 0x30), peb32);
        if (heap != 0)
        {
            int flagsOff = peb32 ? 0x40 : 0x70, forceOff = peb32 ? 0x44 : 0x74;
            WriteU32(heap + (ulong)flagsOff, 2);
            WriteU32(heap + (ulong)forceOff, 0);
        }
        Output?.Invoke($"Anti-debug: PEB normalized (BeingDebugged/NtGlobalFlag/heap @ {peb:X}).");
    }

    private ulong GetPebBase(bool peb32)
    {
        int size = peb32 ? 8 : 48;
        IntPtr buf = System.Runtime.InteropServices.Marshal.AllocHGlobal(size);
        try
        {
            int cls = peb32 ? Native.ProcessWow64Information : Native.ProcessBasicInformation;
            int st = Native.NtQueryInformationProcess(_proc, cls, buf, (uint)size, out _);
            if (st != 0) return 0;
            // ProcessWow64Information returns the PEB32 pointer directly; ProcessBasicInformation puts
            // PebBaseAddress at offset 8 (after NTSTATUS + padding).
            return peb32 ? (ulong)System.Runtime.InteropServices.Marshal.ReadIntPtr(buf)
                         : (ulong)System.Runtime.InteropServices.Marshal.ReadIntPtr(buf, 8);
        }
        finally { System.Runtime.InteropServices.Marshal.FreeHGlobal(buf); }
    }

    // ---- hooks ----
    private void InstallNtdllHooks()
    {
        ulong ntdll = ModuleBaseByName("ntdll.dll", Is32);
        if (ntdll == 0) { Output?.Invoke("Anti-debug: ntdll not found; hooks skipped."); return; }

        // Detection queries.
        TryHook(ntdll, "NtQueryInformationProcess", AdKind.QueryInfoProcess, 5);
        TryHook(ntdll, "NtSetInformationThread", AdKind.SetInfoThread, 4);
        TryHook(ntdll, "NtQuerySystemInformation", AdKind.QuerySystemInfo, 4);
        TryHook(ntdll, "NtQueryObject", AdKind.QueryObject, 5);   // hide debug-object counts
        // Hardware-breakpoint self-detection: scrub Dr0-7 from any queried CONTEXT, and stop the target from
        // clearing our Dr breakpoints via a set-context.
        TryHook(ntdll, "NtGetContextThread", AdKind.GetContextThread, 2);
        TryHook(ntdll, "NtSetContextThread", AdKind.SetContextThread, 2);
        // Timing (syscall side).
        TryHook(ntdll, "NtQueryPerformanceCounter", AdKind.NtQpc, 2);
        TryHook(ntdll, "NtQuerySystemTime", AdKind.NtSystemTime, 1);

        // Timing (KUSER_SHARED_DATA readers live in kernelbase; kernel32 forwards to it).
        ulong kbase = ModuleBaseByName("kernelbase.dll", Is32);
        if (kbase != 0)
        {
            TryHook(kbase, "GetTickCount", AdKind.TickCount, 0);
            TryHook(kbase, "GetTickCount64", AdKind.TickCount64, 0);
            TryHook(kbase, "QueryPerformanceCounter", AdKind.Qpc, 1);
            TryHook(kbase, "GetSystemTimeAsFileTime", AdKind.SysTimeAsFileTime, 1);
        }
        Output?.Invoke($"Anti-debug: {_internalBps.Count} hook(s) armed ({(Is32 ? "32-bit" : "64-bit")}; ntdll @ {ntdll:X}).");
    }

    private void TryHook(ulong moduleBase, string export, AdKind kind, int x86Args)
    {
        ulong va = ResolveExport(moduleBase, export);
        if (va == 0) return;
        var raw = new byte[1];
        Native.ReadProcessMemory(_proc, va, raw, 1, out var read);
        if ((int)read != 1) return;
        var bp = new InternalBp { Kind = kind, X86Args = x86Args, Original = raw[0] };
        lock (_lock) _internalBps[va] = bp;
        ArmInternal(va);
    }

    private void ArmInternal(ulong va)
    {
        InternalBp? bp; lock (_lock) _internalBps.TryGetValue(va, out bp);
        if (bp is null || bp.Armed) return;
        if (WriteCode(va, [0xCC])) bp.Armed = true;
    }

    private void DisarmInternal(ulong va)
    {
        InternalBp? bp; lock (_lock) _internalBps.TryGetValue(va, out bp);
        if (bp is { Armed: true }) { WriteCode(va, [bp.Original]); bp.Armed = false; }
    }

    // ---- rdtsc / rdtscp interception (instruction, not an API — breakpoint each one and emulate it) ----
    /// <summary>Find rdtsc/rdtscp instructions in the main image's code and breakpoint them. Linear-sweep
    /// disassembly is used so we only break at real instruction boundaries; high-entropy (packed/compressed)
    /// executable sections are SKIPPED so we never plant an int3 inside data the unpack stub reads.</summary>
    private void InterceptRdtsc()
    {
        var hdr = ReadMemory(ImageBase, 0x1000);
        if (hdr.Length < 0x200 || !PeView.TryParse(hdr, out var view)) return;
        int found = 0;
        foreach (var s in view.Sections)
        {
            if (!s.IsExecutable || found >= 512) continue;
            uint size = Math.Min(Math.Max(s.VirtualSize, s.SizeOfRawData), 16u << 20);
            if (size < 2) continue;
            var code = ReadMemory(ImageBase + s.VirtualAddress, (int)size);
            if (code.Length < 2 || Entropy.Shannon(code) > 7.0) continue;   // skip compressed/packed code

            ulong baseVa = ImageBase + s.VirtualAddress;
            var dec = Decoder.Create(Is32 ? 32 : 64, new ByteArrayCodeReader(code));
            dec.IP = baseVa;
            while (dec.IP < baseVa + (ulong)code.Length && found < 512)
            {
                ulong ip = dec.IP;
                dec.Decode(out var ins);
                if (ins.IsInvalid) continue;
                if (ins.Mnemonic == Mnemonic.Rdtsc) { ArmRdtsc(ip, AdKind.Rdtsc); found++; }
                else if (ins.Mnemonic == Mnemonic.Rdtscp) { ArmRdtsc(ip, AdKind.Rdtscp); found++; }
            }
        }
        if (found > 0) Output?.Invoke($"Anti-debug: {found} rdtsc/rdtscp instruction(s) hooked.");
    }

    private void ArmRdtsc(ulong va, AdKind kind)
    {
        lock (_lock) if (_internalBps.ContainsKey(va) || _swBps.ContainsKey(va) || _tempBps.ContainsKey(va)) return;
        var raw = new byte[1];
        Native.ReadProcessMemory(_proc, va, raw, 1, out var read);
        if ((int)read != 1) return;
        lock (_lock) _internalBps[va] = new InternalBp { Kind = kind, X86Args = 0, Original = raw[0] };
        ArmInternal(va);
    }

    // ---- hook dispatch (loop thread; debuggee frozen at the int3) ----
    private void HandleAntiDebugHook(ulong addr, uint tid, IntPtr hThread)
    {
        InternalBp? bp; lock (_lock) _internalBps.TryGetValue(addr, out bp);
        if (bp is null) return;

        using var c = new Ctx(Is32);
        if (!c.Get(hThread)) return;
        c.Ip = addr;                                  // rewind over the 0xCC

        ulong sp = c.GetReg(Is32 ? "esp" : "rsp");
        // Arg N (1-based): x64 → rcx/rdx/r8/r9; x86 stdcall → [esp + 4*N].
        ulong Arg(int n) => !Is32
            ? n switch { 1 => c.GetReg("rcx"), 2 => c.GetReg("rdx"), 3 => c.GetReg("r8"), 4 => c.GetReg("r9"), _ => ReadPtr(sp + (ulong)(n - 1) * 8, false) }
            : ReadU32(sp + (ulong)(n * 4));

        // NtGetContextThread can't be emulated (we don't have the real context). Let it run, then scrub the Dr
        // registers from its output on return — so the program never sees our hardware breakpoints.
        if (bp.Kind == AdKind.GetContextThread)
        {
            ArmReturnBp(ReadPtr(sp, Is32), Arg(2));   // arg2 = PCONTEXT
            LetItRun(addr, tid, c, hThread);
            return;
        }

        // NtSetContextThread: strip CONTEXT_DEBUG_REGISTERS from the incoming CONTEXT so the call applies every
        // register group except the debug registers — preserving our hardware breakpoints against a target that
        // tries to clear them. Then let the (modified) call run.
        if (bp.Kind == AdKind.SetContextThread)
        {
            ulong ctxPtr = Arg(2);
            int flagsOff = Is32 ? 0x00 : 0x30;        // CONTEXT.ContextFlags offset (matches Ctx.FlagsOff)
            if (ctxPtr != 0)
            {
                uint flags = ReadU32(ctxPtr + (ulong)flagsOff);
                if ((flags & 0x10) != 0) WriteU32(ctxPtr + (ulong)flagsOff, flags & ~0x10u);   // 0x10 = debug-register group
            }
            LetItRun(addr, tid, c, hThread);
            return;
        }

        // rdtsc / rdtscp instruction hook: emulate it from the synthetic clock and skip over it. EDX:EAX get the
        // 64-bit TSC (rdtscp also zeroes ECX = processor id); RIP advances past the instruction (the int3 stays
        // armed for the next execution). Per-call deltas stay tiny so cycle-timing checks can't see the debugger.
        if (bp.Kind is AdKind.Rdtsc or AdKind.Rdtscp)
        {
            ulong tsc = 0x1_0000_0000UL + (ulong)NextFake() * 100;
            c.TrySetByName(Is32 ? "eax" : "rax", tsc & 0xFFFFFFFF);
            c.TrySetByName(Is32 ? "edx" : "rdx", tsc >> 32);
            if (bp.Kind == AdKind.Rdtscp) c.TrySetByName(Is32 ? "ecx" : "rcx", 0);
            c.Ip = addr + (ulong)(bp.Kind == AdKind.Rdtscp ? 3 : 2);
            c.Set(hThread);
            return;
        }

        bool handled = bp.Kind switch
        {
            AdKind.QueryInfoProcess => HookQueryInfoProcess(c, Arg),
            AdKind.SetInfoThread => HookSetInfoThread(c, Arg),
            AdKind.QuerySystemInfo => HookQuerySystemInfo(c, Arg),
            AdKind.TickCount => HookTickCount(c, false),
            AdKind.TickCount64 => HookTickCount(c, true),
            AdKind.Qpc => HookQpc(c, Arg, ntStatus: false),
            AdKind.NtQpc => HookQpc(c, Arg, ntStatus: true),
            AdKind.SysTimeAsFileTime => HookSystemTime(c, Arg, ntStatus: false),
            AdKind.NtSystemTime => HookSystemTime(c, Arg, ntStatus: true),
            _ => false,
        };

        if (handled) { EmulateReturn(c, sp, bp.X86Args, hThread); return; }

        // Not a recognised case — let the real function run: step one instruction off our int3, re-arm it.
        LetItRun(addr, tid, c, hThread);
    }

    /// <summary>Step one instruction off an internal hook's int3, re-arming it afterwards, so the real
    /// function runs.</summary>
    private void LetItRun(ulong addr, uint tid, Ctx c, IntPtr hThread)
    {
        DisarmInternal(addr);
        lock (_lock) _internalStep[tid] = addr;
        c.TrapFlag = true;
        c.Set(hThread);
    }

    // NtQueryInformationProcess(handle, class, out info, len, out retlen)
    private bool HookQueryInfoProcess(Ctx c, Func<int, ulong> arg)
    {
        ulong cls = arg(2), outPtr = arg(3);
        switch (cls)
        {
            case 0x07:  // ProcessDebugPort → 0 (no debug port)
                WritePtr(outPtr, 0, Is32); SetRet(c, 0); return true;
            case 0x1E:  // ProcessDebugObjectHandle → null handle, STATUS_PORT_NOT_SET
                WritePtr(outPtr, 0, Is32); SetRet(c, 0xC0000353); return true;
            case 0x1F:  // ProcessDebugFlags → 1 (NoDebugInherit: i.e. "not being debugged")
                WriteU32(outPtr, 1); SetRet(c, 0); return true;
            default:
                return false;
        }
    }

    // NtSetInformationThread(handle, class, info, len)
    private bool HookSetInfoThread(Ctx c, Func<int, ulong> arg)
    {
        if (arg(2) == 0x11) { SetRet(c, 0); return true; }   // ThreadHideFromDebugger → pretend success, don't hide
        return false;
    }

    // NtQuerySystemInformation(class, out info, len, out retlen)
    private bool HookQuerySystemInfo(Ctx c, Func<int, ulong> arg)
    {
        if (arg(1) == 0x23)   // SystemKernelDebuggerInformation → {Enabled=0, NotPresent=1}
        {
            ulong outPtr = arg(2);
            WriteMemory(outPtr, [0, 1]);
            SetRet(c, 0);
            return true;
        }
        return false;
    }

    private static void SetRet(Ctx c, ulong status) => c.TrySetByName(c.Is32 ? "eax" : "rax", status);

    // ---- timing: a monotonic synthetic clock that advances a tiny step per call, so the deltas a program
    // measures across a (slow, breakpointed) region stay small and it can't tell it's being debugged. ----
    private long NextFake() => System.Threading.Interlocked.Increment(ref _fakeClock);

    // GetTickCount → ms in eax; GetTickCount64 → ms in rax (x64) / edx:eax (x86).
    private bool HookTickCount(Ctx c, bool wide)
    {
        ulong ms = 0x1000_0000UL + (ulong)NextFake();
        if (wide)
        {
            c.TrySetByName(Is32 ? "eax" : "rax", Is32 ? ms & 0xFFFFFFFF : ms);
            if (Is32) c.TrySetByName("edx", ms >> 32);
        }
        else SetRet(c, (uint)ms);
        return true;
    }

    // QueryPerformanceCounter(out counter) → BOOL; NtQueryPerformanceCounter(out counter, out freq) → NTSTATUS.
    private bool HookQpc(Ctx c, Func<int, ulong> arg, bool ntStatus)
    {
        ulong counter = (ulong)NextFake();
        if (arg(1) is var cnt && cnt != 0) WriteMemory(cnt, BitConverter.GetBytes(counter));
        if (ntStatus && arg(2) is var frq && frq != 0) WriteMemory(frq, BitConverter.GetBytes(10_000_000UL));
        SetRet(c, ntStatus ? 0u : 1u);
        return true;
    }

    // GetSystemTimeAsFileTime(out filetime) → void; NtQuerySystemTime(out time) → NTSTATUS.
    private bool HookSystemTime(Ctx c, Func<int, ulong> arg, bool ntStatus)
    {
        ulong ft = 0x01DB_0000_0000_0000UL + (ulong)NextFake() * 10_000UL;   // 1 ms (in 100 ns units) per call
        if (arg(1) is var outp && outp != 0) WriteMemory(outp, BitConverter.GetBytes(ft));
        if (ntStatus) SetRet(c, 0);
        return true;
    }

    // ---- return-patch hooks: run the real function, then scrub its output on return ----
    private void ArmReturnBp(ulong retAddr, ulong ctxPtr)
    {
        if (retAddr == 0 || ctxPtr == 0) return;
        lock (_lock)
            if (_pendingReturns.ContainsKey(retAddr) || _swBps.ContainsKey(retAddr)
                || _tempBps.ContainsKey(retAddr) || _internalBps.ContainsKey(retAddr)) return;
        var o = ReadMemory(retAddr, 1);
        if (o.Length < 1) return;
        lock (_lock) _pendingReturns[retAddr] = (ctxPtr, o[0]);
        WriteCode(retAddr, [0xCC]);
    }

    /// <summary>At an armed return address: restore the byte, rewind, and zero the Dr0-Dr3/Dr6/Dr7 fields of
    /// the CONTEXT the call filled in — hiding our hardware breakpoints. Handled silently (never surfaced).</summary>
    private void HandleReturnHook(ulong addr, IntPtr hThread)
    {
        (ulong CtxPtr, byte Orig) pend;
        lock (_lock) { if (!_pendingReturns.Remove(addr, out pend)) return; }
        WriteCode(addr, [pend.Orig]);
        SetIp(hThread, addr);
        int[] drOff = Is32 ? [0x04, 0x08, 0x0C, 0x10, 0x14, 0x18] : [0x48, 0x50, 0x58, 0x60, 0x68, 0x70];
        var zero = new byte[Is32 ? 4 : 8];
        foreach (int off in drOff) WriteMemory(pend.CtxPtr + (ulong)off, zero);
    }

    /// <summary>Emulate the function's return: pop the return address and (x86 stdcall) the arguments.</summary>
    private void EmulateReturn(Ctx c, ulong sp, int x86Args, IntPtr hThread)
    {
        ulong retAddr = ReadPtr(sp, Is32);
        c.Ip = retAddr;
        ulong newSp = Is32 ? sp + 4 + (ulong)x86Args * 4   // stdcall: callee cleans args
                           : sp + 8;                        // x64: caller cleans
        c.TrySetByName(Is32 ? "esp" : "rsp", newSp);
        c.Set(hThread);
    }

    // ---- module / export resolution from process memory ----
    /// <summary>Base of the loaded module named <paramref name="name"/> of the target's bitness (the SysWOW64
    /// copy for a WOW64 target, else System32), or 0. Prefers the bitness-matched copy; falls back to any.</summary>
    private ulong ModuleBaseByName(string name, bool wow64)
    {
        ModuleInfo? best = null;
        lock (_lock)
            foreach (var m in _modules.Values)
            {
                if (!m.Name.Equals(name, StringComparison.OrdinalIgnoreCase)) continue;
                bool isWowPath = m.Path.Contains("SysWOW64", StringComparison.OrdinalIgnoreCase);
                if (wow64 == isWowPath) return m.Base;   // exact bitness-dir match
                best ??= m;                              // fallback: any copy
            }
        return best?.Base ?? 0;
    }

    private ulong ResolveExport(ulong moduleBase, string name)
    {
        var hdr = ReadMemory(moduleBase, 0x1000);
        if (hdr.Length < 0x200 || !PeView.TryParse(hdr, out var view)) return 0;
        var (expRva, _) = view.DataDir(PeConstants.DirExport);
        if (expRva == 0) return 0;
        var dir = ReadMemory(moduleBase + expRva, 40);
        if (dir.Length < 40) return 0;
        uint numNames = U32(dir, 0x18);
        uint eatRva = U32(dir, 0x1C), nameTblRva = U32(dir, 0x20), ordTblRva = U32(dir, 0x24);
        var nameTbl = ReadMemory(moduleBase + nameTblRva, (int)Math.Min(numNames, 100_000) * 4);
        var ordTbl = ReadMemory(moduleBase + ordTblRva, (int)Math.Min(numNames, 100_000) * 2);
        for (uint i = 0; i < numNames; i++)
        {
            if ((i + 1) * 4 > (uint)nameTbl.Length || (i + 1) * 2 > (uint)ordTbl.Length) break;
            uint nameRva = U32(nameTbl, (int)i * 4);
            string s = ReadCString(moduleBase + nameRva);
            if (!s.Equals(name, StringComparison.Ordinal)) continue;
            ushort ord = U16(ordTbl, (int)i * 2);
            var eat = ReadMemory(moduleBase + eatRva + (ulong)ord * 4, 4);
            if (eat.Length < 4) return 0;
            uint funcRva = BitConverter.ToUInt32(eat, 0);
            return funcRva == 0 ? 0 : moduleBase + funcRva;
        }
        return 0;
    }

    private string ReadCString(ulong va, int max = 256)
    {
        var b = ReadMemory(va, max);
        int end = Array.IndexOf(b, (byte)0);
        if (end < 0) end = b.Length;
        return System.Text.Encoding.ASCII.GetString(b, 0, end);
    }

    // ---- small memory helpers ----
    private uint ReadU32(ulong va) { var b = ReadMemory(va, 4); return b.Length == 4 ? BitConverter.ToUInt32(b, 0) : 0; }
    private void WriteU32(ulong va, uint v) => WriteMemory(va, BitConverter.GetBytes(v));
    private ulong ReadPtr(ulong va, bool is32) { var b = ReadMemory(va, is32 ? 4 : 8); return b.Length < (is32 ? 4 : 8) ? 0 : (is32 ? BitConverter.ToUInt32(b, 0) : BitConverter.ToUInt64(b, 0)); }
    private void WritePtr(ulong va, ulong v, bool is32) => WriteMemory(va, is32 ? BitConverter.GetBytes((uint)v) : BitConverter.GetBytes(v));
    private static uint U32(byte[] b, int o) => o + 4 <= b.Length ? BitConverter.ToUInt32(b, o) : 0;
    private static ushort U16(byte[] b, int o) => o + 2 <= b.Length ? BitConverter.ToUInt16(b, o) : (ushort)0;
}

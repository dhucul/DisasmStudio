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

    /// <summary>When hiding, install the int3 hooks on ntdll/kernelbase/user32 API entries (the debug-query
    /// and timing emulation). These live in system modules, not the target, so a target's self-CRC won't see
    /// them — but a protector that scans ntdll prologues for hooks might. Set false to test that.</summary>
    public bool HideUseApiHooks { get; set; } = true;

    /// <summary>When hiding, patch the target's own <c>rdtsc</c>/<c>rdtscp</c> instructions to feed a synthetic
    /// clock. This modifies the TARGET's code, so a self-CRC protector (e.g. VMProtect) can detect it. Set
    /// false to leave the target's bytes untouched — separated from <see cref="HideUseApiHooks"/> so API
    /// emulation can stay on while the target is not modified.</summary>
    public bool HideInterceptRdtsc { get; set; } = true;

    /// <summary>When hiding, spoof the debuggee's parent PID (the value a packer compares against explorer.exe)
    /// so it doesn't see the debugger as its parent. Auto-resolved to this session's explorer.exe at the loader
    /// breakpoint; disable to leave the real parent in place. <see cref="SpoofParentProcessId"/> reports what
    /// was used. Covers NtQueryInformationProcess(ProcessBasicInformation) (the common one) and, when
    /// <see cref="HideUseApiHooks"/> is on, the kernel32 Process32FirstW/Process32NextW snapshot walk.</summary>
    public bool SpoofParentProcess { get; set; } = true;

    /// <summary>The parent PID injected into NtQueryInformationProcess(ProcessBasicInformation) results, or 0 if
    /// parent spoofing is off or no explorer.exe was found. Resolved at the loader breakpoint.</summary>
    public uint SpoofParentProcessId => _spoofParentPid;

    private bool _adApplied;
    private uint _spoofParentPid;          // parent PID to report to the debuggee (0 = spoof disabled)
    private bool _windowHooksInstalled;    // FindWindow* hooks armed (once user32 is mapped)
    private long _fakeClock;                                            // monotonic synthetic timer (defeats timing checks)
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
        QueryInfoProcessParent,                                      // return-patch: spoof PROCESS_BASIC_INFORMATION.InheritedFromUniqueProcessId
        FindWindowW, FindWindowA, FindWindowExW, FindWindowExA,      // emulate: hide known debugger windows (return NULL)
        TickCount, TickCount64, Qpc, NtQpc, SysTimeAsFileTime, NtSystemTime,   // timing: emulate a slow synthetic clock
        Rdtsc, Rdtscp,                                               // instruction hooks: emulate the synthetic TSC
        CloseHandle,                                                 // return-patch: swallow invalid-handle closes
        Process32First, Process32Next,                               // return-patch: hide debugger from snapshot walk
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
        try { PatchKUserSharedData(); } catch { }
        try { ResolveSpoofParent(); } catch { }
        if (HideUseApiHooks) { try { InstallNtdllHooks(); } catch { } }
        else Output?.Invoke("Anti-debug: ntdll/user32 API hooks DISABLED.");
        if (HideInterceptRdtsc) { try { InterceptRdtsc(); } catch { } }
        else Output?.Invoke("Anti-debug: rdtsc patching DISABLED — the target's own code is left unmodified (testing self-CRC detection).");
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

    // ---- KUSER_SHARED_DATA.KdDebuggerEnabled spoof ----
    /// <summary>Zero the KdDebuggerEnabled byte in the debuggee's read-only view of KUSER_SHARED_DATA
    /// (0x7FFE0000). This shared page is mapped as read-only into every process; a protector can read it
    /// directly as a fast "am I being debugged?" check that needs no API call. We temporarily re-protect
    /// to writable, zero the byte, then restore. On x64 the byte is at offset 0x2D4; on WOW64 the 32-bit
    /// view is at a different VA (segment base), so we patch both if a WOW64 target.</summary>
    private void PatchKUserSharedData()
    {
        // The 64-bit KUSER_SHARED_DATA is mapped at the same fixed VA in every 64-bit process on x64 Windows.
        const ulong kuser64 = 0x7FFE0000;
        const int kdOff = 0x2D4;
        if (!Is32)
        {
            WriteByteNoDefault(kuser64 + (ulong)kdOff, 0);
            Output?.Invoke($"Anti-debug: KUSER_SHARED_DATA.KdDebuggerEnabled zeroed (x64 @ {kuser64 + (ulong)kdOff:X}).");
        }
        else
        {
            // For a WOW64 target, the 32-bit KUSER_SHARED_DATA is at a per-process VA. The segment base the
            // CPU uses for 32-bit linear addressing doesn't map 1:1 to a VA in the 64-bit host process, but
            // the WOW64 layer maps a known copy at a fixed offset. The most reliable approach: locate the
            // 32-bit PEB, walk TEB->TIB->Self to get the 32-bit linear address space bounds, and read the
            // FS:[0x2D4] value via the debuggee's context. Since we don't have a full 32-bit-address-space
            // remapping layer, we zero the 64-bit KUSER_SHARED_DATA (which the WOW64 thunk transitions
            // through) and trust that any WOW64-level read of KdDebuggerEnabled sees the same underlying
            // page. A sufficiently aggressive WOW64 protector can read FS:[0x2D4] directly; covering that
            // requires a per-instruction hook on every `mov al, fs:[0x2D4]` — impractical here.
            WriteByteNoDefault(kuser64 + (ulong)kdOff, 0);
            Output?.Invoke($"Anti-debug: KUSER_SHARED_DATA.KdDebuggerEnabled zeroed (x64 page @ WOW64 target).");
        }
    }

    /// <summary>Write a single byte to a guest VA that may be read-only, without changing the page
    /// protection in a way that a protector can detect later. Temporarily makes the page RW, writes,
    /// restores. On failure the call is silently dropped; a dead KdDebuggerEnabled is best-effort.</summary>
    private void WriteByteNoDefault(ulong va, byte value)
    {
        ulong page = va & ~0xFFFUL;
        uint orig = 0;
        if (!Native.VirtualProtectEx(_proc, page, 0x1000, Native.PAGE_READWRITE, out orig)) return;
        try { WriteMemory(va, [value]); }
        finally { Native.VirtualProtectEx(_proc, page, 0x1000, orig, out _); }
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
        // Fake-handle close test: swallow the STATUS_INVALID_HANDLE exception via return-patch. NtClose has
        // no standard export name — the stub lives at a known syscall ordinal, so we hook ZwClose instead
        // (the user-mode entry NtClose forwards to). On x64 ZwClose == NtClose (identical prologue).
        TryHook(ntdll, "ZwClose", AdKind.CloseHandle, 1);
        if (_internalBps.Count == 0 || !_internalBps.Values.Any(bp => bp.Kind == AdKind.CloseHandle))
            TryHook(ntdll, "NtClose", AdKind.CloseHandle, 1);
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

        // Snapshot parent walk: hook kernel32!Process32FirstW / Process32NextW. The packer calls these to
        // walk its own process tree; we override the th32ParentProcessID field on return so it always sees
        // explorer.exe as its parent. Process32FirstW → 2 stdcall args (hSnapshot, out PROCESSENTRY32W);
        // Process32NextW → 2 stdcall args (hSnapshot, out PROCESSENTRY32W). Both return BOOL.
        ulong k32 = ModuleBaseByName("kernel32.dll", Is32);
        if (k32 != 0)
        {
            TryHook(k32, "Process32FirstW", AdKind.Process32First, 2);
            TryHook(k32, "Process32NextW", AdKind.Process32Next, 2);
        }

        Output?.Invoke($"Anti-debug: {_internalBps.Count} hook(s) armed ({(Is32 ? "32-bit" : "64-bit")}; ntdll @ {ntdll:X}).");

        TryInstallWindowHooks();   // user32 is usually already mapped; LOAD_DLL re-tries any later load
    }

    private void TryHook(ulong moduleBase, string export, AdKind kind, int x86Args)
    {
        ulong va = ResolveExport(moduleBase, export);
        if (va == 0) return;
        lock (_lock) if (_internalBps.ContainsKey(va)) return;   // already hooked — idempotent across re-install
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
        // x64 stack args start at [rsp+0x28] (after the return addr + 0x20 of register-home/shadow space), so
        // arg N (N≥5) sits at rsp + N*8; x86 stdcall puts arg N at [esp + N*4] (return addr occupies [esp]).
        ulong Arg(int n) => !Is32
            ? n switch { 1 => c.GetReg("rcx"), 2 => c.GetReg("rdx"), 3 => c.GetReg("r8"), 4 => c.GetReg("r9"), _ => ReadPtr(sp + (ulong)n * 8, false) }
            : ReadU32(sp + (ulong)(n * 4));

        // NtGetContextThread can't be emulated (we don't have the real context). Let it run, then scrub the Dr
        // registers from its output on return — so the program never sees our hardware breakpoints.
        if (bp.Kind == AdKind.GetContextThread)
        {
            ArmReturnBp(ReadPtr(sp, Is32), AdKind.GetContextThread, Arg(2), 0);   // arg2 = PCONTEXT
            LetItRun(addr, tid, c, hThread);
            return;
        }

        // NtQueryObject(handle, ObjectTypesInformation=2nd arg ==3, out buf, len, …): can't be emulated (we don't
        // know the real object table), so run it, then scrub the DebugObject type's counts from its output on
        // return — emulating a system with no live debug object. Other classes pass straight through.
        if (bp.Kind == AdKind.QueryObject)
        {
            if (Arg(2) == 3) ArmReturnBp(ReadPtr(sp, Is32), AdKind.QueryObject, Arg(3), Arg(4));   // arg3 = buffer, arg4 = length
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

        // NtClose(handle): the "close an invalid handle" trick raises STATUS_INVALID_HANDLE only under a
        // debugger. Run it; on return, if the status is 0xC0000008 (INVALID_HANDLE), swallow it by setting
        // eax/rax to 0 (STATUS_SUCCESS) — the no-debugger outcome where closing a bad handle is silent.
        // The per-call overhead is trivial: the function runs, and on return we check one dword.
        if (bp.Kind == AdKind.CloseHandle && Arg(1) is var hVal && hVal != 0)
        {
            ArmReturnBp(ReadPtr(sp, Is32), AdKind.CloseHandle, 0, 0);
            LetItRun(addr, tid, c, hThread);
            return;
        }

        // Process32FirstW(snapshot, out entry) / Process32NextW(snapshot, out entry): run the real function,
        // then on return overwrite only the th32ParentProcessID field in the output PROCESSENTRY32W — so every
        // process in the snapshot walk looks like its parent is explorer.exe (i.e. the debugger is invisible).
        // arg2 = pointer to PROCESSENTRY32W.
        if (bp.Kind is AdKind.Process32First or AdKind.Process32Next && _spoofParentPid != 0)
        {
            ulong entryPtr = Arg(2);
            ArmReturnBp(ReadPtr(sp, Is32), bp.Kind, entryPtr, 0);
            LetItRun(addr, tid, c, hThread);
            return;
        }

        // NtQueryInformationProcess(ProcessBasicInformation): can't emulate (the caller needs the real PEB
        // pointer, etc.), so run it and overwrite only InheritedFromUniqueProcessId on return — the parent PID
        // a packer compares against explorer.exe. arg2 = class (0 == ProcessBasicInformation), arg3 = buffer.
        if (bp.Kind == AdKind.QueryInfoProcess && _spoofParentPid != 0 && Arg(2) == 0)
        {
            ArmReturnBp(ReadPtr(sp, Is32), AdKind.QueryInfoProcessParent, Arg(3), 0);
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
            AdKind.FindWindowW => HookFindWindow(c, Arg, ex: false, wide: true),
            AdKind.FindWindowA => HookFindWindow(c, Arg, ex: false, wide: false),
            AdKind.FindWindowExW => HookFindWindow(c, Arg, ex: true, wide: true),
            AdKind.FindWindowExA => HookFindWindow(c, Arg, ex: true, wide: false),
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
    private void ArmReturnBp(ulong retAddr, AdKind kind, ulong ptr, ulong len)
    {
        // CloseHandle doesn't scrub a buffer (ptr==0 is valid — it patches the return status instead).
        if (retAddr == 0 || (ptr == 0 && kind != AdKind.CloseHandle)) return;
        lock (_lock)
            if (_pendingReturns.ContainsKey(retAddr) || _swBps.ContainsKey(retAddr)
                || _tempBps.ContainsKey(retAddr) || _internalBps.ContainsKey(retAddr)) return;
        var o = ReadMemory(retAddr, 1);
        if (o.Length < 1) return;
        lock (_lock) _pendingReturns[retAddr] = new PendingReturn(kind, ptr, len, o[0]);
        WriteCode(retAddr, [0xCC]);
    }

    /// <summary>At an armed return address: restore the original byte, rewind, and scrub the just-completed
    /// call's output per its kind — the queried CONTEXT's debug registers, or an NtQueryObject result's
    /// DebugObject counts. Handled silently (never surfaced to the UI).</summary>
    private void HandleReturnHook(ulong addr, IntPtr hThread)
    {
        PendingReturn pend;
        lock (_lock) { if (!_pendingReturns.Remove(addr, out pend)) return; }
        WriteCode(addr, [pend.Orig]);
        SetIp(hThread, addr);
        switch (pend.Kind)
        {
            case AdKind.GetContextThread: ScrubDebugRegisters(pend.Ptr); break;
            case AdKind.QueryObject: ScrubDebugObjectCounts(pend.Ptr, pend.Len); break;
            case AdKind.QueryInfoProcessParent: ScrubParentProcessId(pend.Ptr); break;
            case AdKind.CloseHandle: SwallowInvalidHandle(hThread); break;
            case AdKind.Process32First:
            case AdKind.Process32Next: ScrubSnapshotParent(pend.Ptr); break;
        }
    }

    /// <summary>If a just-completed NtClose returned STATUS_INVALID_HANDLE (0xC0000008), overwrite the
    /// return value with STATUS_SUCCESS (0) — the no-debugger behaviour where closing a bad handle is a
    /// silent no-op. This is a direct register patch (no buffer involved), done at the return-patch landing.</summary>
    private void SwallowInvalidHandle(IntPtr hThread)
    {
        using var c = new Ctx(Is32);
        if (!c.Get(hThread)) return;
        ulong eax = c.GetReg(Is32 ? "eax" : "rax");
        if (eax == 0xC0000008) { c.TrySetByName(Is32 ? "eax" : "rax", 0); c.Set(hThread); }
    }

    /// <summary>Overwrite the th32ParentProcessID field at offset 24 (x86/x64) in the PROCESSENTRY32W an
    /// Process32FirstW / Process32NextW just filled in, so the debuggee always sees explorer.exe as its
    /// parent — regardless of which iteration of the snapshot walk returned. FIELD_OFFSET spec in tlhelp32.h;
    /// 0 if the spoof PID hasn't been resolved.</summary>
    private void ScrubSnapshotParent(ulong pe32Ptr)
    {
        if (pe32Ptr == 0 || _spoofParentPid == 0) return;
        const int parentOffX86 = 24, parentOffX64 = 24;   // same offset — the pid field is DWORD in both
        int off = Is32 ? parentOffX86 : parentOffX64;
        WriteU32(pe32Ptr + (ulong)off, _spoofParentPid);
    }

    /// <summary>Zero the Dr0-Dr3/Dr6/Dr7 fields of a CONTEXT a NtGetContextThread call filled in, hiding our
    /// hardware breakpoints from a target that reads its own debug registers.</summary>
    private void ScrubDebugRegisters(ulong ctxPtr)
    {
        if (ctxPtr == 0) return;
        int[] drOff = Is32 ? [0x04, 0x08, 0x0C, 0x10, 0x14, 0x18] : [0x48, 0x50, 0x58, 0x60, 0x68, 0x70];
        var zero = new byte[Is32 ? 4 : 8];
        foreach (int off in drOff) WriteMemory(ctxPtr + (ulong)off, zero);
    }

    /// <summary>Walk the OBJECT_TYPE_INFORMATION array an NtQueryObject(ObjectTypesInformation) call wrote into
    /// the debuggee buffer and zero the "DebugObject" type's TotalNumberOfObjects/Handles — the values a packer
    /// reads to spot a live debug object. A parse miss simply leaves the result unscrubbed; every access is
    /// bounds-checked, so it can never fault the host. The buffer begins with a ULONG count, then pointer-aligned
    /// OBJECT_TYPE_INFORMATION entries, each a UNICODE_STRING TypeName followed inline by its name and counts;
    /// the next entry starts at align(TypeName.Buffer + MaximumLength).</summary>
    private void ScrubDebugObjectCounts(ulong buffer, ulong len)
    {
        if (buffer == 0 || len < 8) return;
        int ptr = Is32 ? 4 : 8;
        int usSize = Is32 ? 8 : 16;                                          // UNICODE_STRING {Length; MaximumLength; Buffer}
        uint count = ReadU32(buffer);                                        // OBJECT_TYPES_INFORMATION.NumberOfTypes
        if (count == 0 || count > 4096) return;
        ulong end = buffer + len;
        ulong entry = (buffer + 4UL + (ulong)ptr - 1) & ~((ulong)ptr - 1);   // first entry: pointer-aligned past the count
        for (uint i = 0; i < count; i++)
        {
            if (entry < buffer || entry + (ulong)usSize + 8 > end) break;
            var us = ReadMemory(entry, usSize);
            if (us.Length < usSize) break;
            ushort nameLen = BitConverter.ToUInt16(us, 0);
            ushort nameMax = BitConverter.ToUInt16(us, 2);
            ulong nameBuf = Is32 ? BitConverter.ToUInt32(us, 4) : BitConverter.ToUInt64(us, 8);
            if (nameBuf != 0 && nameLen is > 0 and <= 1024)
            {
                var nb = ReadMemory(nameBuf, nameLen);
                if (nb.Length == nameLen && System.Text.Encoding.Unicode.GetString(nb) == "DebugObject")
                {
                    WriteU32(entry + (ulong)usSize, 0);       // TotalNumberOfObjects
                    WriteU32(entry + (ulong)usSize + 4, 0);   // TotalNumberOfHandles
                }
            }
            if (nameBuf == 0) break;
            entry = (nameBuf + nameMax + (ulong)ptr - 1) & ~((ulong)ptr - 1);   // next entry follows this name, aligned
        }
    }

    // ---- parent-process spoof ----
    /// <summary>Resolve the PID to report as the debuggee's parent: the explorer.exe in this session (so an
    /// "is my parent explorer?" check passes), else any explorer.exe. Leaves <see cref="_spoofParentPid"/> 0
    /// when spoofing is off or none is found, which disables the patch.</summary>
    private void ResolveSpoofParent()
    {
        _spoofParentPid = 0;
        if (!SpoofParentProcess) return;
        var explorers = System.Diagnostics.Process.GetProcessesByName("explorer");
        try
        {
            int session = System.Diagnostics.Process.GetCurrentProcess().SessionId;
            System.Diagnostics.Process? pick = null;
            foreach (var p in explorers)
            {
                try { if (p.SessionId == session) { pick = p; break; } } catch { /* exited between calls */ }
                pick ??= p;
            }
            if (pick is not null)
            {
                _spoofParentPid = (uint)pick.Id;
                Output?.Invoke($"Anti-debug: parent PID will be spoofed to explorer.exe (PID {_spoofParentPid}).");
            }
        }
        catch { }
        finally { foreach (var p in explorers) p.Dispose(); }
    }

    /// <summary>Overwrite PROCESS_BASIC_INFORMATION.InheritedFromUniqueProcessId in the buffer a just-completed
    /// NtQueryInformationProcess(ProcessBasicInformation) filled in, so the debuggee reads explorer.exe as its
    /// parent rather than the debugger. (PebBaseAddress and the other fields are left intact.)</summary>
    private void ScrubParentProcessId(ulong pbi)
    {
        if (pbi == 0 || _spoofParentPid == 0) return;
        int off = Is32 ? 0x14 : 0x28;   // InheritedFromUniqueProcessId
        WritePtr(pbi + (ulong)off, _spoofParentPid, Is32);
    }

    // ---- window-enumeration defense: FindWindow[Ex][A/W] ----
    /// <summary>Install the FindWindow* hooks once user32 is mapped (idempotent). Called at the loader
    /// breakpoint and again on each LOAD_DLL, so a user32 mapped later (e.g. a packer's runtime LoadLibrary)
    /// is still covered.</summary>
    private void TryInstallWindowHooks()
    {
        if (_windowHooksInstalled) return;
        ulong user32 = ModuleBaseByName("user32.dll", Is32);
        if (user32 == 0) return;
        int before = _internalBps.Count;
        TryHook(user32, "FindWindowW", AdKind.FindWindowW, 2);
        TryHook(user32, "FindWindowA", AdKind.FindWindowA, 2);
        TryHook(user32, "FindWindowExW", AdKind.FindWindowExW, 4);
        TryHook(user32, "FindWindowExA", AdKind.FindWindowExA, 4);
        if (_internalBps.Count > before)
        {
            _windowHooksInstalled = true;
            Output?.Invoke($"Anti-debug: {_internalBps.Count - before} window-enumeration hook(s) armed (user32 @ {user32:X}).");
        }
    }

    /// <summary>Emulate a "not found" (NULL) result when a FindWindow* call looks up a known debugger window
    /// class or title; otherwise pass the call through unchanged. Defeats the common
    /// FindWindow("OLLYDBG"/"x64dbg"/…) detection without disturbing the program's other window lookups.
    /// EnumWindows-style callback enumeration is not filtered (it can't be without trampolining the callback).</summary>
    private bool HookFindWindow(Ctx c, Func<int, ulong> arg, bool ex, bool wide)
    {
        ulong clsPtr = arg(ex ? 3 : 1), namePtr = arg(ex ? 4 : 2);
        if (IsDebuggerWindow(ReadGuestStr(clsPtr, wide)) || IsDebuggerWindow(ReadGuestStr(namePtr, wide)))
        {
            SetRet(c, 0);   // NULL handle: no such window
            return true;
        }
        return false;       // not a debugger window — let the real lookup run
    }

    // Curated debugger/analysis-tool window identities. Classes match exactly (case-insensitive); titles match
    // as a substring (their product name appears in the caption). Extend as needed.
    private static readonly string[] DebuggerWindowClasses =
        ["ollydbg", "windbgframeclass", "id", "zeta debugger", "rock debugger", "obsidiangui", "immunitydebugger"];
    private static readonly string[] DebuggerWindowTitles =
        ["ollydbg", "x64dbg", "x32dbg", "immunity debugger", "windbg", "ida pro", "interactive disassembler", "cheat engine", "process hacker"];

    /// <summary>True if a window class or title names a known debugger / analysis tool.</summary>
    private static bool IsDebuggerWindow(string s)
    {
        if (string.IsNullOrWhiteSpace(s)) return false;
        string t = s.Trim().ToLowerInvariant();
        foreach (var cls in DebuggerWindowClasses) if (t == cls) return true;
        foreach (var p in DebuggerWindowTitles) if (t.Contains(p, StringComparison.Ordinal)) return true;
        return false;
    }

    /// <summary>Read a class/title argument from the debuggee as a C-string. A NULL pointer or a class atom
    /// (a small integer from MAKEINTATOM, not a pointer) reads as empty, so the call passes through.</summary>
    private string ReadGuestStr(ulong ptr, bool wide)
    {
        if (ptr <= 0xFFFF) return "";   // NULL or an ATOM — not a string pointer
        return wide ? ReadWString(ptr) : ReadCString(ptr);
    }

    private string ReadWString(ulong va, int maxChars = 256)
    {
        var b = ReadMemory(va, maxChars * 2);
        int n = 0;
        while (n + 1 < b.Length && (b[n] | b[n + 1]) != 0) n += 2;
        return System.Text.Encoding.Unicode.GetString(b, 0, n);
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

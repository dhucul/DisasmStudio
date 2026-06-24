using System.Runtime.InteropServices;

namespace DisasmStudio.Debug;

/// <summary>
/// Win32 debugging-API interop. The host is x64, so <see cref="DEBUG_EVENT"/> and <see cref="CONTEXT64"/>
/// use 64-bit pointers regardless of the debuggee; 32-bit (WOW64) targets use <see cref="WOW64_CONTEXT"/>
/// via the <c>Wow64*</c> entry points. Everything is guarded by <see cref="OperatingSystem.IsWindows"/>
/// at the call sites, matching the pattern in DisasmStudio.Core's Demangler.
/// </summary>
internal static class Native
{
    // ---- creation / debug control ----
    public const uint DEBUG_ONLY_THIS_PROCESS = 0x00000002;
    public const uint DEBUG_PROCESS = 0x00000001;
    public const uint CREATE_SUSPENDED = 0x00000004;
    public const uint CREATE_NEW_CONSOLE = 0x00000010;
    public const uint CREATE_BREAKAWAY_FROM_JOB = 0x01000000;

    // ---- debug event codes ----
    public const uint EXCEPTION_DEBUG_EVENT = 1;
    public const uint CREATE_THREAD_DEBUG_EVENT = 2;
    public const uint CREATE_PROCESS_DEBUG_EVENT = 3;
    public const uint EXIT_THREAD_DEBUG_EVENT = 4;
    public const uint EXIT_PROCESS_DEBUG_EVENT = 5;
    public const uint LOAD_DLL_DEBUG_EVENT = 6;
    public const uint UNLOAD_DLL_DEBUG_EVENT = 7;
    public const uint OUTPUT_DEBUG_STRING_EVENT = 8;
    public const uint RIP_EVENT = 9;

    // ---- exception codes ----
    public const uint EXCEPTION_BREAKPOINT = 0x80000003;
    public const uint EXCEPTION_SINGLE_STEP = 0x80000004;
    public const uint STATUS_WX86_BREAKPOINT = 0x4000001F;
    public const uint STATUS_WX86_SINGLE_STEP = 0x4000001E;
    public const uint EXCEPTION_ACCESS_VIOLATION = 0xC0000005;
    public const uint STATUS_GUARD_PAGE_VIOLATION = 0x80000001;

    // ---- continue status ----
    public const uint DBG_CONTINUE = 0x00010002;
    public const uint DBG_EXCEPTION_NOT_HANDLED = 0x80010001;

    // ---- context flags ----
    public const uint CONTEXT_AMD64 = 0x00100000;
    public const uint CONTEXT64_ALL = CONTEXT_AMD64 | 0x1 | 0x2 | 0x4 | 0x8 | 0x10; // control|integer|segments|float|debug
    public const uint WOW64_CONTEXT_i386 = 0x00010000;
    public const uint WOW64_CONTEXT_ALL = WOW64_CONTEXT_i386 | 0x1 | 0x2 | 0x4 | 0x8 | 0x10;

    // ---- access / protection ----
    public const uint PROCESS_ALL_ACCESS = 0x001FFFFF;
    public const uint PROCESS_SET_QUOTA = 0x0100;
    public const uint PROCESS_TERMINATE = 0x0001;
    public const uint THREAD_ALL_ACCESS = 0x001FFFFF;
    public const uint PAGE_EXECUTE_READWRITE = 0x40;

    [StructLayout(LayoutKind.Sequential)]
    public struct STARTUPINFO
    {
        public uint cb;
        public IntPtr lpReserved, lpDesktop, lpTitle;
        public uint dwX, dwY, dwXSize, dwYSize, dwXCountChars, dwYCountChars, dwFillAttribute, dwFlags;
        public ushort wShowWindow, cbReserved2;
        public IntPtr lpReserved2, hStdInput, hStdOutput, hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_INFORMATION
    {
        public IntPtr hProcess, hThread;
        public uint dwProcessId, dwThreadId;
    }

    // DEBUG_EVENT: 3-DWORD header then an 8-byte-aligned union (offset 16 on x64). The union's largest
    // member is EXCEPTION_DEBUG_INFO (~160 bytes), so reserve 176 and overlay the members we read.
    [StructLayout(LayoutKind.Explicit, Size = 176)]
    public struct DEBUG_EVENT
    {
        [FieldOffset(0)] public uint dwDebugEventCode;
        [FieldOffset(4)] public uint dwProcessId;
        [FieldOffset(8)] public uint dwThreadId;
        [FieldOffset(16)] public EXCEPTION_DEBUG_INFO Exception;
        [FieldOffset(16)] public CREATE_THREAD_DEBUG_INFO CreateThread;
        [FieldOffset(16)] public CREATE_PROCESS_DEBUG_INFO CreateProcess;
        [FieldOffset(16)] public EXIT_THREAD_DEBUG_INFO ExitThread;
        [FieldOffset(16)] public EXIT_PROCESS_DEBUG_INFO ExitProcess;
        [FieldOffset(16)] public LOAD_DLL_DEBUG_INFO LoadDll;
        [FieldOffset(16)] public UNLOAD_DLL_DEBUG_INFO UnloadDll;
        [FieldOffset(16)] public OUTPUT_DEBUG_STRING_INFO DebugString;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct EXCEPTION_DEBUG_INFO
    {
        public EXCEPTION_RECORD ExceptionRecord;
        public uint dwFirstChance;
    }

    // Full 152 bytes (x64): the ExceptionInformation array has 15 ulong entries, so the struct must be
    // sized correctly or EXCEPTION_DEBUG_INFO.dwFirstChance (which follows it) is read at the wrong offset.
    [StructLayout(LayoutKind.Explicit, Size = 152)]
    public struct EXCEPTION_RECORD
    {
        [FieldOffset(0)] public uint ExceptionCode;
        [FieldOffset(4)] public uint ExceptionFlags;
        [FieldOffset(8)] public ulong ExceptionRecord;
        [FieldOffset(16)] public ulong ExceptionAddress;
        [FieldOffset(24)] public uint NumberParameters;
        [FieldOffset(32)] public ulong Info0;   // ExceptionInformation[0] (e.g. access-violation r/w + watchpoint addr)
        [FieldOffset(40)] public ulong Info1;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct CREATE_PROCESS_DEBUG_INFO
    {
        public IntPtr hFile, hProcess, hThread;
        public ulong lpBaseOfImage;
        public uint dwDebugInfoFileOffset, nDebugInfoSize;
        public ulong lpThreadLocalBase, lpStartAddress, lpImageName;
        public ushort fUnicode;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct CREATE_THREAD_DEBUG_INFO
    {
        public IntPtr hThread;
        public ulong lpThreadLocalBase, lpStartAddress;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct EXIT_THREAD_DEBUG_INFO { public uint dwExitCode; }

    [StructLayout(LayoutKind.Sequential)]
    public struct EXIT_PROCESS_DEBUG_INFO { public uint dwExitCode; }

    [StructLayout(LayoutKind.Sequential)]
    public struct LOAD_DLL_DEBUG_INFO
    {
        public IntPtr hFile;
        public ulong lpBaseOfDll;
        public uint dwDebugInfoFileOffset, nDebugInfoSize;
        public ulong lpImageName;
        public ushort fUnicode;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct UNLOAD_DLL_DEBUG_INFO { public ulong lpBaseOfDll; }

    [StructLayout(LayoutKind.Sequential)]
    public struct OUTPUT_DEBUG_STRING_INFO
    {
        public ulong lpDebugStringData;
        public ushort fUnicode, nDebugStringLength;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct MEMORY_BASIC_INFORMATION
    {
        public ulong BaseAddress;
        public ulong AllocationBase;
        public uint AllocationProtect;
        public uint _align;
        public ulong RegionSize;
        public uint State;
        public uint Protect;
        public uint Type;
        public uint _align2;
    }

    public const uint MEM_COMMIT = 0x1000;
    public const uint PAGE_NOACCESS = 0x01, PAGE_GUARD = 0x100;
    public const uint PAGE_READONLY = 0x02, PAGE_READWRITE = 0x04, PAGE_WRITECOPY = 0x08;
    public const uint PAGE_EXECUTE = 0x10, PAGE_EXECUTE_READ = 0x20, PAGE_EXECUTE_WRITECOPY = 0x80;

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern bool CreateProcessW(string? lpApplicationName, string? lpCommandLine,
        IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags,
        IntPtr lpEnvironment, string? lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool DebugActiveProcess(uint dwProcessId);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool DebugActiveProcessStop(uint dwProcessId);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool DebugSetProcessKillOnExit(bool KillOnExit);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool DebugBreakProcess(IntPtr Process);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool WaitForDebugEvent(out DEBUG_EVENT lpDebugEvent, uint dwMilliseconds);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool ContinueDebugEvent(uint dwProcessId, uint dwThreadId, uint dwContinueStatus);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool ReadProcessMemory(IntPtr hProcess, ulong lpBaseAddress, byte[] lpBuffer, nuint nSize, out nuint lpNumberOfBytesRead);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool WriteProcessMemory(IntPtr hProcess, ulong lpBaseAddress, byte[] lpBuffer, nuint nSize, out nuint lpNumberOfBytesWritten);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool VirtualProtectEx(IntPtr hProcess, ulong lpAddress, nuint dwSize, uint flNewProtect, out uint lpflOldProtect);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern nuint VirtualQueryEx(IntPtr hProcess, ulong lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, nuint dwLength);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool FlushInstructionCache(IntPtr hProcess, ulong lpBaseAddress, nuint dwSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenThread(uint dwDesiredAccess, bool bInheritHandle, uint dwThreadId);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern uint SuspendThread(IntPtr hThread);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern uint ResumeThread(IntPtr hThread);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool GetThreadContext(IntPtr hThread, IntPtr lpContext);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool SetThreadContext(IntPtr hThread, IntPtr lpContext);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool Wow64GetThreadContext(IntPtr hThread, IntPtr lpContext);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool Wow64SetThreadContext(IntPtr hThread, IntPtr lpContext);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool IsWow64Process(IntPtr hProcess, out bool Wow64Process);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool TerminateProcess(IntPtr hProcess, uint uExitCode);

    // STILL_ACTIVE (259) in lpExitCode means the process is still running. Used by the auto-timing dumper to
    // notice a target that exits before its image settles.
    public const uint STILL_ACTIVE = 259;
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool GetExitCodeProcess(IntPtr hProcess, out uint lpExitCode);

    // Best-effort "the GUI has finished starting up and is waiting for input" signal (returns 0 when idle,
    // WAIT_TIMEOUT for busy, WAIT_FAILED for a non-GUI process). One accelerator among the auto-timing signals.
    [DllImport("user32.dll", SetLastError = true)]
    public static extern uint WaitForInputIdle(IntPtr hProcess, uint dwMilliseconds);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "K32GetModuleFileNameExW")]
    public static extern uint GetModuleFileNameEx(IntPtr hProcess, ulong hModule, char[] lpFilename, uint nSize);

    // Enumerate a process's loaded modules (HMODULE == module base). The first entry is the main image.
    // Used by the non-invasive dumper to find the EXE base and the dependency set for IAT reconstruction,
    // without attaching a debugger.
    [DllImport("kernel32.dll", SetLastError = true, EntryPoint = "K32EnumProcessModules")]
    public static extern bool EnumProcessModules(IntPtr hProcess, [Out] IntPtr[] lphModule, uint cb, out uint lpcbNeeded);

    // Toolhelp module snapshot — the only reliable way for this x64 process to enumerate a 32-bit (WOW64)
    // target's *32-bit* modules (EnumProcessModules returns the 64-bit view, whose kernel32 base differs from
    // the one the WOW64 target actually imports through, breaking IAT resolution). TH32CS_SNAPMODULE32 asks for
    // the 32-bit list explicitly. The first module is the main image; modBaseAddr is the 32-bit load base.
    public const uint TH32CS_SNAPMODULE = 0x00000008;
    public const uint TH32CS_SNAPMODULE32 = 0x00000010;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct MODULEENTRY32W
    {
        public uint dwSize;
        public uint th32ModuleID;
        public uint th32ProcessID;
        public uint GlblcntUsage;
        public uint ProccntUsage;
        public IntPtr modBaseAddr;   // BYTE* — 32-bit base zero-extended into the pointer field
        public uint modBaseSize;
        public IntPtr hModule;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)] public string szModule;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string szExePath;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern bool Module32FirstW(IntPtr hSnapshot, ref MODULEENTRY32W lpme);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern bool Module32NextW(IntPtr hSnapshot, ref MODULEENTRY32W lpme);

    // Resolve a path from a file handle — reliable at LOAD_DLL time (when GetModuleFileNameEx often isn't,
    // since the loader hasn't yet registered the module). dwFlags 0 = FILE_NAME_NORMALIZED | VOLUME_NAME_DOS.
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern uint GetFinalPathNameByHandleW(IntPtr hFile, char[] lpszFilePath, uint cchFilePath, uint dwFlags);

    // File-identity match for a hosted DLL: two handles refer to the same file iff their
    // (dwVolumeSerialNumber, nFileIndexHigh, nFileIndexLow) match — immune to casing / 8.3 / subst / symlink
    // and to a same-named DLL loaded from a different directory.
    public const uint FILE_READ_ATTRIBUTES = 0x80;
    public const uint FILE_SHARE_READ = 0x1, FILE_SHARE_WRITE = 0x2, FILE_SHARE_DELETE = 0x4;
    public const uint OPEN_EXISTING = 3;
    public static readonly IntPtr INVALID_HANDLE_VALUE = new(-1);

    [StructLayout(LayoutKind.Sequential)]
    public struct BY_HANDLE_FILE_INFORMATION
    {
        public uint dwFileAttributes;
        public uint ftCreationLow, ftCreationHigh;
        public uint ftLastAccessLow, ftLastAccessHigh;
        public uint ftLastWriteLow, ftLastWriteHigh;
        public uint dwVolumeSerialNumber;
        public uint nFileSizeHigh, nFileSizeLow;
        public uint nNumberOfLinks;
        public uint nFileIndexHigh, nFileIndexLow;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool GetFileInformationByHandle(IntPtr hFile, out BY_HANDLE_FILE_INFORMATION info);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern IntPtr CreateFileW(string lpFileName, uint dwDesiredAccess, uint dwShareMode,
        IntPtr lpSecurityAttributes, uint dwCreationDisposition, uint dwFlagsAndAttributes, IntPtr hTemplateFile);

    // ---- job object containment (limited sandbox: kill-on-close + block child processes) ----
    public const int JobObjectExtendedLimitInformation = 9;
    public const uint JOB_OBJECT_LIMIT_ACTIVE_PROCESS = 0x00000008;
    public const uint JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000;

    [StructLayout(LayoutKind.Sequential)]
    public struct JOBOBJECT_BASIC_LIMIT_INFORMATION
    {
        public long PerProcessUserTimeLimit, PerJobUserTimeLimit;
        public uint LimitFlags;
        public nuint MinimumWorkingSetSize, MaximumWorkingSetSize;
        public uint ActiveProcessLimit;
        public nuint Affinity;
        public uint PriorityClass, SchedulingClass;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct IO_COUNTERS { public ulong ReadOperationCount, WriteOperationCount, OtherOperationCount, ReadTransferCount, WriteTransferCount, OtherTransferCount; }

    [StructLayout(LayoutKind.Sequential)]
    public struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION
    {
        public JOBOBJECT_BASIC_LIMIT_INFORMATION BasicLimitInformation;
        public IO_COUNTERS IoInfo;
        public nuint ProcessMemoryLimit, JobMemoryLimit, PeakProcessMemoryUsed, PeakJobMemoryUsed;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern IntPtr CreateJobObjectW(IntPtr lpJobAttributes, string? lpName);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool SetInformationJobObject(IntPtr hJob, int JobObjectInfoClass, ref JOBOBJECT_EXTENDED_LIMIT_INFORMATION lpJobObjectInfo, uint cbJobObjectInfoLength);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool AssignProcessToJobObject(IntPtr hJob, IntPtr hProcess);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool IsProcessInJob(IntPtr hProcess, IntPtr hJob, out bool result);

    // ---- anti-anti-debug: locate the debuggee PEB (and the 32-bit PEB for WOW64) ----
    public const int ProcessBasicInformation = 0;
    public const int ProcessWow64Information = 26;

    [DllImport("ntdll.dll")]
    public static extern int NtQueryInformationProcess(IntPtr hProcess, int infoClass, IntPtr buffer, uint length, out uint returnLength);

    // Freeze / thaw every thread of a process in one call (needs PROCESS_SUSPEND_RESUME). The non-invasive
    // dumper uses these for a consistent snapshot; unlike DebugActiveProcess they do not make us the target's
    // debugger, so they don't trip a protector's IsDebuggerPresent / debug-port checks.
    [DllImport("ntdll.dll")]
    public static extern int NtSuspendProcess(IntPtr hProcess);
    [DllImport("ntdll.dll")]
    public static extern int NtResumeProcess(IntPtr hProcess);
}

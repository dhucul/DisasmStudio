namespace DisasmStudio.Core.Analysis;

/// <summary>One parameter of an API: its C type, name, and (optionally) a flag-set key whose
/// <see cref="FlagSet"/> decodes its value into symbolic constants (e.g. an access mask → KEY_READ).</summary>
public sealed record ApiParam(string Type, string Name, string? Decode = null);

/// <summary>A Win32 API prototype.</summary>
public sealed record ApiSignature(string Module, string ReturnType, string Name, IReadOnlyList<ApiParam> Params);

/// <summary>
/// A bundled database of common Win32 API prototypes, used to annotate call sites the way IDA Pro and
/// Binary Ninja do — showing parameter names (and resolved values) at each call. Curated toward the
/// APIs that matter for reverse engineering: files, registry, process/thread, memory, networking,
/// crypto, and UI. Lookup tolerates the usual decorations (leading '_', trailing '@N').
/// </summary>
public static class ApiDatabase
{
    private static readonly Dictionary<string, ApiSignature> _byName = new(StringComparer.OrdinalIgnoreCase);

    public static int Count => _byName.Count;

    /// <summary>Find a prototype by imported name, tolerating stdcall/underscore decoration.</summary>
    public static ApiSignature? Lookup(string? name)
    {
        if (string.IsNullOrEmpty(name)) return null;
        if (_byName.TryGetValue(name, out var s)) return s;
        string n = name.TrimStart('_');
        int at = n.IndexOf('@');
        if (at > 0) n = n[..at];                  // strip @N stdcall arg-byte suffix
        return _byName.TryGetValue(n, out s) ? s : null;
    }

    private static ApiParam P(string type, string name) => new(type, name);
    private static ApiParam PA(string type, string name, string flags) => new(type, name, flags);
    private static void Add(string module, string ret, string name, params ApiParam[] ps) => _byName[name] = new ApiSignature(module, ret, name, ps);

    /// <summary>Register both the ANSI (…A) and wide (…W) variants of an API that shares its layout.</summary>
    private static void AddAW(string module, string ret, string baseName, params ApiParam[] ps)
    {
        Add(module, ret, baseName + "A", ps);
        Add(module, ret, baseName + "W", ps);
    }

    static ApiDatabase()
    {
        // ---- kernel32: files ----
        AddAW("kernel32", "HANDLE", "CreateFile",
            P("LPCSTR", "lpFileName"), PA("DWORD", "dwDesiredAccess", "FILE_ACCESS"), PA("DWORD", "dwShareMode", "FILE_SHARE"),
            P("LPSECURITY_ATTRIBUTES", "lpSecurityAttributes"), PA("DWORD", "dwCreationDisposition", "CREATE_DISPOSITION"),
            PA("DWORD", "dwFlagsAndAttributes", "FILE_FLAGS_ATTRS"), P("HANDLE", "hTemplateFile"));
        Add("kernel32", "BOOL", "ReadFile", P("HANDLE", "hFile"), P("LPVOID", "lpBuffer"),
            P("DWORD", "nNumberOfBytesToRead"), P("LPDWORD", "lpNumberOfBytesRead"), P("LPOVERLAPPED", "lpOverlapped"));
        Add("kernel32", "BOOL", "WriteFile", P("HANDLE", "hFile"), P("LPCVOID", "lpBuffer"),
            P("DWORD", "nNumberOfBytesToWrite"), P("LPDWORD", "lpNumberOfBytesWritten"), P("LPOVERLAPPED", "lpOverlapped"));
        Add("kernel32", "BOOL", "CloseHandle", P("HANDLE", "hObject"));
        AddAW("kernel32", "BOOL", "DeleteFile", P("LPCSTR", "lpFileName"));
        AddAW("kernel32", "BOOL", "CopyFile", P("LPCSTR", "lpExistingFileName"), P("LPCSTR", "lpNewFileName"), P("BOOL", "bFailIfExists"));
        AddAW("kernel32", "BOOL", "MoveFile", P("LPCSTR", "lpExistingFileName"), P("LPCSTR", "lpNewFileName"));
        AddAW("kernel32", "BOOL", "CreateDirectory", P("LPCSTR", "lpPathName"), P("LPSECURITY_ATTRIBUTES", "lpSecurityAttributes"));
        AddAW("kernel32", "HANDLE", "FindFirstFile", P("LPCSTR", "lpFileName"), P("LPVOID", "lpFindFileData"));
        Add("kernel32", "HANDLE", "GetStdHandle", P("DWORD", "nStdHandle"));

        // ---- kernel32: modules / process / thread ----
        AddAW("kernel32", "HMODULE", "LoadLibrary", P("LPCSTR", "lpLibFileName"));
        Add("kernel32", "HMODULE", "LoadLibraryExW", P("LPCWSTR", "lpLibFileName"), P("HANDLE", "hFile"), P("DWORD", "dwFlags"));
        AddAW("kernel32", "HMODULE", "GetModuleHandle", P("LPCSTR", "lpModuleName"));
        AddAW("kernel32", "DWORD", "GetModuleFileName", P("HMODULE", "hModule"), P("LPSTR", "lpFilename"), P("DWORD", "nSize"));
        Add("kernel32", "FARPROC", "GetProcAddress", P("HMODULE", "hModule"), P("LPCSTR", "lpProcName"));
        AddAW("kernel32", "BOOL", "CreateProcess",
            P("LPCSTR", "lpApplicationName"), P("LPSTR", "lpCommandLine"), P("LPSECURITY_ATTRIBUTES", "lpProcessAttributes"),
            P("LPSECURITY_ATTRIBUTES", "lpThreadAttributes"), P("BOOL", "bInheritHandles"), P("DWORD", "dwCreationFlags"),
            P("LPVOID", "lpEnvironment"), P("LPCSTR", "lpCurrentDirectory"), P("LPVOID", "lpStartupInfo"), P("LPVOID", "lpProcessInformation"));
        Add("kernel32", "UINT", "WinExec", P("LPCSTR", "lpCmdLine"), P("UINT", "uCmdShow"));
        Add("kernel32", "HANDLE", "OpenProcess", PA("DWORD", "dwDesiredAccess", "PROCESS_ACCESS"), P("BOOL", "bInheritHandle"), P("DWORD", "dwProcessId"));
        Add("kernel32", "HANDLE", "CreateThread", P("LPVOID", "lpThreadAttributes"), P("SIZE_T", "dwStackSize"),
            P("LPVOID", "lpStartAddress"), P("LPVOID", "lpParameter"), P("DWORD", "dwCreationFlags"), P("LPDWORD", "lpThreadId"));
        Add("kernel32", "HANDLE", "CreateRemoteThread", P("HANDLE", "hProcess"), P("LPVOID", "lpThreadAttributes"),
            P("SIZE_T", "dwStackSize"), P("LPVOID", "lpStartAddress"), P("LPVOID", "lpParameter"), P("DWORD", "dwCreationFlags"), P("LPDWORD", "lpThreadId"));
        Add("kernel32", "BOOL", "WriteProcessMemory", P("HANDLE", "hProcess"), P("LPVOID", "lpBaseAddress"),
            P("LPCVOID", "lpBuffer"), P("SIZE_T", "nSize"), P("SIZE_T*", "lpNumberOfBytesWritten"));
        Add("kernel32", "BOOL", "ReadProcessMemory", P("HANDLE", "hProcess"), P("LPCVOID", "lpBaseAddress"),
            P("LPVOID", "lpBuffer"), P("SIZE_T", "nSize"), P("SIZE_T*", "lpNumberOfBytesRead"));
        Add("kernel32", "BOOL", "TerminateProcess", P("HANDLE", "hProcess"), P("UINT", "uExitCode"));
        Add("kernel32", "HANDLE", "GetCurrentProcess");
        Add("kernel32", "DWORD", "GetCurrentProcessId");
        Add("kernel32", "void", "ExitProcess", P("UINT", "uExitCode"));
        Add("kernel32", "DWORD", "WaitForSingleObject", P("HANDLE", "hHandle"), P("DWORD", "dwMilliseconds"));
        Add("kernel32", "void", "Sleep", P("DWORD", "dwMilliseconds"));
        AddAW("kernel32", "HANDLE", "CreateMutex", P("LPVOID", "lpMutexAttributes"), P("BOOL", "bInitialOwner"), P("LPCSTR", "lpName"));

        // ---- kernel32: memory ----
        Add("kernel32", "LPVOID", "VirtualAlloc", P("LPVOID", "lpAddress"), P("SIZE_T", "dwSize"), PA("DWORD", "flAllocationType", "MEM_ALLOC"), PA("DWORD", "flProtect", "PAGE"));
        Add("kernel32", "LPVOID", "VirtualAllocEx", P("HANDLE", "hProcess"), P("LPVOID", "lpAddress"), P("SIZE_T", "dwSize"), PA("DWORD", "flAllocationType", "MEM_ALLOC"), PA("DWORD", "flProtect", "PAGE"));
        Add("kernel32", "BOOL", "VirtualProtect", P("LPVOID", "lpAddress"), P("SIZE_T", "dwSize"), PA("DWORD", "flNewProtect", "PAGE"), P("PDWORD", "lpflOldProtect"));
        Add("kernel32", "BOOL", "VirtualFree", P("LPVOID", "lpAddress"), P("SIZE_T", "dwSize"), P("DWORD", "dwFreeType"));
        Add("kernel32", "HANDLE", "GetProcessHeap");
        Add("kernel32", "LPVOID", "HeapAlloc", P("HANDLE", "hHeap"), P("DWORD", "dwFlags"), P("SIZE_T", "dwBytes"));
        Add("kernel32", "BOOL", "HeapFree", P("HANDLE", "hHeap"), P("DWORD", "dwFlags"), P("LPVOID", "lpMem"));

        // ---- kernel32: misc / anti-analysis ----
        Add("kernel32", "DWORD", "GetLastError");
        Add("kernel32", "DWORD", "GetTickCount");
        Add("kernel32", "BOOL", "IsDebuggerPresent");
        Add("kernel32", "BOOL", "CheckRemoteDebuggerPresent", P("HANDLE", "hProcess"), P("PBOOL", "pbDebuggerPresent"));
        AddAW("kernel32", "void", "OutputDebugString", P("LPCSTR", "lpOutputString"));
        AddAW("kernel32", "DWORD", "GetEnvironmentVariable", P("LPCSTR", "lpName"), P("LPSTR", "lpBuffer"), P("DWORD", "nSize"));
        Add("kernel32", "int", "MultiByteToWideChar", P("UINT", "CodePage"), P("DWORD", "dwFlags"), P("LPCSTR", "lpMultiByteStr"),
            P("int", "cbMultiByte"), P("LPWSTR", "lpWideCharStr"), P("int", "cchWideChar"));

        // ---- user32 ----
        AddAW("user32", "int", "MessageBox", P("HWND", "hWnd"), P("LPCSTR", "lpText"), P("LPCSTR", "lpCaption"), P("UINT", "uType"));
        AddAW("user32", "HWND", "FindWindow", P("LPCSTR", "lpClassName"), P("LPCSTR", "lpWindowName"));
        AddAW("user32", "LRESULT", "SendMessage", P("HWND", "hWnd"), P("UINT", "Msg"), P("WPARAM", "wParam"), P("LPARAM", "lParam"));
        AddAW("user32", "BOOL", "PostMessage", P("HWND", "hWnd"), P("UINT", "Msg"), P("WPARAM", "wParam"), P("LPARAM", "lParam"));
        Add("user32", "BOOL", "ShowWindow", P("HWND", "hWnd"), P("int", "nCmdShow"));
        AddAW("user32", "int", "wsprintf", P("LPSTR", "lpOut"), P("LPCSTR", "lpFmt"));
        Add("user32", "SHORT", "GetAsyncKeyState", P("int", "vKey"));
        Add("user32", "HHOOK", "SetWindowsHookExW", P("int", "idHook"), P("HOOKPROC", "lpfn"), P("HINSTANCE", "hmod"), P("DWORD", "dwThreadId"));

        // ---- advapi32 ----
        AddAW("advapi32", "LONG", "RegOpenKeyEx", P("HKEY", "hKey"), P("LPCSTR", "lpSubKey"), P("DWORD", "ulOptions"), PA("REGSAM", "samDesired", "REGSAM"), P("PHKEY", "phkResult"));
        AddAW("advapi32", "LONG", "RegQueryValueEx", P("HKEY", "hKey"), P("LPCSTR", "lpValueName"), P("LPDWORD", "lpReserved"),
            P("LPDWORD", "lpType"), P("LPBYTE", "lpData"), P("LPDWORD", "lpcbData"));
        AddAW("advapi32", "LONG", "RegSetValueEx", P("HKEY", "hKey"), P("LPCSTR", "lpValueName"), P("DWORD", "Reserved"),
            P("DWORD", "dwType"), P("const BYTE*", "lpData"), P("DWORD", "cbData"));
        AddAW("advapi32", "LONG", "RegCreateKeyEx", P("HKEY", "hKey"), P("LPCSTR", "lpSubKey"), P("DWORD", "Reserved"),
            P("LPSTR", "lpClass"), P("DWORD", "dwOptions"), PA("REGSAM", "samDesired", "REGSAM"), P("LPVOID", "lpSecurityAttributes"),
            P("PHKEY", "phkResult"), P("LPDWORD", "lpdwDisposition"));
        Add("advapi32", "LONG", "RegCloseKey", P("HKEY", "hKey"));
        Add("advapi32", "BOOL", "OpenProcessToken", P("HANDLE", "ProcessHandle"), PA("DWORD", "DesiredAccess", "TOKEN_ACCESS"), P("PHANDLE", "TokenHandle"));
        AddAW("advapi32", "BOOL", "LookupPrivilegeValue", P("LPCSTR", "lpSystemName"), P("LPCSTR", "lpName"), P("PLUID", "lpLuid"));
        AddAW("advapi32", "SC_HANDLE", "OpenSCManager", P("LPCSTR", "lpMachineName"), P("LPCSTR", "lpDatabaseName"), P("DWORD", "dwDesiredAccess"));
        Add("advapi32", "BOOL", "CryptAcquireContextW", P("HCRYPTPROV*", "phProv"), P("LPCWSTR", "szContainer"),
            P("LPCWSTR", "szProvider"), P("DWORD", "dwProvType"), P("DWORD", "dwFlags"));

        // ---- ws2_32 / wininet / urlmon ----
        Add("ws2_32", "int", "WSAStartup", P("WORD", "wVersionRequested"), P("LPVOID", "lpWSAData"));
        Add("ws2_32", "SOCKET", "socket", P("int", "af"), P("int", "type"), P("int", "protocol"));
        Add("ws2_32", "int", "connect", P("SOCKET", "s"), P("const sockaddr*", "name"), P("int", "namelen"));
        Add("ws2_32", "int", "send", P("SOCKET", "s"), P("const char*", "buf"), P("int", "len"), P("int", "flags"));
        Add("ws2_32", "int", "recv", P("SOCKET", "s"), P("char*", "buf"), P("int", "len"), P("int", "flags"));
        Add("ws2_32", "int", "bind", P("SOCKET", "s"), P("const sockaddr*", "name"), P("int", "namelen"));
        Add("ws2_32", "int", "listen", P("SOCKET", "s"), P("int", "backlog"));
        Add("ws2_32", "u_short", "htons", P("u_short", "hostshort"));
        Add("ws2_32", "unsigned long", "inet_addr", P("const char*", "cp"));
        AddAW("wininet", "HINTERNET", "InternetOpen", P("LPCSTR", "lpszAgent"), P("DWORD", "dwAccessType"),
            P("LPCSTR", "lpszProxy"), P("LPCSTR", "lpszProxyBypass"), P("DWORD", "dwFlags"));
        AddAW("wininet", "HINTERNET", "InternetOpenUrl", P("HINTERNET", "hInternet"), P("LPCSTR", "lpszUrl"),
            P("LPCSTR", "lpszHeaders"), P("DWORD", "dwHeadersLength"), P("DWORD", "dwFlags"), P("DWORD_PTR", "dwContext"));
        Add("wininet", "BOOL", "InternetReadFile", P("HINTERNET", "hFile"), P("LPVOID", "lpBuffer"),
            P("DWORD", "dwNumberOfBytesToRead"), P("LPDWORD", "lpdwNumberOfBytesRead"));
        AddAW("urlmon", "HRESULT", "URLDownloadToFile", P("LPUNKNOWN", "pCaller"), P("LPCSTR", "szURL"),
            P("LPCSTR", "szFileName"), P("DWORD", "dwReserved"), P("LPVOID", "lpfnCB"));

        // ---- ntdll / shell32 / ole32 ----
        Add("ntdll", "NTSTATUS", "NtAllocateVirtualMemory", P("HANDLE", "ProcessHandle"), P("PVOID*", "BaseAddress"),
            P("ULONG_PTR", "ZeroBits"), P("PSIZE_T", "RegionSize"), P("ULONG", "AllocationType"), P("ULONG", "Protect"));
        Add("ntdll", "NTSTATUS", "NtProtectVirtualMemory", P("HANDLE", "ProcessHandle"), P("PVOID*", "BaseAddress"),
            P("PSIZE_T", "RegionSize"), P("ULONG", "NewProtect"), P("PULONG", "OldProtect"));
        Add("ntdll", "void", "RtlMoveMemory", P("void*", "Destination"), P("const void*", "Source"), P("SIZE_T", "Length"));
        AddAW("shell32", "HINSTANCE", "ShellExecute", P("HWND", "hwnd"), P("LPCSTR", "lpOperation"), P("LPCSTR", "lpFile"),
            P("LPCSTR", "lpParameters"), P("LPCSTR", "lpDirectory"), P("INT", "nShowCmd"));
        Add("ole32", "HRESULT", "CoCreateInstance", P("REFCLSID", "rclsid"), P("LPUNKNOWN", "pUnkOuter"),
            P("DWORD", "dwClsContext"), P("REFIID", "riid"), P("LPVOID*", "ppv"));
        Add("ole32", "HRESULT", "CoInitializeEx", P("LPVOID", "pvReserved"), P("DWORD", "dwCoInit"));
    }
}
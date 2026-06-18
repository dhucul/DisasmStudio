namespace DisasmStudio.Core.Analysis;

/// <summary>
/// A named set of bit flags (or an enum) that decodes an integer argument into symbolic names —
/// e.g. an access mask <c>0x20019</c> → <c>KEY_READ</c>, or <c>0x10001</c> →
/// <c>DELETE|FILE_READ_DATA</c>. Composite values (higher-valued, like KEY_READ or FILE_ALL_ACCESS)
/// are matched before their component bits, so the output reads the way a developer wrote it.
/// </summary>
public sealed class FlagSet
{
    private readonly (ulong Value, string Name)[] _entries; // sorted by value descending
    private readonly bool _isEnum;

    public FlagSet(bool isEnum, params (ulong, string)[] entries)
    {
        _isEnum = isEnum;
        _entries = entries.OrderByDescending(e => e.Item1).ToArray();
    }

    public string Decode(ulong v)
    {
        if (_isEnum)
        {
            foreach (var (val, name) in _entries) if (val == v) return name;
            return $"0x{v:X}";
        }

        if (v == 0) return "0";
        // Entries are value-descending, so composites (KEY_READ, FILE_ALL_ACCESS) and high-bit
        // generic rights are matched/emitted first — the form these masks are usually written in.
        var parts = new List<string>();
        ulong rem = v;
        foreach (var (val, name) in _entries)
            if (val != 0 && (rem & val) == val) { parts.Add(name); rem &= ~val; }
        if (rem != 0) parts.Add($"0x{rem:X}");
        return parts.Count == 0 ? $"0x{v:X}" : string.Join("|", parts);
    }
}

/// <summary>Maps a parameter's flag-set key (set in <see cref="ApiDatabase"/>) to its <see cref="FlagSet"/>.</summary>
public static class FlagDecoder
{
    public static FlagSet? For(string? key) => key is not null && _sets.TryGetValue(key, out var s) ? s : null;

    // Generic + standard rights shared by every access-mask context.
    private static readonly (ulong, string)[] Generic =
    [
        (0x80000000, "GENERIC_READ"), (0x40000000, "GENERIC_WRITE"), (0x20000000, "GENERIC_EXECUTE"),
        (0x10000000, "GENERIC_ALL"), (0x02000000, "MAXIMUM_ALLOWED"), (0x01000000, "ACCESS_SYSTEM_SECURITY"),
        (0x00100000, "SYNCHRONIZE"), (0x00080000, "WRITE_OWNER"), (0x00040000, "WRITE_DAC"),
        (0x00020000, "READ_CONTROL"), (0x00010000, "DELETE"),
    ];

    private static FlagSet Access(params (ulong, string)[] specific) => new(false, [.. Generic, .. specific]);

    private static readonly Dictionary<string, FlagSet> _sets = new()
    {
        ["FILE_ACCESS"] = Access(
            (0x1F01FF, "FILE_ALL_ACCESS"), (0x120089, "FILE_GENERIC_READ"), (0x120116, "FILE_GENERIC_WRITE"),
            (0x1200A0, "FILE_GENERIC_EXECUTE"),
            (0x0001, "FILE_READ_DATA"), (0x0002, "FILE_WRITE_DATA"), (0x0004, "FILE_APPEND_DATA"),
            (0x0008, "FILE_READ_EA"), (0x0010, "FILE_WRITE_EA"), (0x0020, "FILE_EXECUTE"),
            (0x0040, "FILE_DELETE_CHILD"), (0x0080, "FILE_READ_ATTRIBUTES"), (0x0100, "FILE_WRITE_ATTRIBUTES")),

        ["PROCESS_ACCESS"] = Access(
            (0x1FFFFF, "PROCESS_ALL_ACCESS"),
            (0x0001, "PROCESS_TERMINATE"), (0x0002, "PROCESS_CREATE_THREAD"), (0x0004, "PROCESS_SET_SESSIONID"),
            (0x0008, "PROCESS_VM_OPERATION"), (0x0010, "PROCESS_VM_READ"), (0x0020, "PROCESS_VM_WRITE"),
            (0x0040, "PROCESS_DUP_HANDLE"), (0x0080, "PROCESS_CREATE_PROCESS"), (0x0100, "PROCESS_SET_QUOTA"),
            (0x0200, "PROCESS_SET_INFORMATION"), (0x0400, "PROCESS_QUERY_INFORMATION"),
            (0x0800, "PROCESS_SUSPEND_RESUME"), (0x1000, "PROCESS_QUERY_LIMITED_INFORMATION")),

        ["REGSAM"] = Access(
            (0xF003F, "KEY_ALL_ACCESS"), (0x20019, "KEY_READ"), (0x20006, "KEY_WRITE"),
            (0x0001, "KEY_QUERY_VALUE"), (0x0002, "KEY_SET_VALUE"), (0x0004, "KEY_CREATE_SUB_KEY"),
            (0x0008, "KEY_ENUMERATE_SUB_KEYS"), (0x0010, "KEY_NOTIFY"), (0x0020, "KEY_CREATE_LINK"),
            (0x0100, "KEY_WOW64_64KEY"), (0x0200, "KEY_WOW64_32KEY")),

        ["TOKEN_ACCESS"] = Access(
            (0xF01FF, "TOKEN_ALL_ACCESS"), (0x20008, "TOKEN_READ"), (0x200E0, "TOKEN_WRITE"),
            (0x0001, "TOKEN_ASSIGN_PRIMARY"), (0x0002, "TOKEN_DUPLICATE"), (0x0004, "TOKEN_IMPERSONATE"),
            (0x0008, "TOKEN_QUERY"), (0x0010, "TOKEN_QUERY_SOURCE"), (0x0020, "TOKEN_ADJUST_PRIVILEGES"),
            (0x0040, "TOKEN_ADJUST_GROUPS"), (0x0080, "TOKEN_ADJUST_DEFAULT"), (0x0100, "TOKEN_ADJUST_SESSIONID")),

        ["FILE_MAP"] = new FlagSet(false,
            (0xF001F, "FILE_MAP_ALL_ACCESS"), (0x0001, "FILE_MAP_COPY"), (0x0002, "FILE_MAP_WRITE"),
            (0x0004, "FILE_MAP_READ"), (0x0020, "FILE_MAP_EXECUTE")),

        // CreateFile dwShareMode (0 = exclusive).
        ["FILE_SHARE"] = new FlagSet(false,
            (0x1, "FILE_SHARE_READ"), (0x2, "FILE_SHARE_WRITE"), (0x4, "FILE_SHARE_DELETE")),

        // CreateFile dwCreationDisposition — an enum (exact value).
        ["CREATE_DISPOSITION"] = new FlagSet(true,
            (1, "CREATE_NEW"), (2, "CREATE_ALWAYS"), (3, "OPEN_EXISTING"), (4, "OPEN_ALWAYS"), (5, "TRUNCATE_EXISTING")),

        // Page protection — a base protection (distinct low bit) optionally OR'd with modifiers.
        ["PAGE"] = new FlagSet(false,
            (0x01, "PAGE_NOACCESS"), (0x02, "PAGE_READONLY"), (0x04, "PAGE_READWRITE"), (0x08, "PAGE_WRITECOPY"),
            (0x10, "PAGE_EXECUTE"), (0x20, "PAGE_EXECUTE_READ"), (0x40, "PAGE_EXECUTE_READWRITE"),
            (0x80, "PAGE_EXECUTE_WRITECOPY"), (0x100, "PAGE_GUARD"), (0x200, "PAGE_NOCACHE"), (0x400, "PAGE_WRITECOMBINE")),

        // VirtualAlloc flAllocationType.
        ["MEM_ALLOC"] = new FlagSet(false,
            (0x00001000, "MEM_COMMIT"), (0x00002000, "MEM_RESERVE"), (0x00080000, "MEM_RESET"),
            (0x00100000, "MEM_TOP_DOWN"), (0x00200000, "MEM_WRITE_WATCH"), (0x00400000, "MEM_PHYSICAL"),
            (0x01000000, "MEM_RESET_UNDO"), (0x20000000, "MEM_LARGE_PAGES")),

        // CreateFile dwFlagsAndAttributes: FILE_ATTRIBUTE_* (low bits) | FILE_FLAG_* (high bits).
        // One meaning per bit — for the 0x80000–0x400000 range where attribute and flag definitions
        // overlap, the FILE_FLAG_* meaning (what CreateFile actually consumes there) is used.
        ["FILE_FLAGS_ATTRS"] = new FlagSet(false,
            (0x00000001, "FILE_ATTRIBUTE_READONLY"), (0x00000002, "FILE_ATTRIBUTE_HIDDEN"),
            (0x00000004, "FILE_ATTRIBUTE_SYSTEM"), (0x00000010, "FILE_ATTRIBUTE_DIRECTORY"),
            (0x00000020, "FILE_ATTRIBUTE_ARCHIVE"), (0x00000040, "FILE_ATTRIBUTE_DEVICE"),
            (0x00000080, "FILE_ATTRIBUTE_NORMAL"), (0x00000100, "FILE_ATTRIBUTE_TEMPORARY"),
            (0x00000200, "FILE_ATTRIBUTE_SPARSE_FILE"), (0x00000400, "FILE_ATTRIBUTE_REPARSE_POINT"),
            (0x00000800, "FILE_ATTRIBUTE_COMPRESSED"), (0x00001000, "FILE_ATTRIBUTE_OFFLINE"),
            (0x00002000, "FILE_ATTRIBUTE_NOT_CONTENT_INDEXED"), (0x00004000, "FILE_ATTRIBUTE_ENCRYPTED"),
            (0x00008000, "FILE_ATTRIBUTE_INTEGRITY_STREAM"),
            (0x00080000, "FILE_FLAG_FIRST_PIPE_INSTANCE"), (0x00100000, "FILE_FLAG_OPEN_NO_RECALL"),
            (0x00200000, "FILE_FLAG_OPEN_REPARSE_POINT"), (0x00800000, "FILE_FLAG_SESSION_AWARE"),
            (0x01000000, "FILE_FLAG_POSIX_SEMANTICS"), (0x02000000, "FILE_FLAG_BACKUP_SEMANTICS"),
            (0x04000000, "FILE_FLAG_DELETE_ON_CLOSE"), (0x08000000, "FILE_FLAG_SEQUENTIAL_SCAN"),
            (0x10000000, "FILE_FLAG_RANDOM_ACCESS"), (0x20000000, "FILE_FLAG_NO_BUFFERING"),
            (0x40000000, "FILE_FLAG_OVERLAPPED"), (0x80000000, "FILE_FLAG_WRITE_THROUGH")),
    };
}

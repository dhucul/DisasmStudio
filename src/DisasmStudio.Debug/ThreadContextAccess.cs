using System.Runtime.InteropServices;

namespace DisasmStudio.Debug;

/// <summary>A snapshot of a thread's registers (general + IP/SP/flags + segments), low to high.</summary>
public sealed class RegisterSet
{
    public required bool Is32 { get; init; }
    public List<(string Name, ulong Value)> Items { get; } = [];
    private readonly Dictionary<string, ulong> _map = new(StringComparer.OrdinalIgnoreCase);

    public void Add(string name, ulong v) { Items.Add((name, v)); _map[name] = v; }
    public ulong this[string name] => _map.TryGetValue(name, out var v) ? v : 0;
    public ulong Ip => this[Is32 ? "eip" : "rip"];
    public ulong Sp => this[Is32 ? "esp" : "rsp"];
}

/// <summary>
/// An aligned native <c>CONTEXT</c> (x64) or <c>WOW64_CONTEXT</c> (x86) buffer with typed field access.
/// The x64 CONTEXT must be 16-byte aligned for <c>GetThreadContext</c>, so the buffer is allocated with
/// <see cref="NativeMemory.AlignedAlloc"/>. Reads/writes go through <see cref="Marshal"/> at fixed offsets.
/// </summary>
internal sealed unsafe class Ctx : IDisposable
{
    public readonly bool Is32;
    private readonly nint _p;
    private readonly int _size;
    private readonly uint _flags;

    // x64 field offsets within CONTEXT.
    private static readonly (string Name, int Off, int Bytes)[] Regs64 =
    [
        ("rax", 0x78, 8), ("rbx", 0x90, 8), ("rcx", 0x80, 8), ("rdx", 0x88, 8),
        ("rsi", 0xA8, 8), ("rdi", 0xB0, 8), ("rbp", 0xA0, 8), ("rsp", 0x98, 8),
        ("r8", 0xB8, 8), ("r9", 0xC0, 8), ("r10", 0xC8, 8), ("r11", 0xD0, 8),
        ("r12", 0xD8, 8), ("r13", 0xE0, 8), ("r14", 0xE8, 8), ("r15", 0xF0, 8),
        ("rip", 0xF8, 8), ("rflags", 0x44, 4),
        ("cs", 0x38, 2), ("ds", 0x3A, 2), ("es", 0x3C, 2), ("fs", 0x3E, 2), ("gs", 0x40, 2), ("ss", 0x42, 2),
    ];
    private static readonly (string Name, int Off, int Bytes)[] Regs32 =
    [
        ("eax", 0xB0, 4), ("ebx", 0xA4, 4), ("ecx", 0xAC, 4), ("edx", 0xA8, 4),
        ("esi", 0xA0, 4), ("edi", 0x9C, 4), ("ebp", 0xB4, 4), ("esp", 0xC4, 4),
        ("eip", 0xB8, 4), ("eflags", 0xC0, 4),
        ("cs", 0xBC, 4), ("ds", 0x98, 4), ("es", 0x94, 4), ("fs", 0x90, 4), ("gs", 0x8C, 4), ("ss", 0xC8, 4),
    ];

    private int FlagsOff => Is32 ? 0x00 : 0x30;
    private int EFlagsOff => Is32 ? 0xC0 : 0x44;
    private static readonly int[] DrOff64 = [0x48, 0x50, 0x58, 0x60, 0x68, 0x70]; // Dr0..Dr3, Dr6, Dr7
    private static readonly int[] DrOff32 = [0x04, 0x08, 0x0C, 0x10, 0x14, 0x18];
    private int[] DrOff => Is32 ? DrOff32 : DrOff64;

    public Ctx(bool is32)
    {
        Is32 = is32;
        _size = is32 ? 0x2CC : 0x4D0;
        _flags = is32 ? Native.WOW64_CONTEXT_ALL : Native.CONTEXT64_ALL;
        _p = (nint)NativeMemory.AlignedAlloc((nuint)_size, 16);
        NativeMemory.Clear((void*)_p, (nuint)_size);
        Marshal.WriteInt32(_p, FlagsOff, (int)_flags);
    }

    public bool Get(IntPtr hThread)
    {
        Marshal.WriteInt32(_p, FlagsOff, (int)_flags);   // a prior Get/Set may have changed ContextFlags — reset it so a reused buffer still retrieves the full context
        return Is32 ? Native.Wow64GetThreadContext(hThread, _p) : Native.GetThreadContext(hThread, _p);
    }

    public bool Set(IntPtr hThread)
    {
        Marshal.WriteInt32(_p, FlagsOff, (int)_flags);   // GetThreadContext may have cleared/changed it
        return Is32 ? Native.Wow64SetThreadContext(hThread, _p) : Native.SetThreadContext(hThread, _p);
    }

    private ulong ReadField(int off, int bytes) => bytes switch
    {
        8 => (ulong)Marshal.ReadInt64(_p, off),
        4 => (uint)Marshal.ReadInt32(_p, off),
        _ => (ushort)Marshal.ReadInt16(_p, off),
    };

    private void WriteField(int off, int bytes, ulong v)
    {
        switch (bytes)
        {
            case 8: Marshal.WriteInt64(_p, off, (long)v); break;
            case 4: Marshal.WriteInt32(_p, off, (int)(uint)v); break;
            default: Marshal.WriteInt16(_p, off, (short)(ushort)v); break;
        }
    }

    public RegisterSet Snapshot()
    {
        var set = new RegisterSet { Is32 = Is32 };
        foreach (var (name, off, bytes) in Is32 ? Regs32 : Regs64) set.Add(name, ReadField(off, bytes));
        return set;
    }

    public bool TrySetByName(string name, ulong value)
    {
        foreach (var (n, off, bytes) in Is32 ? Regs32 : Regs64)
            if (string.Equals(n, name, StringComparison.OrdinalIgnoreCase)) { WriteField(off, bytes, value); return true; }
        return false;
    }

    /// <summary>Read a named register (0 if unknown). Used by the anti-anti-debug hooks to inspect call args.</summary>
    public ulong GetReg(string name)
    {
        foreach (var (n, off, bytes) in Is32 ? Regs32 : Regs64)
            if (string.Equals(n, name, StringComparison.OrdinalIgnoreCase)) return ReadField(off, bytes);
        return 0;
    }

    public ulong Ip
    {
        get => ReadField(Is32 ? 0xB8 : 0xF8, Is32 ? 4 : 8);
        set => WriteField(Is32 ? 0xB8 : 0xF8, Is32 ? 4 : 8, value);
    }

    public ulong Sp => ReadField(Is32 ? 0xC4 : 0x98, Is32 ? 4 : 8);

    public bool TrapFlag
    {
        get => (Marshal.ReadInt32(_p, EFlagsOff) & 0x100) != 0;
        set { int f = Marshal.ReadInt32(_p, EFlagsOff); f = value ? f | 0x100 : f & ~0x100; Marshal.WriteInt32(_p, EFlagsOff, f); }
    }

    /// <summary>EFlags.RF — set to step past an execute hardware breakpoint at RIP without re-triggering.</summary>
    public bool ResumeFlag
    {
        set { int f = Marshal.ReadInt32(_p, EFlagsOff); f = value ? f | 0x10000 : f & ~0x10000; Marshal.WriteInt32(_p, EFlagsOff, f); }
    }

    public ulong GetDr(int i) => ReadField(DrOff[i], Is32 ? 4 : 8);
    public void SetDr(int i, ulong v) => WriteField(DrOff[i], Is32 ? 4 : 8, v);
    public ulong Dr7 { get => GetDr(5); set => SetDr(5, value); }
    public ulong Dr6 { get => GetDr(4); set => SetDr(4, value); }

    public void Dispose() => NativeMemory.AlignedFree((void*)_p);
}

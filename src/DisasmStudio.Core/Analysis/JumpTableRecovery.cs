using DisasmStudio.Core.Disasm;
using DisasmStudio.Core.Formats;
using Iced.Intel;

namespace DisasmStudio.Core.Analysis;

/// <summary>
/// Recovers the targets of an indirect <c>jmp</c> that dispatches through a jump table (a compiled
/// <c>switch</c>) — statically, by reconstructing the table from the surrounding code and the binary's
/// data rather than from runtime register values. Two forms are handled:
///   • absolute-pointer table — <c>jmp qword/dword ptr [base + idx*scale + disp]</c>, where each entry
///     is a code address (x64 8-byte tables, x86 4-byte tables);
///   • RVA/offset table (the common MSVC x64 form) — <c>mov reg,[tab+idx*4]; add reg, base; jmp reg</c>,
///     where each entry is a 32-bit offset from a base.
/// The table base comes from a preceding <c>lea reg,[rip+x]</c> (or an absolute displacement on x86);
/// the entry count from a preceding <c>cmp idx, N</c> bound check; entries are then read and validated
/// to point into executable memory. When the pattern can't be reconstructed it gives up (returns false),
/// which is the correct answer for true dynamic dispatch (vtables, function pointers).
/// </summary>
public static class JumpTableRecovery
{
    private const int BackWindow = 48;
    private const int MaxEntries = 4096;
    private const int UnknownCap = 256;

    public static bool TryRecover(IBinaryImage image, LinearIndex linear, Disassembler dis, ulong jmpVa, out ulong[] targets)
    {
        targets = [];
        if (!dis.TryDecodeAt(jmpVa, out var jmp) || jmp.FlowControl != FlowControl.IndirectBranch) return false;
        // The back-scans below start from IndexOf(jmpVa) and walk preceding instructions; that's only valid if
        // the jmp is an exact indexed entry (IndexOf otherwise returns the nearest-below line, off by one).
        if (linear.VaAt(linear.IndexOf(jmpVa)) != jmpVa) return false;
        return jmp.Op0Kind switch
        {
            OpKind.Memory => TryMemoryTable(image, linear, dis, jmpVa, jmp, out targets),
            OpKind.Register => TryRvaTable(image, linear, dis, jmpVa, jmp, out targets),
            _ => false,
        };
    }

    // jmp [base + idx*scale + disp] — table of absolute code pointers.
    private static bool TryMemoryTable(IBinaryImage image, LinearIndex linear, Disassembler dis, ulong jmpVa, in Instruction jmp, out ulong[] targets)
    {
        targets = [];
        var idx = jmp.MemoryIndex;
        int scale = jmp.MemoryIndexScale;
        if (idx == Register.None || (scale != 4 && scale != 8)) return false; // need an indexed table

        ulong tableStart;
        var baseReg = jmp.MemoryBase;
        if (baseReg == Register.None)
            tableStart = jmp.MemoryDisplacement64;                          // x86: [idx*scale + table]
        else if (FindLeaRip(linear, dis, jmpVa, baseReg, out ulong baseAddr))
            tableStart = baseAddr + jmp.MemoryDisplacement64;               // x64: [reg + idx*scale + disp]
        else
            return false;

        if (!image.IsMappedVa(tableStart)) return false;
        int count = FindBoundsCount(linear, dis, jmpVa, idx);
        return ReadTable(image, tableStart, scale, baseAddr: 0, isRva: false, count, out targets);
    }

    // mov reg,[tab + idx*4]; add reg, base; jmp reg — table of 32-bit offsets from base (MSVC x64).
    private static bool TryRvaTable(IBinaryImage image, LinearIndex linear, Disassembler dis, ulong jmpVa, in Instruction jmp, out ulong[] targets)
    {
        targets = [];
        Register jreg = Full(jmp.Op0Register);
        Register baseReg = Register.None, tabReg = Register.None, idxReg = Register.None;
        ulong dispT = 0;
        bool haveAdd = false, haveLoad = false;

        long start = linear.IndexOf(jmpVa);
        for (long k = start - 1; k >= 0 && start - k <= BackWindow; k--)
        {
            if (!dis.TryDecodeAt(linear.VaAt(k), out var ins)) break;
            if (ins.FlowControl is FlowControl.Call or FlowControl.IndirectCall or FlowControl.Return) break;

            if (!haveAdd && ins.Mnemonic == Mnemonic.Add && ins.Op0Kind == OpKind.Register
                && Full(ins.Op0Register) == jreg && ins.Op1Kind == OpKind.Register)
            {
                baseReg = Full(ins.Op1Register);
                haveAdd = true;
            }
            else if (haveAdd && !haveLoad && ins.Mnemonic is Mnemonic.Mov or Mnemonic.Movsxd
                && ins.Op0Kind == OpKind.Register && Full(ins.Op0Register) == jreg
                && ins.Op1Kind == OpKind.Memory && ins.MemoryIndex != Register.None && ins.MemoryIndexScale == 4)
            {
                tabReg = ins.MemoryBase == Register.None ? Register.None : Full(ins.MemoryBase);
                idxReg = ins.MemoryIndex;
                dispT = ins.MemoryDisplacement64;
                haveLoad = true;
                if (tabReg == Register.None) break;
            }
        }
        if (!haveAdd || !haveLoad) return false;

        if (!FindLeaRip(linear, dis, jmpVa, baseReg, out ulong baseAddr)) return false;
        ulong tableAddr = baseReg == tabReg ? baseAddr
            : FindLeaRip(linear, dis, jmpVa, tabReg, out ulong ta) ? ta : 0;
        if (tableAddr == 0) return false;

        ulong tableStart = tableAddr + dispT;
        if (!image.IsMappedVa(tableStart)) return false;
        int count = FindBoundsCount(linear, dis, jmpVa, idxReg);
        return ReadTable(image, tableStart, entrySize: 4, baseAddr, isRva: true, count, out targets);
    }

    private static bool ReadTable(IBinaryImage image, ulong tableStart, int entrySize, ulong baseAddr, bool isRva, int count, out ulong[] targets)
    {
        var list = new List<ulong>();
        var seen = new HashSet<ulong>();
        // FindBoundsCount already returns the entry count (N+1 for `cmp idx,N; ja default`), so use it
        // directly — `count + 1` read one entry past the table (a spurious case when the next bytes happen to
        // look like a code address). The IsExecutableVa break below still bounds an unknown/over-large count.
        int limit = count > 0 ? Math.Min(count, MaxEntries) : UnknownCap;
        for (int i = 0; i < limit; i++)
        {
            var b = image.ReadBytesAtVa(tableStart + (ulong)(i * entrySize), entrySize);
            if (b.Length < entrySize) break;
            ulong t = isRva
                ? (ulong)((long)baseAddr + BitConverter.ToInt32(b, 0))       // signed 32-bit offset from base
                : entrySize == 8 ? BitConverter.ToUInt64(b, 0) : BitConverter.ToUInt32(b, 0);
            if (!image.IsExecutableVa(t)) break;                              // first non-code entry ends the table
            if (seen.Add(t)) list.Add(t);
        }
        targets = [.. list];
        return list.Count >= 2;                                              // a 1-target "table" isn't a switch
    }

    /// <summary>Find a preceding <c>lea reg,[rip+x]</c> that sets <paramref name="reg"/>; returns its absolute target.</summary>
    private static bool FindLeaRip(LinearIndex linear, Disassembler dis, ulong fromVa, Register reg, out ulong addr)
    {
        addr = 0;
        Register want = Full(reg);
        long start = linear.IndexOf(fromVa);
        for (long k = start - 1; k >= 0 && start - k <= BackWindow; k--)
        {
            if (!dis.TryDecodeAt(linear.VaAt(k), out var ins)) return false;
            if (ins.FlowControl is FlowControl.Call or FlowControl.IndirectCall or FlowControl.Return) return false;
            if (ins.Op0Kind == OpKind.Register && Full(ins.Op0Register) == want)
            {
                if (ins.Mnemonic == Mnemonic.Lea && ins.IsIPRelativeMemoryOperand) { addr = ins.IPRelativeMemoryAddress; return true; }
                return false; // the register was set by something else first — can't resolve statically
            }
        }
        return false;
    }

    /// <summary>Entry count from a preceding <c>cmp idx, N</c> (assumes <c>ja default</c> ⇒ N+1 entries), or -1.</summary>
    private static int FindBoundsCount(LinearIndex linear, Disassembler dis, ulong fromVa, Register idxReg)
    {
        Register want = Full(idxReg);
        long start = linear.IndexOf(fromVa);
        for (long k = start - 1; k >= 0 && start - k <= BackWindow; k--)
        {
            if (!dis.TryDecodeAt(linear.VaAt(k), out var ins)) break;
            if (ins.FlowControl is FlowControl.Call or FlowControl.IndirectCall or FlowControl.Return) break;
            if (ins.Mnemonic == Mnemonic.Cmp && ins.Op0Kind == OpKind.Register && Full(ins.Op0Register) == want && IsImm(ins.Op1Kind))
            {
                ulong n = ins.GetImmediate(1);
                if (n < MaxEntries) return (int)n + 1;
            }
        }
        return -1;
    }

    private static Register Full(Register r) => r.GetFullRegister();

    private static bool IsImm(OpKind k) => k is OpKind.Immediate8 or OpKind.Immediate8_2nd or OpKind.Immediate16
        or OpKind.Immediate32 or OpKind.Immediate64 or OpKind.Immediate8to16 or OpKind.Immediate8to32
        or OpKind.Immediate8to64 or OpKind.Immediate32to64;
}

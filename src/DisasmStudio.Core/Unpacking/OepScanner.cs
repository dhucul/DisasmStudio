using Iced.Intel;

namespace DisasmStudio.Core.Unpacking;

/// <summary>
/// Best-effort static recovery of the Original Entry Point from an unpacked memory dump. A packer's PE header
/// entry points at its <i>stub</i>; the stub decompresses/decrypts the original image and then transfers to the
/// real OEP with a single far jump (UPX's <c>popad; jmp oep</c>, or <c>push oep; ret</c>, or
/// <c>mov reg, oep; jmp reg</c>). Running a <i>dump</i> from the stub re-runs the stub over already-unpacked
/// bytes and crashes, so producing a runnable rebuild needs the real OEP. This linearly scans the stub for that
/// terminal transfer — the first jump/return to an <b>executable, far, prologue-looking</b> target
/// (<see cref="OepValidator"/>) — and returns it, or 0 if none is found (caller then keeps the stub entry).
/// Best-effort by design: it recovers simple/compressor stubs reliably; a heavily mutated protector stub may
/// not expose a clean tail jump, in which case the debugger-traced unpacker is the right tool.
/// </summary>
public static class OepScanner
{
    private const int StubScanBytes = 0x4000;   // how much of the stub to scan
    private const int MaxInstructions = 6000;
    private const ulong FarThreshold = 0x1000;  // a transfer this far from the stub entry is "leaving the stub"

    /// <summary>Recover the OEP from the dump, or 0 if it can't be found.</summary>
    public static ulong FindOep(MemReader mem, PeView view, ulong imageBase, bool is64)
    {
        if (view.EntryRva == 0) return 0;
        ulong stubEntry = imageBase + view.EntryRva;

        // If the header entry already decodes as a clean function prologue, it IS the OEP — this isn't a packer
        // stub, so don't hunt for a "better" target (which would mis-recover a tail call on a normal binary).
        var entryHead = mem(stubEntry, 32);
        if (entryHead.Length >= 2 && OepValidator.LooksLikeOep(entryHead, is64)) return 0;

        var code = mem(stubEntry, StubScanBytes);
        if (code.Length < 2) return 0;

        var dec = Decoder.Create(is64 ? 64 : 32, new ByteArrayCodeReader(code));
        dec.IP = stubEntry;
        ulong end = stubEntry + (ulong)code.Length;
        int ptr = is64 ? 8 : 4;
        var regs = new Dictionary<Register, ulong>();
        ulong lastPush = 0; bool havePush = false;

        for (int n = 0; n < MaxInstructions && dec.IP < end; n++)
        {
            dec.Decode(out var ins);
            if (ins.IsInvalid) continue;

            switch (ins.Mnemonic)
            {
                case Mnemonic.Mov when ins.Op0Kind == OpKind.Register && IsImm(ins.Op1Kind):
                    regs[ins.Op0Register] = ins.GetImmediate(1);
                    break;

                case Mnemonic.Push when IsImm(ins.Op0Kind):
                    lastPush = ins.GetImmediate(0); havePush = true;
                    break;
                case Mnemonic.Push when ins.Op0Kind == OpKind.Register:
                    havePush = regs.TryGetValue(ins.Op0Register, out lastPush);
                    break;

                case Mnemonic.Ret when havePush:                       // push oep; ret
                    if (Accept(mem, view, imageBase, is64, stubEntry, lastPush)) return lastPush;
                    havePush = false;
                    break;

                case Mnemonic.Jmp:
                    ulong target = ins.Op0Kind switch
                    {
                        OpKind.NearBranch16 or OpKind.NearBranch32 or OpKind.NearBranch64 => ins.NearBranchTarget,
                        OpKind.Register => regs.GetValueOrDefault(ins.Op0Register),
                        OpKind.Memory => DerefJmp(mem, ins, ptr),
                        _ => 0,
                    };
                    if (target != 0 && Accept(mem, view, imageBase, is64, stubEntry, target)) return target;
                    break;
            }
        }
        return 0;
    }

    /// <summary>A candidate OEP is accepted when it is executable, lies well outside the stub, and decodes as a
    /// plausible function entry.</summary>
    private static bool Accept(MemReader mem, PeView view, ulong imageBase, bool is64, ulong stubEntry, ulong target)
    {
        if (target == 0) return false;
        ulong delta = target > stubEntry ? target - stubEntry : stubEntry - target;
        if (delta < FarThreshold) return false;                 // an internal stub jump, not the exit
        if (!IsExecutableVa(view, imageBase, target)) return false;
        var head = mem(target, 32);
        return head.Length >= 2 && OepValidator.LooksLikeOep(head, is64);
    }

    private static ulong DerefJmp(MemReader mem, in Instruction ins, int ptr)
    {
        ulong addr = ins.IsIPRelativeMemoryOperand ? ins.IPRelativeMemoryAddress
            : ins.MemoryBase == Register.None && ins.MemoryIndex == Register.None ? ins.MemoryDisplacement64 : 0;
        if (addr == 0) return 0;
        var p = mem(addr, ptr);
        return p.Length < ptr ? 0 : ptr == 8 ? BitConverter.ToUInt64(p, 0) : BitConverter.ToUInt32(p, 0);
    }

    private static bool IsExecutableVa(PeView view, ulong imageBase, ulong va)
    {
        foreach (var s in view.Sections)
        {
            if (!s.IsExecutable) continue;
            ulong start = imageBase + s.VirtualAddress;
            ulong size = Math.Max(s.VirtualSize, s.SizeOfRawData);
            if (va >= start && va < start + size) return true;
        }
        return false;
    }

    private static bool IsImm(OpKind k) => k is OpKind.Immediate8 or OpKind.Immediate8to16 or OpKind.Immediate8to32
        or OpKind.Immediate8to64 or OpKind.Immediate16 or OpKind.Immediate32 or OpKind.Immediate32to64 or OpKind.Immediate64;
}

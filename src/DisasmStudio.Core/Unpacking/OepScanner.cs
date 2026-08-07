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
    private const ulong FarThreshold = 0x1000;  // a transfer this far from the stub entry is "leaving the stub"

    /// <summary>How far past a candidate to look for the prologue it approaches (see <see cref="RefineToPrologue"/>).</summary>
    private const int MaxRefineInstructions = 8;

    /// <summary>
    /// Snap an OEP candidate forward to the function prologue it approaches.
    /// <para>
    /// A candidate recovered by execution — the section guard breaking on the first instruction fetched inside a
    /// guarded section — is accurate about where execution went, but that is not always the entry point proper:
    /// packers commonly land on a short trampoline, a jump thunk, or alignment padding a few instructions ahead
    /// of the real prologue. That matters beyond cosmetics, because the address is written into the rebuilt
    /// PE's <c>AddressOfEntryPoint</c> and is what seeds naming and function recovery.
    /// </para>
    /// <para>
    /// Conservative by construction: it returns <paramref name="oep"/> unchanged when that already looks like a
    /// prologue, when nothing within a few instructions does, or when decoding runs past
    /// <paramref name="limit"/> — it never invents an entry point that wasn't there.
    /// </para>
    /// </summary>
    /// <param name="limit">Exclusive upper bound (normally the end of the containing section); 0 for none.
    /// A prologue found past the section's end would be a coincidence, not this function's entry.</param>
    public static ulong RefineToPrologue(MemReader mem, ulong oep, bool is64, ulong limit = 0)
    {
        if (oep == 0) return oep;

        // A single snapshot backs both the forward decode and every prologue test. Re-reading per candidate
        // would let the two disagree wherever the target is not frozen — the non-invasive dumper reads a running
        // process by design — and would cost a syscall per step for no benefit. Sized for the longest walk:
        // MaxRefineInstructions at the 15-byte x86 maximum, plus enough tail for the validator to decode the
        // instruction it lands on.
        const int ValidatorWindow = 32;
        var code = mem(oep, MaxRefineInstructions * 15 + ValidatorWindow);
        if (code.Length < 2) return oep;

        // Bytes at `va` as the validator sees them: from the snapshot, never past `limit`, so a candidate near
        // the end of a section is judged on that section's bytes alone.
        byte[] At(ulong va)
        {
            long off = (long)(va - oep);
            if (off < 0 || off >= code.Length) return [];
            int len = (int)Math.Min(ValidatorWindow, code.Length - off);
            if (limit != 0 && va < limit) len = (int)Math.Min(len, (long)(limit - va));
            return len <= 0 ? [] : code.AsSpan((int)off, len).ToArray();
        }

        var head = At(oep);
        if (head.Length >= 2 && OepValidator.LooksLikeOep(head, is64)) return oep;

        var dec = Decoder.Create(is64 ? 64 : 32, new ByteArrayCodeReader(code));
        dec.IP = oep;
        for (int i = 0; i < MaxRefineInstructions; i++)
        {
            dec.Decode(out var insn);
            if (insn.IsInvalid || insn.Length <= 0) break;
            ulong va = dec.IP;                       // start of the next instruction
            if (limit != 0 && va >= limit) break;
            var bytes = At(va);
            if (bytes.Length >= 2 && OepValidator.LooksLikeOep(bytes, is64)) return va;
        }
        return oep;
    }

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

        // Delegate instruction-level tracking to the shared StubInstructionTracker; apply our own acceptance
        // criteria (far threshold, executable section, prologue validation).
        var transfer = StubInstructionTracker.FindFirstTransfer(
            mem, code, stubEntry, is64,
            t => Accept(mem, view, imageBase, is64, stubEntry, t.Target));

        return transfer?.Target ?? 0;
    }

    /// <summary>A candidate OEP is accepted when it is executable, lies well outside the stub, and decodes as a
    /// plausible function entry.</summary>
    public static bool Accept(MemReader mem, PeView view, ulong imageBase, bool is64, ulong stubEntry, ulong target)
    {
        if (target == 0) return false;
        ulong delta = target > stubEntry ? target - stubEntry : stubEntry - target;
        if (delta < FarThreshold) return false;                 // an internal stub jump, not the exit
        if (!IsExecutableVa(view, imageBase, target)) return false;
        var head = mem(target, 32);
        return head.Length >= 2 && OepValidator.LooksLikeOep(head, is64);
    }

    /// <summary>Check whether a VA falls within an executable section of the PE.</summary>
    public static bool IsExecutableVa(PeView view, ulong imageBase, ulong va)
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
}

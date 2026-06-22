using Iced.Intel;

namespace DisasmStudio.Core.Unpacking;

/// <summary>Confidence check for an OEP candidate: do the bytes decode as a plausible function entry /
/// CRT startup? A soft signal — a false result lowers confidence but does not block the dump.</summary>
public static class OepValidator
{
    public static bool LooksLikeOep(byte[] code, bool is64)
    {
        if (code.Length < 2) return false;
        var dec = Iced.Intel.Decoder.Create(is64 ? 64 : 32, new ByteArrayCodeReader(code));
        dec.IP = 0;
        dec.Decode(out var i0);
        if (i0.IsInvalid) return false;

        // mov edi, edi  (hot-patch pad) → look past it
        if (i0.Mnemonic == Mnemonic.Mov && i0.Op0Kind == OpKind.Register && i0.Op1Kind == OpKind.Register
            && i0.Op0Register == i0.Op1Register)
            dec.Decode(out i0);

        // push ebp/rbp [; mov ebp/rbp, esp/rsp]
        if (i0.Mnemonic == Mnemonic.Push && i0.Op0Kind == OpKind.Register
            && i0.Op0Register is Register.EBP or Register.RBP)
            return true;

        // sub esp/rsp, imm  — frame allocation (common x64 prologue)
        if (i0.Mnemonic == Mnemonic.Sub && i0.Op0Kind == OpKind.Register
            && i0.Op0Register is Register.ESP or Register.RSP)
            return true;

        // push <callee-saved reg> — frequent x64 entry start
        if (i0.Mnemonic == Mnemonic.Push && i0.Op0Kind == OpKind.Register)
            return true;

        // mov [rsp+x], reg — x64 home-register save (e.g. mov [rsp+8], rcx)
        if (i0.Mnemonic == Mnemonic.Mov && i0.Op0Kind == OpKind.Memory
            && i0.MemoryBase is Register.RSP or Register.ESP)
            return true;

        // call rel — CRT startup thunk
        if (i0.Mnemonic == Mnemonic.Call && i0.Op0Kind is OpKind.NearBranch32 or OpKind.NearBranch64)
            return true;

        // xor reg, reg — some entrypoints zero a register first
        if (i0.Mnemonic == Mnemonic.Xor && i0.Op0Kind == OpKind.Register && i0.Op0Register == i0.Op1Register)
            return true;

        return false;
    }
}

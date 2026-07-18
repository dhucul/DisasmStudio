using Iced.Intel;

namespace DisasmStudio.Debug;

/// <summary>
/// Resolves the effective address an instruction <b>writes to</b> in memory, from a register snapshot — used by
/// the debugger's "follow writes" feature to scroll the memory views to the location being written while stepping.
/// Only an <b>explicit</b> written memory operand counts: implicit stack traffic (<c>push</c>/<c>pop</c>/<c>call</c>)
/// has no explicit memory operand and so is ignored, keeping the view on real data writes rather than chasing the
/// stack — while genuine writes to locals through <c>[rbp±d]</c>/<c>[rsp+d]</c> (which use the SS segment) are still
/// followed. Pure and allocation-light — unit-tested by <c>--smoke-followwrite</c>.
/// </summary>
public static class WriteTarget
{
    [ThreadStatic] private static InstructionInfoFactory? _iif;

    /// <summary>Compute the VA <paramref name="insn"/> writes to and the byte width of that write, evaluated
    /// against <paramref name="regs"/>. False when the instruction has no explicit memory-write operand.</summary>
    public static bool TryResolve(in Instruction insn, RegisterSet regs, out ulong ea, out int size)
    {
        ea = 0;
        size = 1;

        var iif = _iif ??= new InstructionInfoFactory();
        var info = iif.GetInfo(in insn);

        // Follow only an EXPLICIT memory operand that is written. Checking the operand's own access (not the
        // segment) means push/pop/call — which have no explicit memory operand — are naturally excluded, while a
        // store to a local through [rbp-8]/[rsp+x] (SS segment) is still followed. `push [mem]` (an explicit
        // memory READ) resolves to nothing; `pop [mem]` (an explicit memory WRITE) is followed, both correctly.
        for (int i = 0; i < insn.OpCount; i++)
        {
            if (insn.GetOpKind(i) != OpKind.Memory) continue;
            if (info.GetOpAccess(i) is OpAccess.Write or OpAccess.ReadWrite or OpAccess.CondWrite or OpAccess.ReadCondWrite)
            {
                ea = insn.IsIPRelativeMemoryOperand
                    ? insn.IPRelativeMemoryAddress
                    : insn.MemoryDisplacement64
                      + RegVal(insn.MemoryBase, regs)
                      + RegVal(insn.MemoryIndex, regs) * (ulong)insn.MemoryIndexScale;
                size = insn.MemorySize.GetInfo().Size;
                return true;
            }
        }
        return false;
    }

    private static ulong RegVal(Register reg, RegisterSet regs) => reg switch
    {
        Register.None => 0,
        Register.RIP or Register.EIP => regs.Ip,          // not normally hit — RIP-relative is handled above
        _ => regs[reg.ToString().ToLowerInvariant()],     // RegisterSet is case-insensitive; Iced names map 1:1
    };
}

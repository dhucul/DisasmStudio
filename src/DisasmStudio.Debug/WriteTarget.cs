using Iced.Intel;

namespace DisasmStudio.Debug;

/// <summary>
/// Resolves the effective address an instruction <b>writes to</b> in memory, from a register snapshot — used by
/// the debugger's "follow writes" feature to scroll the memory views to the location being written while stepping.
/// Only <b>explicit</b> memory-write operands count (so <c>push</c>/<c>pop</c>/<c>call</c> stack traffic is ignored,
/// as is any stack-segment access), which keeps the view on real data writes instead of chasing the stack.
/// Pure and allocation-light — unit-tested by <c>--smoke-followwrite</c>.
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

        // Must have an explicit memory operand — this excludes implicit stack pushes/pops/calls.
        bool hasMem = false;
        for (int i = 0; i < insn.OpCount; i++)
            if (insn.GetOpKind(i) == OpKind.Memory) { hasMem = true; break; }
        if (!hasMem) return false;

        var iif = _iif ??= new InstructionInfoFactory();
        var info = iif.GetInfo(in insn);
        foreach (var m in info.GetUsedMemory())
        {
            if (m.Segment == Register.SS) continue;   // never chase the stack
            if (m.Access is OpAccess.Write or OpAccess.ReadWrite or OpAccess.CondWrite or OpAccess.ReadCondWrite)
            {
                ea = insn.IsIPRelativeMemoryOperand
                    ? insn.IPRelativeMemoryAddress
                    : insn.MemoryDisplacement64
                      + RegVal(insn.MemoryBase, regs)
                      + RegVal(insn.MemoryIndex, regs) * (ulong)insn.MemoryIndexScale;
                size = m.MemorySize.GetInfo().Size;
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

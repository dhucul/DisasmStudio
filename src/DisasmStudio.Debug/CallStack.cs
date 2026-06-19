using Iced.Intel;

namespace DisasmStudio.Debug;

/// <summary>
/// A best-effort call stack: frame 0 is the current instruction, then the stack is scanned for return
/// addresses (executable values immediately preceded by a <c>call</c>). Robust without unwind info,
/// which suits frame-pointer-omitted x64 code; it can include a few false positives on a deep scan.
/// </summary>
public static class CallStack
{
    public static List<ulong> Walk(DebuggerEngine eng, RegisterSet regs)
    {
        var frames = new List<ulong> { regs.Ip };
        var seen = new HashSet<ulong> { regs.Ip };
        int ptr = eng.Is32 ? 4 : 8;
        var stack = eng.ReadMemory(regs.Sp, 0x800);

        for (int i = 0; i + ptr <= stack.Length && frames.Count < 64; i += ptr)
        {
            ulong v = ptr == 8 ? BitConverter.ToUInt64(stack, i) : BitConverter.ToUInt32(stack, i);
            if (v == 0 || !seen.Add(v) || !eng.IsExecutable(v)) continue;
            var pre = eng.ReadMemory(v - 16, 16);
            if (pre.Length == 16 && EndsWithCall(pre, v, eng.Is32)) frames.Add(v);
        }
        return frames;
    }

    private static bool EndsWithCall(byte[] pre, ulong end, bool is32)
    {
        for (int start = 1; start <= 7; start++)
        {
            var dec = Decoder.Create(is32 ? 32 : 64, new ByteArrayCodeReader(pre, 16 - start, start));
            dec.IP = end - (ulong)start;
            dec.Decode(out var instr);
            if (!instr.IsInvalid && instr.Length == start && instr.FlowControl is FlowControl.Call or FlowControl.IndirectCall)
                return true;
        }
        return false;
    }
}

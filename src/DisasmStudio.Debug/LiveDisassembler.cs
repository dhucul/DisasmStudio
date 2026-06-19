using DisasmStudio.Core.Disasm;
using Iced.Intel;

namespace DisasmStudio.Debug;

/// <summary>Decodes instructions straight from the debuggee's memory (by 64-bit VA), so the listing
/// reflects the actual executing bytes — including self-modifying / unpacked code.</summary>
public sealed class LiveDisassembler(DebuggerEngine eng) : IInstructionDecoder
{
    private readonly int _bitness = eng.Is32 ? 32 : 64;

    public bool TryDecodeAt(ulong va, out Instruction instr)
    {
        var bytes = eng.ReadMemory(va, 16);
        if (bytes.Length == 0) { instr = default; return false; }
        var dec = Decoder.Create(_bitness, new ByteArrayCodeReader(bytes));
        dec.IP = va;
        dec.Decode(out instr);
        return !instr.IsInvalid && instr.Length > 0;
    }
}

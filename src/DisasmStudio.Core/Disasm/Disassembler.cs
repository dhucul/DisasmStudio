using DisasmStudio.Core.Formats;
using Iced.Intel;

namespace DisasmStudio.Core.Disasm;

/// <summary>
/// A reusable Iced <see cref="CodeReader"/> over an image, repositioned per instruction via
/// <see cref="SetWindow"/>. Each window is capped at the longest possible x86/x64 instruction
/// (16 bytes) and clamped to the end of the backing, so the decoder never reads past the image.
/// Single-threaded use — create one per <see cref="Disassembler"/>.
/// </summary>
internal sealed class ImageWindowReader(IBinaryImage image) : CodeReader
{
    private const int WindowSize = 16;
    private readonly int _length = image.BackingLength;
    private int _pos;
    private int _end;

    public void SetWindow(int offset)
    {
        _pos = offset;
        _end = (int)Math.Min((long)offset + WindowSize, _length);
    }

    public override int ReadByte() => _pos < _end ? image.ReadByteAtOffset(_pos++) : -1;
}

/// <summary>
/// Decodes a single instruction at any VA on demand, with one decoder + repositionable reader
/// (no per-instruction allocation). This is what lets the linear view decode only the rows on
/// screen over an arbitrarily large image. Not thread-safe.
/// </summary>
public sealed class Disassembler
{
    private readonly IBinaryImage _image;
    private readonly ImageWindowReader _reader;
    private readonly Decoder _decoder;

    public Disassembler(IBinaryImage image)
    {
        _image = image;
        _reader = new ImageWindowReader(image);
        _decoder = Decoder.Create(image.Bitness, _reader, DecoderOptions.None);
    }

    /// <summary>Decode the instruction at <paramref name="va"/>; false if unmapped or undecodable.</summary>
    public bool TryDecodeAt(ulong va, out Instruction instr)
    {
        int off = _image.VaToOffset(va);
        if (off < 0) { instr = default; return false; }
        _reader.SetWindow(off);
        _decoder.IP = va;
        _decoder.Decode(out instr);
        return !instr.IsInvalid && instr.Length > 0;
    }
}

/// <summary>Static helpers shared by the analysis passes and the views.</summary>
public static class FlowAnalysis
{
    /// <summary>The target VA of a direct jmp/jcc/call, or null for indirect/non-branch flow.</summary>
    public static ulong? DirectBranchTarget(in Instruction instr) =>
        instr.FlowControl is FlowControl.Call or FlowControl.ConditionalBranch or FlowControl.UnconditionalBranch
            && instr.Op0Kind is OpKind.NearBranch16 or OpKind.NearBranch32 or OpKind.NearBranch64
            ? instr.NearBranchTarget
            : null;

    public static bool IsDirectCall(in Instruction instr) =>
        instr.FlowControl == FlowControl.Call &&
        instr.Op0Kind is OpKind.NearBranch16 or OpKind.NearBranch32 or OpKind.NearBranch64;

    public static bool IsBlockTerminator(in Instruction instr) => instr.FlowControl is
        FlowControl.UnconditionalBranch or FlowControl.ConditionalBranch or FlowControl.IndirectBranch
        or FlowControl.Return or FlowControl.Interrupt or FlowControl.Exception;

    private static bool IsImmediate(OpKind kind) => kind is
        OpKind.Immediate8 or OpKind.Immediate8_2nd or OpKind.Immediate16 or
        OpKind.Immediate32 or OpKind.Immediate64 or OpKind.Immediate8to16 or
        OpKind.Immediate8to32 or OpKind.Immediate8to64 or OpKind.Immediate32to64;

    /// <summary>Resolvable addresses an instruction references as data (memory operands / pushed offsets).</summary>
    public static void CollectDataRefs(in Instruction instr, IBinaryImage img, List<ulong> sink)
    {
        for (int i = 0; i < instr.OpCount; i++)
        {
            var kind = instr.GetOpKind(i);
            if (kind == OpKind.Memory)
            {
                ulong addr;
                if (instr.IsIPRelativeMemoryOperand) addr = instr.IPRelativeMemoryAddress;
                else if (instr.MemoryBase == Register.None && instr.MemoryIndex == Register.None) addr = instr.MemoryDisplacement64;
                else
                {
                    // [base + index*scale + disp]: the displacement itself can be a table base —
                    // e.g. an indexed lookup `movzx eax,[ecx + table]`. Treat it as a data ref when it
                    // lands in mapped, non-code memory (a small struct offset won't be a mapped VA).
                    ulong disp = instr.MemoryDisplacement64;
                    if (disp != 0 && img.IsMappedVa(disp) && !img.IsExecutableVa(disp)) sink.Add(disp);
                    continue;
                }
                if (img.IsMappedVa(addr) || img.ImportsByIatVa.ContainsKey(addr)) sink.Add(addr);
            }
            else if (IsImmediate(kind))
            {
                // A mapped immediate is an address reference (e.g. `push offset str`). Keep executable
                // targets too: some builds put read-only string literals in .text, so excluding them
                // would drop the very references that let a string jump to its code.
                ulong val = instr.GetImmediate(i);
                if (img.IsMappedVa(val)) sink.Add(val);
            }
        }
    }
}

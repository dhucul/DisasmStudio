using System.Collections.Generic;
using System.IO;
using Iced.Intel;
using static Iced.Intel.AssemblerRegisters;

namespace DisasmStudio.Core.Devirt.Synthetic;

/// <summary>
/// A tiny but realistic x86 stack VM, used to prove the devirtualization pipeline end-to-end without a real
/// (encrypted, anti-debug-protected) VMProtect sample. It assembles — via Iced's encoder — a real entry
/// stub, a dispatcher (<c>movzx eax,[esi]; inc esi; jmp [eax*4+TABLE]</c>) and 8 handler routines whose
/// native bodies use exactly the canonical stack/VIP patterns <see cref="HandlerClassifier"/> recognises,
/// then lays them out in a PE32 alongside the handler table (<c>.vmtab</c>) and a bytecode program
/// (<c>.vmcode</c>). The image is "decrypted" simply because nothing is encrypted — that is the Phase-1
/// precondition the engine requires. NB: a green test proves the *pipeline + IR reuse*, not real-VMProtect
/// coverage (the synthetic VM and its recogniser share an author).
///
/// VM model (x86): esi = VIP (bytecode pointer), edi = VSP (virtual stack, grows down), ebx = context base
/// (4 vregs). Opcodes index an 8-entry handler table; PUSH_IMM and JZ carry a 4-byte little-endian operand.
/// </summary>
public static class SyntheticVm
{
    public const ulong ImageBase = 0x00400000;
    public const ulong TextVa = ImageBase + 0x1000;   // entry stub + dispatcher + handlers
    public const ulong TableVa = ImageBase + 0x2000;  // 8 handler VAs (dword each)
    public const ulong VmCodeVa = ImageBase + 0x3000; // bytecode program
    public const ulong VStackTop = ImageBase + 0x8000;// runtime-only (never executed)
    public const ulong ContextVa = ImageBase + 0x9000;// runtime-only
    public const int HandlerCount = 8;

    // Opcode byte -> handler index (also the handler-table slot).
    public const byte OP_PUSH_IMM = 0;   // + imm32
    public const byte OP_PUSH_V0 = 1;
    public const byte OP_POP_V0 = 2;
    public const byte OP_ADD = 3;
    public const byte OP_MUL = 4;
    public const byte OP_CMP_LT = 5;
    public const byte OP_JZ = 6;         // + targetVipVa32
    public const byte OP_VM_EXIT = 7;

    /// <summary>Assemble a program into bytecode. Labels let JZ target a later instruction by its VIP VA.</summary>
    public sealed class VmAsm
    {
        private readonly List<byte> _b = [];
        private readonly List<(int Offset, int Label)> _fixups = [];
        private readonly Dictionary<int, int> _labelOffset = [];
        private int _nextLabel;

        public ulong BaseVa { get; }
        public VmAsm(ulong baseVa = VmCodeVa) => BaseVa = baseVa;

        private void Imm32(uint v) { _b.Add((byte)v); _b.Add((byte)(v >> 8)); _b.Add((byte)(v >> 16)); _b.Add((byte)(v >> 24)); }

        public VmAsm PushImm(int v) { _b.Add(OP_PUSH_IMM); Imm32((uint)v); return this; }
        public VmAsm PushV0() { _b.Add(OP_PUSH_V0); return this; }
        public VmAsm PopV0() { _b.Add(OP_POP_V0); return this; }
        public VmAsm Add() { _b.Add(OP_ADD); return this; }
        public VmAsm Mul() { _b.Add(OP_MUL); return this; }
        public VmAsm CmpLt() { _b.Add(OP_CMP_LT); return this; }
        public VmAsm VmExit() { _b.Add(OP_VM_EXIT); return this; }

        public int NewLabel() => _nextLabel++;
        public void Mark(int label) => _labelOffset[label] = _b.Count;
        public VmAsm Jz(int label) { _b.Add(OP_JZ); _fixups.Add((_b.Count, label)); Imm32(0); return this; }

        public byte[] ToBytes()
        {
            foreach (var (off, label) in _fixups)
            {
                uint targetVa = (uint)(BaseVa + (ulong)_labelOffset[label]);
                _b[off + 0] = (byte)targetVa; _b[off + 1] = (byte)(targetVa >> 8);
                _b[off + 2] = (byte)(targetVa >> 16); _b[off + 3] = (byte)(targetVa >> 24);
            }
            return [.. _b];
        }
    }

    /// <summary>Build a runnable-looking PE32 hosting the VM with the given bytecode in <c>.vmcode</c>.</summary>
    public static byte[] BuildVmImage(byte[] bytecode)
    {
        var (text, handlerVas) = AssembleVm();
        var table = new byte[HandlerCount * 4];
        for (int i = 0; i < HandlerCount; i++)
        {
            uint va = (uint)handlerVas[i];
            table[i * 4 + 0] = (byte)va; table[i * 4 + 1] = (byte)(va >> 8);
            table[i * 4 + 2] = (byte)(va >> 16); table[i * 4 + 3] = (byte)(va >> 24);
        }
        return BuildPe(0xA000, 0x1000,
        [
            (".text\0\0\0", 0x1000, text, 0x60000020u),      // CODE | EXECUTE | READ
            (".vmtab\0\0", 0x2000, table, 0x40000040u),      // INITIALIZED_DATA | READ
            (".vmcode\0", 0x3000, bytecode, 0x40000040u),
        ]);
    }

    /// <summary>A plain, un-virtualized EXE (push ebp; mov ebp,esp; pop ebp; ret) — for the NoVmFound test.</summary>
    public static byte[] BuildPlainImage()
    {
        var asm = new Assembler(32);
        asm.push(ebp); asm.mov(ebp, esp); asm.pop(ebp); asm.ret();
        var text = Encode(asm, TextVa);
        return BuildPe(0x3000, 0x1000, [(".text\0\0\0", 0x1000, text, 0x60000020u)]);
    }

    /// <summary>A PE that the packer detector flags as a virtualizer but whose VM body is opaque/encrypted
    /// on disk (high-entropy, no readable dispatcher) — for the ImageEncrypted test.</summary>
    public static byte[] BuildEncryptedLookalikeImage()
    {
        var body = new byte[0x1000];
        for (int i = 0; i < body.Length; i++) body[i] = (byte)((i * 7 + 13) & 0xFF);  // ~8.0 entropy
        var stub = new byte[0x200];
        for (int i = 0; i < stub.Length; i++) stub[i] = (byte)((i * 11 + 5) & 0xFF);
        return BuildPe(0x4000, 0x1000,
        [
            (".tamCORE", 0x1000, stub, 0x60000020u),         // entry stub (X R), opaque
            (".tamCORE", 0x2000, body, 0xE0000020u),         // RWX high-entropy packed body -> Virtualizer verdict
        ]);
    }

    // ---- x86 assembly of the VM (stub + dispatcher + 8 handlers) ----

    private static (byte[] Text, ulong[] HandlerVas) AssembleVm()
    {
        var a = new Assembler(32);
        var dispatch = a.CreateLabel();
        var hPushImm = a.CreateLabel();
        var hPushV0 = a.CreateLabel();
        var hPopV0 = a.CreateLabel();
        var hAdd = a.CreateLabel();
        var hMul = a.CreateLabel();
        var hCmpLt = a.CreateLabel();
        var hJz = a.CreateLabel();
        var hExit = a.CreateLabel();

        // entry stub: save context, init VIP/VSP/context-base, enter the dispatcher.
        a.pushad();
        a.mov(esi, (uint)VmCodeVa);     // VIP
        a.mov(edi, (uint)VStackTop);    // VSP
        a.mov(ebx, (uint)ContextVa);    // context base
        a.jmp(dispatch);

        // dispatcher: fetch opcode, advance VIP, dispatch through the handler table.
        a.Label(ref dispatch);
        a.movzx(eax, __byte_ptr[esi]);
        a.inc(esi);
        a.jmp(__dword_ptr[eax * 4 + (long)TableVa]);

        // PUSH_IMM: read imm32 from VIP, advance VIP by 4, push onto the virtual stack.
        a.Label(ref hPushImm);
        a.mov(eax, __dword_ptr[esi]);
        a.add(esi, 4);
        a.sub(edi, 4);
        a.mov(__dword_ptr[edi], eax);
        a.jmp(dispatch);

        // PUSH_V0: push vreg0 (context+0).
        a.Label(ref hPushV0);
        a.mov(eax, __dword_ptr[ebx]);
        a.sub(edi, 4);
        a.mov(__dword_ptr[edi], eax);
        a.jmp(dispatch);

        // POP_V0: pop into vreg0.
        a.Label(ref hPopV0);
        a.mov(eax, __dword_ptr[edi]);
        a.add(edi, 4);
        a.mov(__dword_ptr[ebx], eax);
        a.jmp(dispatch);

        // ADD / MUL: pop Top0 (right) and Top1 (left), push (left op right). Uniform binop shape.
        EmitBinOp(a, ref hAdd, dispatch, isMul: false);
        EmitBinOp(a, ref hMul, dispatch, isMul: true);

        // CMP_LT: pop Top0/Top1, push (Top1 < Top0) as 0/1.
        a.Label(ref hCmpLt);
        a.mov(eax, __dword_ptr[edi]);     // Top0 (right)
        a.add(edi, 4);
        a.mov(ecx, __dword_ptr[edi]);     // Top1 (left)
        a.xor(edx, edx);
        a.cmp(ecx, eax);
        a.setl(dl);
        a.mov(__dword_ptr[edi], edx);
        a.jmp(dispatch);

        // JZ: pop condition, read 4-byte target VIP VA from the stream; if condition == 0, VIP = target.
        a.Label(ref hJz);
        a.mov(eax, __dword_ptr[edi]);     // popped condition
        a.add(edi, 4);
        a.mov(ecx, __dword_ptr[esi]);     // branch target operand
        a.add(esi, 4);
        a.test(eax, eax);
        a.cmove(esi, ecx);                // if zero -> take the branch
        a.jmp(dispatch);

        // VM_EXIT: restore context and leave the VM.
        a.Label(ref hExit);
        a.popad();
        a.ret();

        var r = AssembleWithLabels(a, TextVa,
            dispatch, hPushImm, hPushV0, hPopV0, hAdd, hMul, hCmpLt, hJz, hExit);
        var text = r.Bytes;
        ulong[] handlerVas =
        [
            r.Rip(hPushImm), r.Rip(hPushV0), r.Rip(hPopV0), r.Rip(hAdd),
            r.Rip(hMul), r.Rip(hCmpLt), r.Rip(hJz), r.Rip(hExit),
        ];
        return (text, handlerVas);
    }

    private static void EmitBinOp(Assembler a, ref Label label, Label dispatch, bool isMul)
    {
        a.Label(ref label);
        a.mov(eax, __dword_ptr[edi]);     // Top0 (right)
        a.add(edi, 4);
        a.mov(ecx, __dword_ptr[edi]);     // Top1 (left)
        if (isMul) a.imul(ecx, eax); else a.add(ecx, eax);
        a.mov(__dword_ptr[edi], ecx);     // result -> new top
        a.jmp(dispatch);
    }

    // ---- Iced encode helpers ----

    private static byte[] Encode(Assembler a, ulong rip)
    {
        var ms = new MemoryStream();
        a.Assemble(new StreamCodeWriter(ms), rip);
        return ms.ToArray();
    }

    private readonly record struct LabelResult(byte[] Bytes, AssemblerResult Result)
    {
        public ulong Rip(Label l) => Result.GetLabelRIP(l);
    }

    private static LabelResult AssembleWithLabels(Assembler a, ulong rip, params Label[] _)
    {
        var ms = new MemoryStream();
        // ReturnNewInstructionOffsets is required for AssemblerResult.GetLabelRIP to resolve label addresses.
        var result = a.Assemble(new StreamCodeWriter(ms), rip, BlockEncoderOptions.ReturnNewInstructionOffsets);
        return new LabelResult(ms.ToArray(), result);
    }

    // ---- minimal PE32 writer (offset == RVA layout, like the .smoke_unpack synthetic builder) ----

    private static byte[] BuildPe(int sizeOfImage, uint headersSize,
        (string Name, uint Rva, byte[] Data, uint Chars)[] sections)
    {
        var b = new byte[sizeOfImage];
        void U16(int o, ushort v) { b[o] = (byte)v; b[o + 1] = (byte)(v >> 8); }
        void U32(int o, uint v) { b[o] = (byte)v; b[o + 1] = (byte)(v >> 8); b[o + 2] = (byte)(v >> 16); b[o + 3] = (byte)(v >> 24); }
        void Ascii(int o, string s) { for (int i = 0; i < s.Length && i < 8; i++) b[o + i] = (byte)s[i]; }

        b[0] = (byte)'M'; b[1] = (byte)'Z';
        int pe = 0x80; U32(0x3C, (uint)pe);
        U32(pe, 0x00004550);                       // "PE\0\0"
        int coff = pe + 4, opt = pe + 24;
        U16(coff + 0, 0x014C);                      // Machine x86
        U16(coff + 2, (ushort)sections.Length);     // NumberOfSections
        U16(coff + 16, 0xE0);                       // SizeOfOptionalHeader
        U16(coff + 18, 0x0102);                     // EXECUTABLE | 32BIT
        U16(opt + 0, 0x010B);                       // PE32 magic
        U32(opt + 16, 0x1000);                      // AddressOfEntryPoint (RVA of .text)
        U32(opt + 28, (uint)ImageBase);             // ImageBase
        U32(opt + 32, 0x1000);                      // SectionAlignment
        U32(opt + 36, 0x1000);                      // FileAlignment
        U32(opt + 56, (uint)sizeOfImage);           // SizeOfImage
        U32(opt + 60, headersSize);                 // SizeOfHeaders
        U16(opt + 68, 3);                           // Subsystem CONSOLE
        U32(opt + 92, 16);                          // NumberOfRvaAndSizes

        int st = opt + 0xE0;
        for (int i = 0; i < sections.Length; i++)
        {
            int s = st + i * 40;
            var (name, rva, data, chars) = sections[i];
            Ascii(s + 0, name);
            U32(s + 8, (uint)data.Length);          // VirtualSize
            U32(s + 12, rva);                       // VirtualAddress
            U32(s + 16, (uint)data.Length);         // SizeOfRawData
            U32(s + 20, rva);                       // PointerToRawData (offset == rva)
            U32(s + 36, chars);
            System.Array.Copy(data, 0, b, (int)rva, System.Math.Min(data.Length, sizeOfImage - (int)rva));
        }
        return b;
    }
}

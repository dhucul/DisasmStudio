using System.Numerics;
using DisasmStudio.Core.Disasm;
using DisasmStudio.Core.Formats;
using Iced.Intel;

namespace DisasmStudio.Core.Analysis;

/// <summary>
/// Marks which bytes of the executable sections are covered by a decoded instruction, as a packed
/// word bitmap (one bit per byte) so coverage is proportional to code size and gaps can be skipped 64
/// bits at a time. Drives the code/data classifier and the gap function-start scan.
/// </summary>
public sealed class CodeBitmap
{
    private readonly ulong[] _start;
    private readonly ulong[] _end;
    private readonly ulong[][] _words;
    private int _last;

    public CodeBitmap(IBinaryImage image)
    {
        var regions = image.Sections
            .Where(s => s.IsExecutable && s.FileSize > 0)
            .Select(s => (s.StartVa, Span: (long)Math.Max(s.VirtualSize, (ulong)s.FileSize)))
            .ToArray();
        _start = regions.Select(r => r.StartVa).ToArray();
        _end = regions.Select(r => r.StartVa + (ulong)r.Span).ToArray();
        _words = regions.Select(r => new ulong[(Math.Min(r.Span, int.MaxValue) + 63) / 64]).ToArray();
    }

    private int RegionOf(ulong va)
    {
        if (_last < _start.Length && va >= _start[_last] && va < _end[_last]) return _last;
        for (int i = 0; i < _start.Length; i++)
            if (va >= _start[i] && va < _end[i]) { _last = i; return i; }
        return -1;
    }

    /// <summary>Mark <paramref name="len"/> bytes from <paramref name="va"/> as code.</summary>
    public void Mark(ulong va, int len)
    {
        int r = RegionOf(va);
        if (r < 0) return;
        long span = (long)Math.Min(_end[r] - _start[r], (ulong)int.MaxValue);
        long i = (long)(va - _start[r]);
        long e = Math.Min(i + len, span);
        var w = _words[r];
        for (long k = i; k < e; k++) w[k >> 6] |= 1UL << (int)(k & 63);
    }

    public bool IsCode(ulong va)
    {
        int r = RegionOf(va);
        if (r < 0) return false;
        long i = (long)(va - _start[r]);
        return (_words[r][i >> 6] & (1UL << (int)(i & 63))) != 0;
    }

    /// <summary>Next code byte at/after <paramref name="va"/>, else <paramref name="limit"/>.</summary>
    public ulong NextCode(ulong va, ulong limit) => Scan(va, limit, set: true);

    /// <summary>Next non-code (gap) byte at/after <paramref name="va"/>, else <paramref name="limit"/>.</summary>
    public ulong NextGap(ulong va, ulong limit) => Scan(va, limit, set: false);

    private ulong Scan(ulong va, ulong limit, bool set)
    {
        int r = RegionOf(va);
        if (r < 0) return limit;
        long span = (long)Math.Min(_end[r] - _start[r], (ulong)int.MaxValue);
        long i = Math.Max(0, (long)(va - _start[r]));
        var w = _words[r];
        while (i < span)
        {
            int wi = (int)(i >> 6);
            ulong word = (set ? w[wi] : ~w[wi]) & (~0UL << (int)(i & 63));
            if (word != 0)
            {
                long idx = ((long)wi << 6) + BitOperations.TrailingZeroCount(word);
                if (idx >= span) break;
                ulong c = _start[r] + (ulong)idx;
                return c < limit ? c : limit;
            }
            i = ((long)wi + 1) << 6;
        }
        return limit;
    }
}

/// <summary>
/// Recursive-descent code discovery. From legitimate roots (entry, exports, symbols, .pdata functions,
/// jump tables, and code pointers in data) it follows real control flow, marking reachable instructions.
/// A follow-up gap scan finds functions the roots miss — chiefly indirectly-called functions, which on a
/// CET build begin with <c>endbr64</c> — by recognising prologues in the unmarked gaps and descending
/// from them. What remains unmarked inside .text is genuine data (padding, jump tables, literals).
/// </summary>
public static class CodeMap
{
    private const long Budget = 120_000_000;

    public static CodeBitmap Compute(IBinaryImage image, IEnumerable<ulong> seeds,
        IReadOnlyDictionary<ulong, ulong[]> jumpTables, CancellationToken token = default)
    {
        var code = new CodeBitmap(image);
        Descend(image, code, seeds, jumpTables, token);
        return code;
    }

    /// <summary>Scan the unmarked .text gaps for function prologues, descend from them, and return the
    /// new function starts found (so they can be listed and named).</summary>
    public static List<ulong> GapScan(IBinaryImage image, CodeBitmap code,
        IReadOnlyDictionary<ulong, ulong[]> jumpTables, CancellationToken token = default)
    {
        var dis = new Disassembler(image);
        var seeds = new List<ulong>();
        var one = new ulong[1];
        foreach (var sec in image.Sections.Where(s => s.IsExecutable && s.FileSize > 0).OrderBy(s => s.StartVa))
        {
            ulong end = sec.StartVa + (sec.VirtualSize > 0 ? Math.Min(sec.VirtualSize, (ulong)sec.FileSize) : (ulong)sec.FileSize);
            ulong va = sec.StartVa;
            while (va < end)
            {
                if (token.IsCancellationRequested) break;
                if (code.IsCode(va)) { va = code.NextGap(va, end); continue; }       // skip known code (word-scan)

                byte b = ByteAt(image, va);
                if (b is 0xCC or 0x00 or 0x90) { va++; continue; }                   // 1-byte padding / nop

                // Multi-byte NOP alignment — mark it so it renders as `nop`, not a db row.
                if (dis.TryDecodeAt(va, out var nop) && nop.Mnemonic == Mnemonic.Nop) { code.Mark(va, nop.Length); va += (ulong)nop.Length; continue; }

                // Aligned pointer into mapped memory — a table entry; leave as data.
                int ps = PointerSize(image, va);
                if (ps > 0) { va += (ulong)ps; continue; }

                // A function start — only a recognisable prologue (endbr64 / frame setup / push-run+alloc).
                // Descend immediately so consecutive blocks in the same run (no padding between them) are each
                // found; NextGap then jumps past the marked code.
                //
                // We deliberately do NOT accept "decodes to a ret/jmp/call within N instructions" as code:
                // those opcodes are common byte values, so almost any data passes — which flooded the function
                // list with hundreds of thousands of phantom sub_* and mis-marked jump tables / literals as
                // code (the latter is also what let function-capture write 0xCC into those tables). Real code
                // in a gap that no seed reaches and that has no prologue is left as data rather than guessed;
                // genuinely indirect-only functions are still found via their prologue (endbr64), the
                // code-pointer scan, or jump-table case edges.
                if (IsPrologue(image, va))
                {
                    one[0] = va;
                    Descend(image, code, one, jumpTables, token);
                    seeds.Add(va);
                    va = Math.Max(code.NextGap(va, end), va + 1);   // always make progress
                    continue;
                }
                va++;   // unknown byte — keep scanning
            }
        }
        return seeds;
    }

    /// <summary>Aligned pointer-into-mapped-memory size at <paramref name="va"/> (8/4), or 0 if not a pointer.</summary>
    private static int PointerSize(IBinaryImage image, ulong va)
    {
        if (va % 8 == 0) { var b = image.ReadBytesAtVa(va, 8); if (b.Length == 8 && image.IsMappedVa(BitConverter.ToUInt64(b, 0))) return 8; }
        if (va % 4 == 0) { var b = image.ReadBytesAtVa(va, 4); if (b.Length == 4 && image.IsMappedVa(BitConverter.ToUInt32(b, 0))) return 4; }
        return 0;
    }

    private static void Descend(IBinaryImage image, CodeBitmap code, IEnumerable<ulong> seeds,
        IReadOnlyDictionary<ulong, ulong[]> jumpTables, CancellationToken token)
    {
        var dis = new Disassembler(image);
        var work = new Stack<ulong>();
        foreach (var s in seeds) if (image.IsExecutableVa(s)) work.Push(s);

        long n = 0;
        while (work.Count > 0 && n < Budget)
        {
            if ((n & 0xFFFFF) == 0 && token.IsCancellationRequested) break;
            ulong va = work.Pop();
            if (!image.IsExecutableVa(va) || code.IsCode(va)) continue;
            if (!dis.TryDecodeAt(va, out var ins)) continue;
            code.Mark(va, ins.Length);
            n++;

            ulong fall = va + (ulong)ins.Length;
            switch (ins.FlowControl)
            {
                case FlowControl.ConditionalBranch:
                    if (FlowAnalysis.DirectBranchTarget(ins) is ulong tc) work.Push(tc);
                    work.Push(fall);
                    break;
                case FlowControl.UnconditionalBranch:
                    if (FlowAnalysis.DirectBranchTarget(ins) is ulong tj) work.Push(tj);
                    break;
                case FlowControl.IndirectBranch:
                    if (jumpTables.TryGetValue(va, out var cases)) foreach (var c in cases) work.Push(c);
                    break;
                case FlowControl.Return:
                case FlowControl.Interrupt:
                case FlowControl.Exception:
                    break;
                case FlowControl.Call:
                    if (FlowAnalysis.IsDirectCall(ins)) work.Push(ins.NearBranchTarget);
                    work.Push(fall);
                    break;
                default:
                    work.Push(fall);
                    break;
            }
        }
    }

    /// <summary>Recognise a function prologue at <paramref name="va"/> (x64 / x86 common, low false-positive forms).</summary>
    private static bool IsPrologue(IBinaryImage image, ulong va)
    {
        var b = image.ReadBytesAtVa(va, 4);
        if (b.Length < 4) return false;
        if ((b[0] == 0xF3 && b[1] == 0x0F && b[2] == 0x1E && b[3] == 0xFA) ||       // endbr64 (CET)
            (b[0] == 0x55 && b[1] == 0x48 && b[2] == 0x89 && b[3] == 0xE5) ||       // push rbp; mov rbp,rsp
            (b[0] == 0x55 && b[1] == 0x8B && b[2] == 0xEC) ||                       // push ebp; mov ebp,esp (x86)
            FrameAlloc(b))                                                          // sub rsp,imm / mov [rsp+x],reg
            return true;

        // A run of register pushes immediately followed by a frame allocation — reliable, unlike a
        // lone push (whose byte can appear at the start of a pointer/data run).
        ulong cur = va;
        int pushes = 0;
        while (pushes < 8 && PushLen(image, cur) is int pl) { cur += (ulong)pl; pushes++; }
        return pushes >= 1 && FrameAlloc(image.ReadBytesAtVa(cur, 4));
    }

    private static bool FrameAlloc(byte[] b) =>
        b.Length >= 3 && (
            (b[0] == 0x48 && b[1] == 0x83 && b[2] == 0xEC) ||                       // sub rsp, imm8
            (b[0] == 0x48 && b[1] == 0x81 && b[2] == 0xEC) ||                       // sub rsp, imm32
            ((b[0] == 0x48 || b[0] == 0x4C) && b[1] == 0x89 && b.Length >= 4 && (b[2] & 0x07) == 0x04 && b[3] == 0x24)); // mov [rsp+x],reg

    /// <summary>Length of a register-push at <paramref name="va"/> (1 or 2 bytes), or null.</summary>
    private static int? PushLen(IBinaryImage image, ulong va)
    {
        var b = image.ReadBytesAtVa(va, 2);
        if (b.Length >= 1 && b[0] is >= 0x50 and <= 0x57) return 1;                 // push rax..rdi
        if (b.Length >= 2 && b[0] is 0x40 or 0x41 && b[1] is >= 0x50 and <= 0x57) return 2; // push reg (REX/r8-15)
        return null;
    }

    private static byte ByteAt(IBinaryImage image, ulong va)
    {
        int off = image.VaToOffset(va);
        return off < 0 ? (byte)0 : image.ReadByteAtOffset(off);
    }
}

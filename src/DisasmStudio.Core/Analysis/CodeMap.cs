using System.Collections;
using DisasmStudio.Core.Disasm;
using DisasmStudio.Core.Formats;
using Iced.Intel;

namespace DisasmStudio.Core.Analysis;

/// <summary>
/// Marks which bytes of the executable sections begin a real instruction, as one bit per byte — so it
/// is proportional to code size, not instruction count, and scales to large files. Drives the
/// code/data classifier (anything not marked, inside .text, is data: padding, jump tables, literals).
/// </summary>
public sealed class CodeBitmap
{
    private readonly ulong[] _start;
    private readonly ulong[] _end;
    private readonly BitArray[] _bits;
    private int _last;

    public CodeBitmap(IBinaryImage image)
    {
        var regions = image.Sections
            .Where(s => s.IsExecutable && s.FileSize > 0)
            .Select(s => (s.StartVa, Span: (long)Math.Max(s.VirtualSize, (ulong)s.FileSize)))
            .ToArray();
        _start = regions.Select(r => r.StartVa).ToArray();
        _end = regions.Select(r => r.StartVa + (ulong)r.Span).ToArray();
        _bits = regions.Select(r => new BitArray((int)Math.Min(r.Span, int.MaxValue))).ToArray();
    }

    private int RegionOf(ulong va)
    {
        if (_last < _start.Length && va >= _start[_last] && va < _end[_last]) return _last;
        for (int i = 0; i < _start.Length; i++)
            if (va >= _start[i] && va < _end[i]) { _last = i; return i; }
        return -1;
    }

    /// <summary>Mark <paramref name="va"/> as an instruction start; returns true if newly marked.</summary>
    public bool Mark(ulong va)
    {
        int r = RegionOf(va);
        if (r < 0) return false;
        int i = (int)(va - _start[r]);
        if (_bits[r][i]) return false;
        _bits[r][i] = true;
        return true;
    }

    public bool IsCode(ulong va)
    {
        int r = RegionOf(va);
        return r >= 0 && _bits[r][(int)(va - _start[r])];
    }

    /// <summary>First instruction-start VA strictly after <paramref name="va"/> in its region, else <paramref name="limit"/>.</summary>
    public ulong NextCode(ulong va, ulong limit)
    {
        int r = RegionOf(va);
        if (r < 0) return limit;
        int n = (int)Math.Min(_end[r] - _start[r], (ulong)int.MaxValue);
        for (int i = (int)(va - _start[r]) + 1; i < n; i++)
            if (_bits[r][i]) { ulong c = _start[r] + (ulong)i; return c < limit ? c : limit; }
        return limit;
    }
}

/// <summary>
/// Recursive-descent code discovery: from a set of legitimate roots (entry, exports, symbols, and code
/// pointers referenced from data) it follows real control flow — calls, branches, fall-through, and
/// recovered jump tables — marking every reachable instruction. Unlike a linear sweep it never walks
/// into data, so the bytes it leaves unmarked inside .text are exactly the padding / jump tables /
/// literals the classifier renders as data. Bounded by an instruction budget.
/// </summary>
public static class CodeMap
{
    private const long Budget = 80_000_000;

    public static CodeBitmap Compute(IBinaryImage image, IEnumerable<ulong> seeds,
        IReadOnlyDictionary<ulong, ulong[]> jumpTables, CancellationToken token = default)
    {
        var code = new CodeBitmap(image);
        var dis = new Disassembler(image);
        var work = new Stack<ulong>();
        foreach (var s in seeds) if (image.IsExecutableVa(s)) work.Push(s);

        long n = 0;
        while (work.Count > 0 && n < Budget)
        {
            if ((n & 0xFFFFF) == 0 && token.IsCancellationRequested) break;
            ulong va = work.Pop();
            if (!image.IsExecutableVa(va) || code.IsCode(va)) continue;
            if (!dis.TryDecodeAt(va, out var ins)) continue;   // not real code — leave unmarked (data)
            code.Mark(va);
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
                    work.Push(fall); // Next, IndirectCall — execution continues after
                    break;
            }
        }
        return code;
    }
}

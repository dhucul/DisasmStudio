using System.Collections.Immutable;
using DisasmStudio.Core.Disasm;
using DisasmStudio.Core.Formats;
using Iced.Intel;

namespace DisasmStudio.Core.Analysis;

/// <summary>
/// Immutable result of interprocedural no-return analysis. Function VAs describe callees proven not to
/// return; call-site VAs also include indirect calls to known no-return imports.
/// </summary>
public sealed class NoReturnInfo
{
    public static NoReturnInfo Empty { get; } = new([], []);

    private readonly ImmutableHashSet<ulong> _functions;
    private readonly ImmutableHashSet<ulong> _callSites;

    public NoReturnInfo(IEnumerable<ulong> functions, IEnumerable<ulong> callSites)
    {
        _functions = functions.ToImmutableHashSet();
        _callSites = callSites.ToImmutableHashSet();
    }

    public IReadOnlySet<ulong> Functions => _functions;
    public IReadOnlySet<ulong> CallSites => _callSites;

    public bool IsNoReturnFunction(ulong va) => _functions.Contains(va);

    /// <summary>True when the call at <paramref name="siteVa"/> cannot return normally.</summary>
    public bool IsNoReturnCall(ulong siteVa, ulong? directTarget) =>
        _callSites.Contains(siteVa) || directTarget is ulong t && _functions.Contains(t);

    public NoReturnInfo Rebased(ulong slide) => slide == 0
        ? this
        : new NoReturnInfo(_functions.Select(x => x + slide), _callSites.Select(x => x + slide));
}

/// <summary>
/// Recognises well-known process/thread termination and language-runtime failure routines. Decoration
/// from PE stdcall, import prefixes, ELF symbol versions/PLT names, and qualified C++ names is ignored.
/// </summary>
public static class KnownNoReturnNames
{
    private static readonly HashSet<string> Names = new(StringComparer.OrdinalIgnoreCase)
    {
        "abort", "exit", "quick_exit",
        "exitprocess", "exitthread", "fatalexit", "rtlexituserprocess", "rtlexituserthread",
        "raisefailfastexception", "fastfail",
        "terminate", "unexpected", "cxa_throw", "cxa_rethrow",
        "assert_fail", "stack_chk_fail", "fortify_fail", "chk_fail",
        "invalid_parameter_noinfo_noreturn", "invoke_watson", "amsg_exit",
        "pthread_exit", "thrd_exit", "longjmp", "siglongjmp",
    };

    public static bool IsKnown(string? name)
    {
        if (string.IsNullOrWhiteSpace(name)) return false;
        if (ApiDatabase.Lookup(name)?.NoReturn == true) return true;

        string n = name.Trim();
        int bang = n.LastIndexOf('!');
        if (bang >= 0) n = n[(bang + 1)..];
        if (n.StartsWith("__imp_", StringComparison.OrdinalIgnoreCase)) n = n[6..];
        int paren = n.IndexOf('(');
        if (paren > 0) n = n[..paren];
        int scope = n.LastIndexOf("::", StringComparison.Ordinal);
        if (scope >= 0) n = n[(scope + 2)..];
        n = n.TrimStart('_');
        int at = n.IndexOf('@');
        if (at > 0) n = n[..at];
        return Names.Contains(n);
    }
}

/// <summary>
/// Computes the least may-return fixpoint over discovered functions. Starting with no internal function
/// assumed to return, functions are added to the may-return set when a reachable path returns or escapes
/// through unresolved control flow. The functions left over are proven no-return, including recursive
/// cycles and wrappers around other no-return functions.
/// </summary>
public static class NoReturnAnalyzer
{
    private const int MaxInstructionsPerFunction = 200_000;

    public static NoReturnInfo Analyze(IBinaryImage image, IEnumerable<ulong> functionStarts,
        IReadOnlyDictionary<ulong, ulong[]>? jumpTables = null, CancellationToken token = default)
    {
        var starts = new HashSet<ulong>(functionStarts.Where(image.IsExecutableVa));
        foreach (ulong va in image.FunctionStarts) if (image.IsExecutableVa(va)) starts.Add(va);
        foreach (var symbol in image.Symbols)
            if (symbol.Kind is NamedSymbolKind.Function or NamedSymbolKind.Export or NamedSymbolKind.Import
                && image.IsExecutableVa(symbol.Va))
                starts.Add(symbol.Va);

        var symbolNames = new Dictionary<ulong, string>();
        foreach (var symbol in image.Symbols) symbolNames[symbol.Va] = symbol.Name;

        var knownNoReturn = new HashSet<ulong>();
        foreach (ulong va in starts)
            if (symbolNames.TryGetValue(va, out string? name) && KnownNoReturnNames.IsKnown(name))
                knownNoReturn.Add(va);

        using INeutralDisassembler dis = NeutralDisasm.For(image, null);
        var rich = image.IsNonX86 ? null : new Disassembler(image);
        var importNames = new Dictionary<ulong, string?>();
        var mayReturn = new HashSet<ulong>();
        var dependents = new Dictionary<ulong, HashSet<ulong>>();
        var pending = new Queue<ulong>(starts.Where(x => !knownNoReturn.Contains(x)));
        var queued = new HashSet<ulong>(pending);

        while (pending.Count > 0 && !token.IsCancellationRequested)
        {
            ulong entry = pending.Dequeue();
            queued.Remove(entry);
            if (mayReturn.Contains(entry)) continue;

            var blockedOn = new HashSet<ulong>();
            if (CanReturn(image, dis, rich, entry, starts, mayReturn, knownNoReturn,
                    symbolNames, importNames, jumpTables, blockedOn, token))
            {
                mayReturn.Add(entry);
                if (dependents.TryGetValue(entry, out var callers))
                    foreach (ulong caller in callers)
                        if (!mayReturn.Contains(caller) && queued.Add(caller)) pending.Enqueue(caller);
            }
            else
            {
                foreach (ulong callee in blockedOn)
                {
                    if (!dependents.TryGetValue(callee, out var callers))
                        dependents[callee] = callers = [];
                    callers.Add(entry);
                }
            }
        }

        // Cancellation must never turn unexamined functions into false no-return facts.
        if (token.IsCancellationRequested) return NoReturnInfo.Empty;

        var noReturnFunctions = new HashSet<ulong>(starts);
        noReturnFunctions.ExceptWith(mayReturn);

        // Record indirect import calls as well as direct calls. Scanning executable sections is safe:
        // a false-positive instruction in data has no effect unless recursive descent actually reaches it.
        var callSites = new HashSet<ulong>();
        foreach (var sec in image.Sections)
        {
            if (!sec.IsExecutable || sec.FileSize <= 0) continue;
            ulong va = sec.StartVa;
            ulong span = sec.VirtualSize > 0 ? Math.Min(sec.VirtualSize, (ulong)sec.FileSize) : (ulong)sec.FileSize;
            ulong end = sec.StartVa + span;
            while (va < end)
            {
                if (token.IsCancellationRequested) return NoReturnInfo.Empty;
                if (!dis.TryDecode(va, out var ins) || ins.Length <= 0) { va++; continue; }
                if (ins.Flow is FlowKind.Call or FlowKind.IndirectCall
                    && IsKnownNoReturnCall(image, rich, va, ins.DirectTarget, noReturnFunctions,
                        symbolNames, importNames))
                    callSites.Add(va);
                va += (ulong)ins.Length;
            }
        }

        return new NoReturnInfo(noReturnFunctions, callSites);
    }

    private static bool CanReturn(IBinaryImage image, INeutralDisassembler dis, Disassembler? rich,
        ulong entry, HashSet<ulong> starts, HashSet<ulong> mayReturn, HashSet<ulong> knownNoReturn,
        IReadOnlyDictionary<ulong, string> symbolNames, Dictionary<ulong, string?> importNames,
        IReadOnlyDictionary<ulong, ulong[]>? jumpTables, HashSet<ulong> blockedOn,
        CancellationToken token)
    {
        var work = new Stack<ulong>();
        var visited = new HashSet<ulong>();
        work.Push(entry);

        while (work.Count > 0)
        {
            if (token.IsCancellationRequested || visited.Count >= MaxInstructionsPerFunction) return true;
            ulong va = work.Pop();
            if (!visited.Add(va)) continue;

            // Reaching another discovered entry is a tail call/fall-in to that function.
            if (va != entry && starts.Contains(va))
            {
                if (mayReturn.Contains(va)) return true;
                if (!knownNoReturn.Contains(va)) blockedOn.Add(va);
                continue;
            }
            if (!image.IsExecutableVa(va) || !dis.TryDecode(va, out var ins) || ins.Length <= 0)
                return true; // unresolved flow is conservatively may-return

            ulong fall = va + (ulong)ins.Length;
            switch (ins.Flow)
            {
                case FlowKind.Ret:
                    return true;
                case FlowKind.Interrupt:
                    // A generic software interrupt can return through an OS/firmware handler (for example
                    // Linux int 0x80). Only x86 instructions that unconditionally trap are proof that normal
                    // fallthrough is impossible; an architecture-neutral interrupt is otherwise unresolved.
                    if (!IsNonReturningTrap(rich, va)) return true;
                    break;
                case FlowKind.CondJump:
                    if (ins.DirectTarget is not ulong cond || !image.IsExecutableVa(cond)) return true;
                    work.Push(cond);
                    work.Push(fall);
                    break;
                case FlowKind.Jump:
                    if (ins.DirectTarget is not ulong target || !image.IsExecutableVa(target)) return true;
                    if (target != entry && starts.Contains(target))
                    {
                        if (mayReturn.Contains(target)) return true;
                        if (!knownNoReturn.Contains(target)) blockedOn.Add(target);
                    }
                    else work.Push(target);
                    break;
                case FlowKind.IndirectJump:
                    if (jumpTables is not null && jumpTables.TryGetValue(va, out var cases) && cases.Length > 0)
                    {
                        foreach (ulong caseTarget in cases)
                            if (image.IsExecutableVa(caseTarget)) work.Push(caseTarget);
                            else return true;
                    }
                    else if (!IsKnownNoReturnTarget(image, rich, va, null, knownNoReturn,
                                 symbolNames, importNames))
                        return true;
                    break;
                case FlowKind.Call:
                case FlowKind.IndirectCall:
                    if (IsKnownNoReturnCall(image, rich, va, ins.DirectTarget, knownNoReturn,
                            symbolNames, importNames))
                        break;
                    if (ins.DirectTarget is ulong callee && starts.Contains(callee)
                        && !mayReturn.Contains(callee))
                    {
                        if (!knownNoReturn.Contains(callee)) blockedOn.Add(callee);
                        break;
                    }
                    work.Push(fall);
                    break;
                default:
                    work.Push(fall);
                    break;
            }
        }
        return false;
    }

    private static bool IsNonReturningTrap(Disassembler? dis, ulong va) =>
        dis is not null
        && dis.TryDecodeAt(va, out var ins)
        && ins.Mnemonic is Mnemonic.Int3 or Mnemonic.Ud0 or Mnemonic.Ud1 or Mnemonic.Ud2;

    private static bool IsKnownNoReturnCall(IBinaryImage image, Disassembler? rich, ulong siteVa,
        ulong? directTarget, IReadOnlySet<ulong> noReturnFunctions,
        IReadOnlyDictionary<ulong, string> symbolNames, Dictionary<ulong, string?> importNames) =>
        IsKnownNoReturnTarget(image, rich, siteVa, directTarget, noReturnFunctions, symbolNames, importNames);

    private static bool IsKnownNoReturnTarget(IBinaryImage image, Disassembler? rich, ulong siteVa,
        ulong? directTarget, IReadOnlySet<ulong> noReturnFunctions,
        IReadOnlyDictionary<ulong, string> symbolNames, Dictionary<ulong, string?> importNames)
    {
        if (directTarget is ulong target)
            return noReturnFunctions.Contains(target)
                || symbolNames.TryGetValue(target, out string? symbol) && KnownNoReturnNames.IsKnown(symbol);

        if (!importNames.TryGetValue(siteVa, out string? name))
        {
            name = ImportNameAt(image, rich, siteVa);
            importNames[siteVa] = name;
        }
        return KnownNoReturnNames.IsKnown(name);
    }

    private static string? ImportNameAt(IBinaryImage image, Disassembler? dis, ulong va)
    {
        if (dis is null || !dis.TryDecodeAt(va, out var ins)
            || ins.Mnemonic is not (Mnemonic.Call or Mnemonic.Jmp)
            || ins.Op0Kind != OpKind.Memory)
            return null;

        ulong slot = ins.IsIPRelativeMemoryOperand ? ins.IPRelativeMemoryAddress
            : ins.MemoryBase == Register.None && ins.MemoryIndex == Register.None
                ? ins.MemoryDisplacement64
                : 0;
        return slot != 0 && image.ImportsByIatVa.TryGetValue(slot, out var import) ? import.Name : null;
    }
}

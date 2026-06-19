using DisasmStudio.Core.Analysis;
using DisasmStudio.Core.Disasm;

namespace DisasmStudio.Core.IL;

/// <summary>
/// The decompiler entry point: turns one function into its four rendered levels (Low IL, Medium IL,
/// High IL, Pseudo-C). It wires the stages together — build the CFG, lift to Low IL, raise to Medium
/// IL, structure into the High IL tree, and emit — and guarantees a result: every stage is wrapped so
/// an unexpected case degrades to a note rather than throwing into the UI.
/// </summary>
public static class Decompiler
{
    private const int MaxBlocks = 6000;

    public static DecompiledFunction Decompile(Function fn, AnalysisResult result)
    {
        try
        {
            CfgBuilder.Build(result.Image, fn, result.JumpTables);
            if (fn.Blocks.Count == 0) return Note(fn.Va, "// no code recovered for this function");
            if (fn.Blocks.Count > MaxBlocks) return Note(fn.Va, $"// function too large to decompile ({fn.Blocks.Count} blocks)");

            var lifter = new Lifter(result.Image, result.Names, result.JumpTables);
            var low = lifter.Lift(fn);
            var mid = MediumLifter.Transform(low, result.Image);
            var (root, labels) = Structurer.Structure(mid);
            var comments = result.Comments;

            return new DecompiledFunction
            {
                Va = fn.Va,
                LowIl = BlockEmitter.Emit(low, comments),
                MediumIl = BlockEmitter.Emit(mid, comments),
                HighIl = StructEmitter.Emit(mid, root, labels, pseudoC: false, comments),
                PseudoC = StructEmitter.Emit(mid, root, labels, pseudoC: true, comments),
            };
        }
        catch (Exception ex)
        {
            return Note(fn.Va, "// decompilation error: " + ex.Message);
        }
    }

    private static DecompiledFunction Note(ulong va, string msg)
    {
        var lines = NoteLines(va, msg);
        return new DecompiledFunction { Va = va, LowIl = lines, MediumIl = lines, HighIl = lines, PseudoC = lines };
    }

    private static IReadOnlyList<DecompLine> NoteLines(ulong va, string msg)
    {
        var w = new IlWriter();
        w.T(msg, AsmTokenKind.Comment);
        w.Flush(va, 0);
        return w.Lines;
    }

    /// <summary>Decompile a function to <em>compilable</em> C lines (typed pointer casts, indirect-call
    /// helper, numeric data addresses, sanitized names). Used by the compilable export; not cached.</summary>
    public static IReadOnlyList<DecompLine> DecompileToCompilableC(Function fn, AnalysisResult result)
    {
        try
        {
            CfgBuilder.Build(result.Image, fn, result.JumpTables);
            if (fn.Blocks.Count == 0) return NoteLines(fn.Va, "/* no code recovered */");
            if (fn.Blocks.Count > MaxBlocks) return NoteLines(fn.Va, $"/* function too large to decompile ({fn.Blocks.Count} blocks) */");

            var low = new Lifter(result.Image, result.Names, result.JumpTables).Lift(fn);
            var mid = MediumLifter.Transform(low, result.Image);
            var (root, labels) = Structurer.Structure(mid);
            return StructEmitter.Emit(mid, root, labels, pseudoC: true, result.Comments, compilable: true);
        }
        catch (Exception ex)
        {
            return NoteLines(fn.Va, "/* decompilation error: " + ex.Message.Replace("*/", "* /") + " */");
        }
    }
}

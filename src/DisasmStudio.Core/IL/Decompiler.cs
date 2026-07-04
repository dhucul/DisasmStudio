using DisasmStudio.Core.Analysis;
using DisasmStudio.Core.Disasm;

namespace DisasmStudio.Core.IL;

/// <summary>Lifts a function's instructions to Low IL. Implemented by the x86/x64 <see cref="Lifter"/>
/// (Iced) and the ARM-family <see cref="ArmLifter"/> (Capstone); both produce the same neutral IL.</summary>
public interface ILifter
{
    LiftedFunction Lift(Function fn);
}

/// <summary>
/// The decompiler entry point: turns one function into its four rendered levels (Low IL, Medium IL,
/// High IL, Pseudo-C). It wires the stages together — build the CFG, lift to Low IL, raise to Medium
/// IL, structure into the High IL tree, and emit — and guarantees a result: every stage is wrapped so
/// an unexpected case degrades to a note rather than throwing into the UI.
/// </summary>
public static class Decompiler
{
    private const int MaxBlocks = 6000;

    /// <summary>Lift to Low IL with the right front-end for the image's architecture.</summary>
    private static LiftedFunction LiftLow(Function fn, AnalysisResult result)
    {
        if (result.Image.IsArm)
        {
            using var arm = new ArmLifter(result.Image, result.Names, result.JumpTables);
            return arm.Lift(fn);
        }
        return new Lifter(result.Image, result.Names, result.JumpTables).Lift(fn);
    }

    public static DecompiledFunction Decompile(Function fn, AnalysisResult result)
    {
        try
        {
            // An IAT slot misfiled as a function — some images keep the import table inside .text, so a
            // call-through target looks like code. It's a pointer, not an instruction stream; say so
            // plainly instead of disassembling the pointer bytes into noise.
            if (result.Image.ImportsByIatVa.TryGetValue(fn.Va, out var imp))
                return Note(fn.Va, $"// import slot -> {imp.Module}!{imp.Name} (data, not code)");

            CfgBuilder.Build(result.Image, fn, result.JumpTables);
            if (fn.Blocks.Count == 0) return Note(fn.Va, "// no code recovered for this function");
            if (fn.Blocks.Count > MaxBlocks) return Note(fn.Va, $"// function too large to decompile ({fn.Blocks.Count} blocks)");

            var low = LiftLow(fn, result);
            var model = ArchModel.For(result.Image);
            var mid = MediumLifter.Transform(low, result.Image, model);
            var (root, labels) = Structurer.Structure(mid);
            var comments = result.Comments;

            return new DecompiledFunction
            {
                Va = fn.Va,
                LowIl = BlockEmitter.Emit(low, comments, model),
                MediumIl = BlockEmitter.Emit(mid, comments, model),
                HighIl = StructEmitter.Emit(mid, root, labels, pseudoC: false, comments, model),
                PseudoC = StructEmitter.Emit(mid, root, labels, pseudoC: true, comments, model),
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
            if (result.Image.ImportsByIatVa.TryGetValue(fn.Va, out var imp))
                return NoteLines(fn.Va, $"/* import slot -> {imp.Module}!{imp.Name} (data, not code) */");

            CfgBuilder.Build(result.Image, fn, result.JumpTables);
            if (fn.Blocks.Count == 0) return NoteLines(fn.Va, "/* no code recovered */");
            if (fn.Blocks.Count > MaxBlocks) return NoteLines(fn.Va, $"/* function too large to decompile ({fn.Blocks.Count} blocks) */");

            var low = LiftLow(fn, result);
            var model = ArchModel.For(result.Image);
            var mid = MediumLifter.Transform(low, result.Image, model);
            var (root, labels) = Structurer.Structure(mid);
            return StructEmitter.Emit(mid, root, labels, pseudoC: true, result.Comments, model, compilable: true);
        }
        catch (Exception ex)
        {
            return NoteLines(fn.Va, "/* decompilation error: " + ex.Message.Replace("*/", "* /") + " */");
        }
    }
}

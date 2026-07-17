using System.Text;
using DisasmStudio.Core.Unpacking;

namespace DisasmStudio.Debug.Unpacking;

/// <summary>
/// Builds a clean, re-openable PE from a <b>frozen live debuggee</b>, reusing the exact dump → IAT-rebuild →
/// PE-writer pipeline the OEP unpacker uses. The image is captured through the engine's own breakpoint-masked
/// reader (<see cref="DebuggerEngine.DumpImage"/> / <see cref="DebuggerEngine.ReadMemory"/>), so any planted
/// int3 / memory-breakpoint page protection is transparent to the dump; imports are resolved against the live
/// module exports (<see cref="ModuleExportResolver"/>).
///
/// <para>Shared by <see cref="UnpackSession"/> (automatic, at a located OEP) and the Memory Map's manual
/// "Dump image as PE" command (at the current stop — typically where a section execute memory breakpoint just
/// broke, which is a de-facto OEP). Call only while the debuggee is stopped.</para>
/// </summary>
public static class LivePeDump
{
    /// <summary>Outcome of a live PE dump. <see cref="Bytes"/> is the rebuilt PE ([] when the image could not be
    /// dumped or parsed); <see cref="Log"/> mirrors the pipeline's progress lines for the caller to surface.</summary>
    public sealed record Result(bool Ok, byte[] Bytes, uint SizeOfImage, ulong Oep,
        int ImportsResolved, int ImportsUnresolved, string Log);

    /// <summary>Dump the main image at <paramref name="oepVa"/> and rebuild it into an openable PE.
    /// <paramref name="oepVa"/> is baked as the entry (clamped to the image; falls back to the header entry when
    /// out of range). <paramref name="preferredImageBase"/> is the file's on-disk preferred base, used for
    /// PeBuilder's relocation choice.</summary>
    public static Result Build(DebuggerEngine eng, ulong oepVa, ulong preferredImageBase)
    {
        var sb = new StringBuilder();
        void Log(string m) => sb.AppendLine(m);
        void LogLines(string block)
        {
            foreach (var line in block.Split('\n', StringSplitOptions.RemoveEmptyEntries)) Log(line.TrimEnd());
        }

        ulong imageBase = eng.ImageBase;
        var image = eng.DumpImage(imageBase, out uint sizeOfImage);
        if (image.Length == 0 || !PeView.TryParse(image, out var view))
        {
            Log("Failed to dump or parse the live image (is the debuggee stopped, with its main image mapped?).");
            return new Result(false, [], 0, 0, 0, 0, sb.ToString());
        }
        Log($"Dumped image: {sizeOfImage:X} bytes from base {imageBase:X}.");

        // OEP: the address the caller stopped at (an execute-bp hit / current IP). Clamp to the image; if it is
        // outside (e.g. execution was in a helper module), fall back to the header entry so the PE still opens.
        uint oepRva = oepVa >= imageBase && oepVa < imageBase + sizeOfImage
            ? (uint)(oepVa - imageBase)
            : view.EntryRva;
        ulong effectiveOep = imageBase + oepRva;
        if (effectiveOep != oepVa)
            Log($"OEP {oepVa:X} is outside the image; using the header entry {effectiveOep:X} instead.");

        MemReader mem = (va, count) => eng.ReadMemory(va, count);
        var resolver = new ModuleExportResolver(eng.Modules, mem);
        Log($"Indexed {resolver.ModuleCount} module(s), {resolver.ExportCount} export(s).");

        var iat = ImportRebuilder.Rebuild(mem, resolver, view, imageBase, effectiveOep);
        LogLines(iat.Log);

        var outBytes = PeBuilder.Build(image, view, oepRva, iat.Ok ? iat : null, imageBase, preferredImageBase, out var buildLog);
        LogLines(buildLog);

        return new Result(true, outBytes, sizeOfImage, effectiveOep, iat.Resolved, iat.Unresolved, sb.ToString());
    }
}

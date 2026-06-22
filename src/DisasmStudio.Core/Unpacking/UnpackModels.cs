namespace DisasmStudio.Core.Unpacking;

/// <summary>Reads up to <paramref name="count"/> bytes of image/process memory at virtual address
/// <paramref name="va"/>. Returns fewer bytes (or an empty array) for unmapped/partial ranges. Lets Core
/// unpacking logic work against either a static dump buffer or a live debuggee without referencing
/// DisasmStudio.Debug.</summary>
public delegate byte[] MemReader(ulong va, int count);

/// <summary>One resolved import: the owning module and either a name or an ordinal.</summary>
public sealed record ApiRef(string Module, string? Name, ushort Ordinal, bool ByOrdinal)
{
    public string Display => ByOrdinal ? $"{Module}#Ordinal_{Ordinal}" : $"{Module}!{Name}";
}

/// <summary>Resolves an absolute API address — the kind of value found in a post-unpack IAT slot — back to
/// its owning module and export. Implemented in DisasmStudio.Debug over the live loaded-module list
/// (<c>ModuleExportResolver</c>); kept as an interface so the IAT rebuilder stays in Core and testable with
/// a synthetic resolver.</summary>
public interface IApiResolver
{
    /// <summary>Resolve an exact export address, or null if it isn't a known export.</summary>
    ApiRef? Resolve(ulong apiVa);

    /// <summary>True if <paramref name="va"/> falls inside any loaded module's image range. Used to tell an
    /// IAT slot (points into a module) from a redirected/trampoline slot (points elsewhere).</summary>
    bool IsInModule(ulong va);

    /// <summary>The nearest export at or below <paramref name="va"/> within the same module, with the byte
    /// offset from it. Lets the rebuilder recover an import whose slot points slightly past an export entry
    /// (hot-patch pads, etc.) instead of leaving a stale, crash-on-reload address.</summary>
    ApiRef? ResolveNearest(ulong va, out uint delta);
}

using DisasmStudio.Core.Unpacking;

namespace DisasmStudio.Debug.Unpacking;

/// <summary>
/// Resolves absolute API addresses (the values found in a post-unpack IAT) back to (module, export) by
/// reading each loaded module's export directory directly from process memory. Built once at OEP, when all
/// the target's dependencies are mapped at their real ASLR bases. Implements <see cref="IApiResolver"/> so
/// the Core <see cref="ImportRebuilder"/> can stay debugger-agnostic.
/// </summary>
public sealed class ModuleExportResolver : IApiResolver
{
    private readonly Dictionary<ulong, ApiRef> _byAddress = [];
    private readonly List<(ulong Lo, ulong Hi)> _ranges = [];

    public int ModuleCount { get; }
    public int ExportCount => _byAddress.Count;

    public ModuleExportResolver(IReadOnlyList<ModuleInfo> modules, MemReader mem)
    {
        int n = 0;
        foreach (var m in modules)
        {
            if (TryIndexModule(m, mem)) n++;
        }
        ModuleCount = n;
    }

    public ApiRef? Resolve(ulong apiVa) => _byAddress.GetValueOrDefault(apiVa);

    public bool IsInModule(ulong va)
    {
        foreach (var (lo, hi) in _ranges) if (va >= lo && va < hi) return true;
        return false;
    }

    public ApiRef? ResolveNearest(ulong va, out uint delta)
    {
        delta = 0;
        // Bound the search to the module that contains va, so we never attribute across modules.
        ulong modLo = 0;
        foreach (var (lo, hi) in _ranges) if (va >= lo && va < hi) { modLo = lo; break; }
        if (modLo == 0) return null;
        ulong best = 0; ApiRef? bestApi = null;
        foreach (var kv in _byAddress)
            if (kv.Key >= modLo && kv.Key <= va && kv.Key > best) { best = kv.Key; bestApi = kv.Value; }
        if (bestApi is null) return null;
        delta = (uint)(va - best);
        return bestApi;
    }

    private bool TryIndexModule(ModuleInfo m, MemReader mem)
    {
        ulong b = m.Base;
        var hdr = mem(b, 0x1000);
        if (hdr.Length < 0x200 || !PeView.TryParse(hdr, out var view)) return false;

        uint imageSize = view.SizeOfImage != 0 ? view.SizeOfImage : 0x10000;
        _ranges.Add((b, b + imageSize));

        var (expRva, expSize) = view.DataDir(PeConstants.DirExport);
        if (expRva == 0) return true;   // a module with no exports still defines a range

        var dir = mem(b + expRva, 40);
        if (dir.Length < 40) return true;
        uint ordinalBase = U32(dir, 0x10);
        uint numFuncs = Math.Min(U32(dir, 0x14), 200_000);
        uint numNames = Math.Min(U32(dir, 0x18), 200_000);
        uint eatRva = U32(dir, 0x1C), nameTblRva = U32(dir, 0x20), ordTblRva = U32(dir, 0x24);

        var eat = mem(b + eatRva, (int)numFuncs * 4);
        var nameTbl = mem(b + nameTblRva, (int)numNames * 4);
        var ordTbl = mem(b + ordTblRva, (int)numNames * 2);

        // Map export-index → name for the named exports.
        var nameByIndex = new Dictionary<uint, string>();
        for (uint i = 0; i < numNames; i++)
        {
            if ((i + 1) * 4 > (uint)nameTbl.Length || (i + 1) * 2 > (uint)ordTbl.Length) break;
            uint nameRva = U32(nameTbl, (int)i * 4);
            ushort idx = U16(ordTbl, (int)i * 2);
            string name = ReadCString(mem, b + nameRva);
            if (name.Length > 0) nameByIndex[idx] = name;
        }

        ulong expLo = expRva, expHi = expRva + expSize;
        for (uint f = 0; f < numFuncs; f++)
        {
            if ((f + 1) * 4 > (uint)eat.Length) break;
            uint funcRva = U32(eat, (int)f * 4);
            if (funcRva == 0) continue;
            if (funcRva >= expLo && funcRva < expHi) continue;   // forwarder — the IAT points at the target module
            ulong va = b + funcRva;
            ushort ordinal = (ushort)(ordinalBase + f);
            var api = nameByIndex.TryGetValue(f, out var nm)
                ? new ApiRef(m.Name, nm, ordinal, false)
                : new ApiRef(m.Name, null, ordinal, true);
            // Prefer a named export over an ordinal-only alias at the same address.
            if (!_byAddress.TryGetValue(va, out var existing) || (existing.ByOrdinal && !api.ByOrdinal))
                _byAddress[va] = api;
        }
        return true;
    }

    private static string ReadCString(MemReader mem, ulong va, int max = 512)
    {
        var b = mem(va, max);
        int end = Array.IndexOf(b, (byte)0);
        if (end < 0) end = b.Length;
        return System.Text.Encoding.ASCII.GetString(b, 0, end);
    }

    private static ushort U16(byte[] b, int o) => o + 2 <= b.Length ? BitConverter.ToUInt16(b, o) : (ushort)0;
    private static uint U32(byte[] b, int o) => o + 4 <= b.Length ? BitConverter.ToUInt32(b, o) : 0;
}

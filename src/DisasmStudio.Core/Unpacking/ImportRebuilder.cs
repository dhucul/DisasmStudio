using System.Text;
using Iced.Intel;

namespace DisasmStudio.Core.Unpacking;

/// <summary>One rebuilt import within a contiguous IAT run.</summary>
public sealed record RebuiltImport(string? Name, ushort Ordinal, bool ByOrdinal);

/// <summary>A maximal run of consecutive same-module IAT slots. <see cref="FirstThunkRva"/> points at the
/// first slot in the <b>existing</b> IAT (which the OEP code already references), so we never move the IAT —
/// we only emit a fresh descriptor + ILT (Import Lookup Table) that names the slots, and the OS loader
/// repopulates them at load time.</summary>
public sealed record ImportRun(string Dll, uint FirstThunkRva, List<RebuiltImport> Imports);

/// <summary>The outcome of reconstructing the imports of a dumped image.</summary>
public sealed record IatRebuildResult(
    List<ImportRun> Runs, int Resolved, int Unresolved, List<ulong> UnresolvedSlots,
    ulong IatStartVa, uint IatStartRva, uint IatSize, string Log)
{
    public bool Ok => Runs.Count > 0 && Resolved > 0;
}

/// <summary>
/// Reconstructs a PE's import table from a post-unpack memory image, ImpRec/Scylla-style: locate the IAT
/// (the array of resolved API pointers the unpacked code calls through), resolve each slot back to a
/// (module, export) via an <see cref="IApiResolver"/>, follow simple redirection trampolines, group the
/// slots into contiguous per-module runs, and serialize a fresh import directory + ILT + hint/name tables.
/// The IAT itself is left in place so the OEP's <c>call [slot]</c> references stay valid; the new directory
/// just describes it so a clean reload re-binds it.
/// </summary>
public static class ImportRebuilder
{
    public static IatRebuildResult Rebuild(MemReader mem, IApiResolver resolver, PeView view, ulong imageBase, ulong? oepVa = null)
    {
        bool is64 = view.Is64;
        int ptr = is64 ? 8 : 4;
        var log = new StringBuilder();

        var (iatStartVa, iatSize) = LocateIat(mem, resolver, view, imageBase, ptr, is64, oepVa, log);
        if (iatStartVa == 0 || iatSize == 0)
            return new IatRebuildResult([], 0, 0, [], 0, 0, 0, log.Append("IAT not located.\n").ToString());

        var slots = mem(iatStartVa, (int)iatSize);
        int slotCount = slots.Length / ptr;

        var runs = new List<ImportRun>();
        var unresolved = new List<ulong>();
        int resolved = 0;
        ImportRun? current = null;

        for (int i = 0; i < slotCount; i++)
        {
            ulong slotVa = iatStartVa + (ulong)(i * ptr);
            ulong value = is64 ? BitConverter.ToUInt64(slots, i * ptr) : BitConverter.ToUInt32(slots, i * ptr);
            uint slotRva = (uint)(slotVa - imageBase);

            if (value == 0) { current = null; continue; }   // a null slot terminates the current run

            var (api, ord, byOrd) = ResolveSlot(mem, resolver, value, is64);
            if (api is null)
            {
                current = null; unresolved.Add(slotVa);
                if (unresolved.Count <= 4)
                {
                    var near = resolver.ResolveNearest(value, out uint d);
                    log.Append($"  unresolved slot {slotVa:X} = {value:X} (inModule={resolver.IsInModule(value)}, nearest={near?.Display ?? "?"}+{d:X})\n");
                }
                continue;
            }

            if (current is null || !current.Dll.Equals(api.Module, StringComparison.OrdinalIgnoreCase))
            {
                current = new ImportRun(api.Module, slotRva, []);
                runs.Add(current);
            }
            current.Imports.Add(byOrd
                ? new RebuiltImport(null, ord, true)
                : new RebuiltImport(api.Name, api.Ordinal, api.ByOrdinal));
            resolved++;
        }

        log.Append($"IAT @ {iatStartVa:X} size {iatSize:X}: {resolved} resolved, {unresolved.Count} unresolved, {runs.Count} descriptor run(s).\n");
        return new IatRebuildResult(runs, resolved, unresolved.Count, unresolved, iatStartVa,
            (uint)(iatStartVa - imageBase), iatSize, log.ToString());
    }

    /// <summary>Resolve a slot value to an export — directly, or by following one redirection hop. A value that
    /// points into a module but isn't an exact export is NOT an import (e.g. a CFG guard pointer the loader
    /// writes); it's left unresolved so it doesn't get fabricated into a bogus import.</summary>
    private static (ApiRef? Api, ushort Ord, bool ByOrd) ResolveSlot(MemReader mem, IApiResolver resolver, ulong value, bool is64)
    {
        if (resolver.Resolve(value) is { } direct)
            return (direct, direct.Ordinal, direct.ByOrdinal);
        if (!resolver.IsInModule(value))   // points outside any module → trampoline/redirected stub
        {
            ulong target = FollowTrampoline(mem, value, is64);
            if (target != 0 && resolver.Resolve(target) is { } via)
                return (via, via.Ordinal, via.ByOrdinal);
        }
        return (null, 0, false);
    }

    /// <summary>Follow one redirection hop from a stub: <c>jmp [mem]</c>, <c>jmp rel</c>, <c>push imm; ret</c>,
    /// or <c>mov reg, imm; jmp reg</c>. Returns the resolved API address, or 0 if the shape isn't recognised.</summary>
    private static ulong FollowTrampoline(MemReader mem, ulong stubVa, bool is64)
    {
        var code = mem(stubVa, 16);
        if (code.Length < 2) return 0;
        var dec = Iced.Intel.Decoder.Create(is64 ? 64 : 32, new ByteArrayCodeReader(code));
        dec.IP = stubVa;
        dec.Decode(out var ins);
        if (ins.IsInvalid) return 0;

        if (ins.FlowControl is FlowControl.UnconditionalBranch or FlowControl.IndirectBranch)
        {
            if (ins.Op0Kind is OpKind.NearBranch16 or OpKind.NearBranch32 or OpKind.NearBranch64)
                return ins.NearBranchTarget;                       // jmp rel → target is the API
            if (ins.Op0Kind == OpKind.Memory)                      // jmp [ptr] → read the pointer
            {
                ulong memAddr = ins.IsIPRelativeMemoryOperand ? ins.IPRelativeMemoryAddress : ins.MemoryDisplacement64;
                if (memAddr == 0) return 0;
                var p = mem(memAddr, is64 ? 8 : 4);
                if (p.Length < (is64 ? 8 : 4)) return 0;
                return is64 ? BitConverter.ToUInt64(p, 0) : BitConverter.ToUInt32(p, 0);
            }
        }
        // push imm32 ; ret
        if (ins.Mnemonic == Mnemonic.Push && ins.Op0Kind is OpKind.Immediate32 or OpKind.Immediate8to32 or OpKind.Immediate8to64 or OpKind.Immediate64)
        {
            ulong t = ins.Op0Kind == OpKind.Immediate64 ? ins.Immediate64 : ins.Immediate32;
            dec.Decode(out var next);
            if (next.FlowControl == FlowControl.Return) return t;
        }
        // mov reg, imm ; jmp reg
        if (ins.Mnemonic == Mnemonic.Mov && ins.Op0Kind == OpKind.Register &&
            ins.Op1Kind is OpKind.Immediate32 or OpKind.Immediate64)
        {
            ulong t = ins.Op1Kind == OpKind.Immediate64 ? ins.Immediate64 : ins.Immediate32;
            dec.Decode(out var next);
            if (next.FlowControl == FlowControl.IndirectBranch && next.Op0Kind == OpKind.Register) return t;
        }
        return 0;
    }

    // ---- IAT location ----
    // Several strategies can each point at *an* IAT; for a packed file the packed import descriptors only
    // describe the stub's tiny table, not the full table the unpacked code calls through. So gather every
    // candidate region and keep the one whose slots RESOLVE to the most imports — which auto-selects the real
    // OEP IAT (code scan) for packers and the precise data-directory table for normal images.
    private static (ulong Va, uint Size) LocateIat(
        MemReader mem, IApiResolver resolver, PeView view, ulong imageBase, int ptr, bool is64, ulong? oepVa, StringBuilder log)
    {
        // Candidates are tried in PRIORITY order — authoritative PE structures first, the heuristic code scan
        // last — and the pick uses a strict ">" on resolvable-slot count, so an earlier (more trustworthy)
        // candidate wins ties. The code scan only wins when it resolves STRICTLY more, which is exactly the
        // packed case (the packed descriptors describe only the stub's tiny table).
        var candidates = new List<(ulong Va, uint Size, string Src)>();

        // 1) The image's own IAT data directory, grown.
        var (iatRva, _) = view.DataDir(PeConstants.DirIat);
        if (iatRva != 0)
        {
            var g = GrowRun(mem, resolver, imageBase + iatRva, ptr);
            if (g.Size > 0) candidates.Add((g.Va, g.Size, "data directory [12]"));
        }

        // 2) The existing import descriptors' FirstThunks, each grown.
        var (impRva, _) = view.DataDir(PeConstants.DirImport);
        if (impRva != 0)
        {
            var desc = mem(imageBase + impRva, 20 * 256);
            for (int d = 0; d + 20 <= desc.Length; d += 20)
            {
                uint firstThunk = BitConverter.ToUInt32(desc, d + 16);
                uint nameRva = BitConverter.ToUInt32(desc, d + 12);
                if (firstThunk == 0 && nameRva == 0) break;
                if (firstThunk == 0) continue;
                var g = GrowRun(mem, resolver, imageBase + firstThunk, ptr);
                if (g.Size > 0) { candidates.Add((g.Va, g.Size, "import descriptor FirstThunk")); break; }
            }
        }

        // 3) From the OEP code: indirect call/jmp/mov through memory whose target points into a module = an IAT
        // slot. Anchor on those and grow to the full contiguous table. The reliable fallback for packers whose
        // on-disk import structures describe only the unpacking stub.
        if (oepVa is ulong oep && oep != 0)
        {
            var r = LocateIatFromCode(mem, resolver, oep, is64, ptr);
            if (r.Size > 0) candidates.Add((r.Va, r.Size, "OEP code scan"));
        }

        // 4) Last resort: scan data sections for the longest module-pointer run.
        if (candidates.Count == 0)
            return ScanForIat(mem, resolver, view, imageBase, ptr, log);

        // Pick the candidate with the most resolvable slots.
        var best = candidates[0]; int bestScore = -1;
        foreach (var c in candidates)
        {
            int score = CountResolved(mem, resolver, c.Va, c.Size, ptr, is64);
            log.Append($"  IAT candidate ({c.Src}) @ {c.Va:X} size {c.Size:X}: {score} resolvable.\n");
            if (score > bestScore) { bestScore = score; best = c; }
        }
        log.Append($"IAT chosen: {best.Src} @ {best.Va:X} size {best.Size:X}.\n");
        return (best.Va, best.Size);
    }

    /// <summary>Find IAT slots by scanning the OEP code for memory operands whose stored pointer resolves into a
    /// loaded module, then grow the contiguous table around the lowest such slot.</summary>
    private static (ulong Va, uint Size) LocateIatFromCode(MemReader mem, IApiResolver resolver, ulong oepVa, bool is64, int ptr)
    {
        var code = mem(oepVa, 0x4000);
        if (code.Length < 16) return (0, 0);
        var dec = Iced.Intel.Decoder.Create(is64 ? 64 : 32, new ByteArrayCodeReader(code));
        dec.IP = oepVa;
        ulong endIp = oepVa + (ulong)code.Length;
        ulong lowest = 0; int found = 0;
        for (int guard = 0; guard < 6000 && dec.IP < endIp; guard++)
        {
            dec.Decode(out var ins);
            if (ins.IsInvalid) continue;   // data / misdecode — keep scanning
            for (int op = 0; op < ins.OpCount; op++)
            {
                if (ins.GetOpKind(op) != OpKind.Memory) continue;
                ulong addr = ins.IsIPRelativeMemoryOperand ? ins.IPRelativeMemoryAddress
                    : (ins.MemoryBase == Register.None && ins.MemoryIndex == Register.None ? ins.MemoryDisplacement64 : 0);
                if (addr == 0) continue;
                var pb = mem(addr, ptr);
                if (pb.Length < ptr) continue;
                ulong val = ptr == 8 ? BitConverter.ToUInt64(pb, 0) : BitConverter.ToUInt32(pb, 0);
                if (resolver.Resolve(val) is null && !resolver.IsInModule(val)) continue;   // not an API pointer
                found++;
                if (lowest == 0 || addr < lowest) lowest = addr;
            }
        }
        if (found == 0 || lowest == 0) return (0, 0);
        return GrowBidirectional(mem, resolver, lowest, ptr);
    }

    /// <summary>Grow a confirmed IAT slot in both directions across resolving slots (tolerating a single null
    /// between per-module groups) to span the whole table.</summary>
    private static (ulong Va, uint Size) GrowBidirectional(MemReader mem, IApiResolver resolver, ulong anchor, int ptr)
    {
        ulong start = anchor, probe = anchor; int gap = 0;
        while (true)
        {
            ulong cand = probe - (ulong)ptr;
            if (cand >= probe) break;   // underflow guard
            var b = mem(cand, ptr);
            if (b.Length < ptr) break;
            ulong v = ptr == 8 ? BitConverter.ToUInt64(b, 0) : BitConverter.ToUInt32(b, 0);
            if (v == 0) { if (++gap >= 2) break; probe = cand; continue; }
            if (resolver.Resolve(v) is not null || resolver.IsInModule(v)) { start = cand; probe = cand; gap = 0; }
            else break;
        }
        return GrowRun(mem, resolver, start, ptr);
    }

    private static int CountResolved(MemReader mem, IApiResolver resolver, ulong va, uint size, int ptr, bool is64)
    {
        var b = mem(va, (int)Math.Min(size, 256u * 1024));
        int n = b.Length / ptr, c = 0;
        for (int i = 0; i < n; i++)
        {
            ulong v = ptr == 8 ? BitConverter.ToUInt64(b, i * ptr) : BitConverter.ToUInt32(b, i * ptr);
            if (v != 0 && ResolveSlot(mem, resolver, v, is64).Api is not null) c++;
        }
        return c;
    }

    /// <summary>Extend a confirmed IAT start forwards while slots keep pointing into modules (tolerating a
    /// single null terminator between descriptor groups).</summary>
    private static (ulong Va, uint Size) GrowRun(MemReader mem, IApiResolver resolver, ulong start, int ptr)
    {
        const int MaxSlots = 8192;
        int count = 0, trailingNulls = 0, pointerOnly = 0;
        for (int i = 0; i < MaxSlots; i++)
        {
            var b = mem(start + (ulong)(i * ptr), ptr);
            if (b.Length < ptr) break;
            ulong v = ptr == 8 ? BitConverter.ToUInt64(b, 0) : BitConverter.ToUInt32(b, 0);
            if (v == 0)
            {
                if (++trailingNulls >= 2) break;   // two nulls in a row ends the table
                count = i + 1;
                continue;
            }
            trailingNulls = 0;
            // A slot that resolves (or points into a module) is a confirmed IAT entry; a merely pointer-shaped
            // value is tolerated only in short bursts, so an unindexed import doesn't truncate the table but a
            // run of non-pointer data past the IAT can't drag the table on into arbitrary memory.
            if (resolver.Resolve(v) is not null || resolver.IsInModule(v)) { count = i + 1; pointerOnly = 0; }
            else if (LooksLikePointer(v) && ++pointerOnly <= 2) count = i + 1;
            else break;
        }
        return (start, (uint)(count * ptr));
    }

    private static bool LooksLikePointer(ulong v) => v > 0x10000 && v < 0x7FFF_FFFF_FFFF;

    private static (ulong Va, uint Size) ScanForIat(
        MemReader mem, IApiResolver resolver, PeView view, ulong imageBase, int ptr, StringBuilder log)
    {
        ulong bestVa = 0; uint bestSize = 0;
        foreach (var s in view.Sections)
        {
            if (s.IsExecutable) continue;                         // the IAT lives in data, not code
            uint size = Math.Min(Math.Max(s.VirtualSize, s.SizeOfRawData), 4u << 20);
            if (size < (uint)(ptr * 4)) continue;
            var data = mem(imageBase + s.VirtualAddress, (int)size);
            int n = data.Length / ptr;
            int runStart = -1, runLen = 0;
            for (int i = 0; i <= n; i++)
            {
                bool isApi = false;
                if (i < n)
                {
                    ulong v = ptr == 8 ? BitConverter.ToUInt64(data, i * ptr) : BitConverter.ToUInt32(data, i * ptr);
                    isApi = v != 0 && (resolver.Resolve(v) is not null || resolver.IsInModule(v));
                }
                if (isApi) { if (runStart < 0) runStart = i; runLen++; }
                else
                {
                    if (runLen > 0 && runLen * ptr > bestSize)
                    {
                        bestSize = (uint)(runLen * ptr);
                        bestVa = imageBase + s.VirtualAddress + (ulong)(runStart * ptr);
                    }
                    runStart = -1; runLen = 0;
                }
            }
        }
        if (bestVa != 0) log.Append($"IAT located by scan @ {bestVa:X} ({bestSize:X} bytes).\n");
        return (bestVa, bestSize);
    }

    // ---- serialize a fresh import section (descriptors + ILTs + strings) ----
    /// <summary>Serialize the import directory for <paramref name="runs"/> into a self-contained section
    /// placed at <paramref name="sectionRva"/>. The descriptor array starts at the section base
    /// (so the Import data directory RVA == <paramref name="sectionRva"/>). Returns the bytes and the
    /// descriptor-array size (for the data-directory entry).</summary>
    public static byte[] SerializeImportSection(IReadOnlyList<ImportRun> runs, uint sectionRva, bool is64, out uint descriptorSize)
    {
        int ptr = is64 ? 8 : 4;
        ulong ordinalFlag = is64 ? 0x8000_0000_0000_0000UL : 0x8000_0000UL;

        descriptorSize = (uint)((runs.Count + 1) * 20);
        uint iltBase = sectionRva + descriptorSize;

        // Lay out the ILTs, recording each run's ILT RVA.
        var iltRva = new uint[runs.Count];
        uint cursor = iltBase;
        for (int i = 0; i < runs.Count; i++)
        {
            iltRva[i] = cursor;
            cursor += (uint)((runs[i].Imports.Count + 1) * ptr);
        }
        uint stringsBase = cursor;

        // Build the string pool (DLL names + hint/name blobs) and record RVAs.
        var pool = new List<byte>();
        var dllNameRva = new uint[runs.Count];
        var nameRva = new Dictionary<(int Run, int Idx), uint>();
        for (int i = 0; i < runs.Count; i++)
        {
            dllNameRva[i] = stringsBase + (uint)pool.Count;
            pool.AddRange(Encoding.ASCII.GetBytes(runs[i].Dll));
            pool.Add(0);
            if ((pool.Count & 1) != 0) pool.Add(0);
            for (int j = 0; j < runs[i].Imports.Count; j++)
            {
                var imp = runs[i].Imports[j];
                if (imp.ByOrdinal) continue;
                nameRva[(i, j)] = stringsBase + (uint)pool.Count;
                pool.Add(0); pool.Add(0);   // Hint = 0
                pool.AddRange(Encoding.ASCII.GetBytes(imp.Name ?? ""));
                pool.Add(0);
                if ((pool.Count & 1) != 0) pool.Add(0);
            }
        }

        uint total = stringsBase - sectionRva + (uint)pool.Count;
        var buf = new byte[total];

        // Descriptors.
        for (int i = 0; i < runs.Count; i++)
        {
            int d = i * 20;
            WriteU32(buf, d + 0, iltRva[i]);                 // OriginalFirstThunk (ILT)
            WriteU32(buf, d + 4, 0);                          // TimeDateStamp
            WriteU32(buf, d + 8, 0);                          // ForwarderChain
            WriteU32(buf, d + 12, dllNameRva[i]);             // Name
            WriteU32(buf, d + 16, runs[i].FirstThunkRva);     // FirstThunk → existing IAT
        }
        // (null terminator descriptor is already zero)

        // ILTs.
        for (int i = 0; i < runs.Count; i++)
        {
            int o = (int)(iltRva[i] - sectionRva);
            for (int j = 0; j < runs[i].Imports.Count; j++)
            {
                var imp = runs[i].Imports[j];
                ulong thunk = imp.ByOrdinal ? (ordinalFlag | imp.Ordinal) : nameRva[(i, j)];
                WritePtr(buf, o + j * ptr, thunk, is64);
            }
            // trailing null thunk already zero
        }

        // Strings.
        pool.CopyTo(buf, (int)(stringsBase - sectionRva));
        return buf;
    }

    private static void WriteU32(byte[] b, int off, uint v) => BitConverter.GetBytes(v).CopyTo(b, off);
    private static void WritePtr(byte[] b, int off, ulong v, bool is64)
    {
        if (is64) BitConverter.GetBytes(v).CopyTo(b, off);
        else BitConverter.GetBytes((uint)v).CopyTo(b, off);
    }
}

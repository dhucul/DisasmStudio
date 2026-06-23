using DisasmStudio.Core.Disasm;
using DisasmStudio.Core.Formats;
using DisasmStudio.Core.Unpacking;
using Iced.Intel;

namespace DisasmStudio.Core.Devirt;

/// <summary>
/// Lightweight forensic pass for virtualizer dumps when the semantic devirtualizer cannot recover a VM.
/// It does not invent handler meanings; it explains what the snapshot contains: entropy by section,
/// indirect-branch forms, pointer-table-looking data, and deliberate null-write crash sites.
/// </summary>
public static class VmTriage
{
    private const int MaxInstructions = 600_000;
    private const int MaxBranchSamples = 24;
    private const int MaxTables = 24;
    private const int MaxCrashes = 24;

    public static VmTriageResult Run(IBinaryImage image)
    {
        var sections = SectionSummaries(image);
        var branches = new List<VmIndirectBranchSite>();
        var crashes = new List<VmSelfCrashSite>();
        int scanned = 0, indirect = 0, regIndirect = 0, memIndirect = 0, indexedMemIndirect = 0;

        var dis = new Disassembler(image);
        var fmt = new AsmFormatter();
        var window = new Queue<TraceInsn>();

        foreach (var sec in image.Sections.OrderBy(s => s.StartVa))
        {
            if (!sec.IsExecutable || sec.FileSize <= 0) continue;
            window.Clear();
            ulong span = sec.VirtualSize > 0 ? Math.Min(sec.VirtualSize, (ulong)sec.FileSize) : (ulong)sec.FileSize;
            ulong va = sec.StartVa, end = sec.StartVa + span;

            while (va < end && scanned < MaxInstructions)
            {
                if (!dis.TryDecodeAt(va, out var ins) || ins.Length <= 0)
                {
                    va++;
                    continue;
                }

                scanned++;
                string text = fmt.FormatText(ins);
                window.Enqueue(new TraceInsn(va, ins, text));
                while (window.Count > 8) window.Dequeue();

                if (ins.FlowControl == FlowControl.IndirectBranch)
                {
                    indirect++;
                    if (ins.Op0Kind == OpKind.Register) regIndirect++;
                    if (ins.Op0Kind == OpKind.Memory)
                    {
                        memIndirect++;
                        if (ins.MemoryIndex != Register.None) indexedMemIndirect++;
                    }

                    if (branches.Count < MaxBranchSamples)
                    branches.Add(new VmIndirectBranchSite(
                            va, sec.Name, text, BranchShape(ins), BranchReason(image, sec, sections, ins, window)));
                }

                if (crashes.Count < MaxCrashes && IsNullWriteTrap(ins, window, out var zeroReg))
                    crashes.Add(new VmSelfCrashSite(va, sec.Name, text,
                        RegisterName(zeroReg, image.Bitness), HasNearbySehInstall(window)));

                va += (ulong)ins.Length;
            }
            if (scanned >= MaxInstructions) break;
        }

        var tables = PointerTableCandidates(image);
        string summary = Summary(sections, scanned, indirect, regIndirect, memIndirect, indexedMemIndirect, tables, crashes);
        return new VmTriageResult
        {
            Sections = sections,
            InstructionsScanned = scanned,
            IndirectBranches = indirect,
            RegisterIndirectBranches = regIndirect,
            MemoryIndirectBranches = memIndirect,
            IndexedMemoryIndirectBranches = indexedMemIndirect,
            BranchSamples = branches,
            PointerTables = tables,
            SelfCrashes = crashes,
            Summary = summary,
        };
    }

    private static List<VmSectionSummary> SectionSummaries(IBinaryImage image)
    {
        var list = new List<VmSectionSummary>();
        foreach (var s in image.Sections.OrderBy(s => s.StartVa))
        {
            int len = Math.Min(s.FileSize, 1 << 20);
            var bytes = len > 0 ? image.ReadBytesAtVa(s.StartVa, len) : [];
            double entropy = bytes.Length > 0 ? Entropy.Shannon(bytes) : 0;
            double nonZero = bytes.Length > 0 ? 100.0 * bytes.Count(b => b != 0) / bytes.Length : 0;
            list.Add(new VmSectionSummary(s.Name, s.StartVa, s.EndVa, s.IsExecutable, s.IsWritable, s.FileSize, entropy, nonZero));
        }
        return list;
    }

    private static List<VmPointerTableCandidate> PointerTableCandidates(IBinaryImage image)
    {
        var tables = new List<VmPointerTableCandidate>();
        int slot = image.Bitness == 64 ? 8 : 4;

        foreach (var s in image.Sections.OrderBy(s => s.StartVa))
        {
            if (s.FileSize < slot * 4) continue;
            ulong va = AlignUp(s.StartVa, (ulong)slot);
            ulong end = s.StartVa + (ulong)s.FileSize;
            while (va + (ulong)slot <= end)
            {
                var run = ReadPointerRun(image, va, end, slot);
                if (run.Count >= 4)
                {
                    tables.Add(new VmPointerTableCandidate(va, s.Name, slot, run.Count, run.IsRva, run.TargetSection));
                    if (tables.Count >= MaxTables) return tables;
                    va += (ulong)(run.Count * slot);
                }
                else
                {
                    va += (ulong)slot;
                }
            }
        }

        return tables;
    }

    private static (int Count, bool IsRva, string TargetSection) ReadPointerRun(IBinaryImage image, ulong va, ulong end, int slot)
    {
        int count = 0;
        bool anyRva = false;
        string targetSection = "";
        while (va + (ulong)slot <= end && count < 1024)
        {
            var b = image.ReadBytesAtVa(va, slot);
            if (b.Length < slot) break;
            ulong raw = slot == 8 ? BitConverter.ToUInt64(b) : BitConverter.ToUInt32(b);
            ulong target = raw;
            bool rva = false;
            if (!image.IsExecutableVa(target) && slot == 4)
            {
                ulong maybe = image.ImageBase + raw;
                if (image.IsExecutableVa(maybe))
                {
                    target = maybe;
                    rva = true;
                }
            }
            if (!image.IsExecutableVa(target)) break;
            targetSection = image.SectionAt(target)?.Name ?? targetSection;
            anyRva |= rva;
            count++;
            va += (ulong)slot;
        }
        return (count, anyRva, targetSection);
    }

    private static bool IsNullWriteTrap(Instruction ins, IEnumerable<TraceInsn> window, out Register zeroReg)
    {
        zeroReg = Register.None;
        if (!WritesMemory(ins) || ins.MemoryBase == Register.None || ins.MemoryIndex != Register.None
            || ins.MemoryDisplacement64 != 0)
            return false;

        var reg = ins.MemoryBase.GetFullRegister();
        foreach (var prev in window.Reverse().Skip(1).Take(6))
        {
            if (SetsZero(prev.Ins, reg))
            {
                zeroReg = reg;
                return true;
            }
            if (WritesRegister(prev.Ins, reg)) break;
        }
        return false;
    }

    private static bool WritesMemory(in Instruction ins) =>
        ins.Op0Kind == OpKind.Memory && ins.Mnemonic is Mnemonic.Mov or Mnemonic.Xchg or Mnemonic.Add
            or Mnemonic.Sub or Mnemonic.Xor or Mnemonic.And or Mnemonic.Or;

    private static bool SetsZero(in Instruction ins, Register reg)
    {
        Register op0 = ins.Op0Kind == OpKind.Register ? ins.Op0Register.GetFullRegister() : Register.None;
        if (op0 != reg) return false;
        return ins.Mnemonic == Mnemonic.Xor && ins.Op1Kind == OpKind.Register && ins.Op1Register.GetFullRegister() == reg
            || ins.Mnemonic == Mnemonic.Sub && ins.Op1Kind == OpKind.Register && ins.Op1Register.GetFullRegister() == reg
            || ins.Mnemonic == Mnemonic.Mov && IsImm(ins.Op1Kind) && ins.GetImmediate(1) == 0;
    }

    private static bool WritesRegister(in Instruction ins, Register reg) =>
        ins.Op0Kind == OpKind.Register && ins.Op0Register.GetFullRegister() == reg
        && ins.Mnemonic is not Mnemonic.Cmp and not Mnemonic.Test;

    private static bool HasNearbySehInstall(IEnumerable<TraceInsn> window) =>
        window.Any(t => t.Ins.Op0Kind == OpKind.Memory && t.Ins.MemorySegment == Register.FS && t.Ins.MemoryDisplacement64 == 0
            || t.Text.Contains("fs:[0]", StringComparison.OrdinalIgnoreCase));

    private static string BranchShape(in Instruction ins) =>
        ins.Op0Kind switch
        {
            OpKind.Register => "jmp-reg",
            OpKind.Memory when ins.MemoryIndex != Register.None => "jmp-indexed-mem",
            OpKind.Memory => "jmp-mem",
            _ => "indirect",
        };

    private static string BranchReason(IBinaryImage image, Section sec, IReadOnlyList<VmSectionSummary> sections,
        Instruction ins, IEnumerable<TraceInsn> window)
    {
        var reasons = new List<string>();
        var summary = sections.FirstOrDefault(s => s.StartVa == sec.StartVa);
        if (summary is { Entropy: >= 7.0 })
            reasons.Add("low confidence: high-entropy bytes may decode as junk");
        if (sec.IsWritable) reasons.Add("writable executable section");
        if (ins.Op0Kind == OpKind.Register && window.Any(t => HasIndexedRead(t.Ins))) reasons.Add("near indexed memory read");
        if (ins.Op0Kind == OpKind.Memory && ins.MemoryIndex != Register.None) reasons.Add("indexed memory branch");
        ulong disp = ins.MemoryDisplacement64;
        if (disp != 0 && image.IsMappedVa(disp)) reasons.Add("mapped displacement");
        return reasons.Count == 0 ? "ordinary indirect branch" : string.Join(", ", reasons);
    }

    private static bool HasIndexedRead(in Instruction ins)
    {
        for (int i = 0; i < ins.OpCount; i++)
            if (ins.GetOpKind(i) == OpKind.Memory && ins.MemoryIndex != Register.None)
                return true;
        return false;
    }

    private static string Summary(IReadOnlyList<VmSectionSummary> sections, int scanned, int indirect, int regIndirect,
        int memIndirect, int indexedMemIndirect, IReadOnlyList<VmPointerTableCandidate> tables,
        IReadOnlyList<VmSelfCrashSite> crashes)
    {
        var hot = sections.Where(s => s.Executable && s.Entropy >= 7.0).OrderByDescending(s => s.Entropy).FirstOrDefault();
        string enc = hot is null ? "No high-entropy executable section stood out."
            : $"High-entropy executable section {hot.Name} ({hot.Entropy:F2}, {hot.NonZeroPercent:F1}% nonzero) suggests packed/encrypted or obfuscated code.";
        return $"{enc} Scanned {scanned:N0} instructions; indirect branches: {indirect} ({regIndirect} register, " +
               $"{memIndirect} memory, {indexedMemIndirect} indexed-memory). Pointer-table candidates: {tables.Count}. " +
               $"Null-write self-crash sites: {crashes.Count}.";
    }

    private static string RegisterName(Register reg, int bitness)
    {
        if (bitness != 32) return reg.ToString().ToLowerInvariant();
        return reg switch
        {
            Register.RAX => "eax",
            Register.RBX => "ebx",
            Register.RCX => "ecx",
            Register.RDX => "edx",
            Register.RSI => "esi",
            Register.RDI => "edi",
            Register.RBP => "ebp",
            Register.RSP => "esp",
            _ => reg.ToString().ToLowerInvariant(),
        };
    }

    private static bool IsImm(OpKind k) => k is OpKind.Immediate8 or OpKind.Immediate8to16 or OpKind.Immediate8to32
        or OpKind.Immediate16 or OpKind.Immediate32 or OpKind.Immediate8to64 or OpKind.Immediate32to64 or OpKind.Immediate64;

    private static ulong AlignUp(ulong v, ulong a) => (v + a - 1) & ~(a - 1);

    private readonly record struct TraceInsn(ulong Va, Instruction Ins, string Text);
}

public sealed record VmSectionSummary(string Name, ulong StartVa, ulong EndVa, bool Executable, bool Writable,
    int FileSize, double Entropy, double NonZeroPercent);

public sealed record VmIndirectBranchSite(ulong Va, string Section, string Text, string Shape, string Reason);

public sealed record VmPointerTableCandidate(ulong Va, string Section, int SlotSize, int Count, bool IsRva,
    string TargetSection);

public sealed record VmSelfCrashSite(ulong Va, string Section, string Text, string ZeroRegister, bool NearbySehInstall);

public sealed record VmTriageResult
{
    public IReadOnlyList<VmSectionSummary> Sections { get; init; } = [];
    public int InstructionsScanned { get; init; }
    public int IndirectBranches { get; init; }
    public int RegisterIndirectBranches { get; init; }
    public int MemoryIndirectBranches { get; init; }
    public int IndexedMemoryIndirectBranches { get; init; }
    public IReadOnlyList<VmIndirectBranchSite> BranchSamples { get; init; } = [];
    public IReadOnlyList<VmPointerTableCandidate> PointerTables { get; init; } = [];
    public IReadOnlyList<VmSelfCrashSite> SelfCrashes { get; init; } = [];
    public string Summary { get; init; } = "";
}

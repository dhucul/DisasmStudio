using System.ComponentModel;
using DisasmStudio.Core.Analysis;
using DisasmStudio.Core.Formats;
using DisasmStudio.Debug;

namespace DisasmStudio.Wpf.ViewModels;

/// <summary>Row in the Functions list — a discovered function, or an imported function (at its IAT slot).</summary>
public sealed class FunctionItem
{
    public Function? Function { get; }
    public ulong Va { get; }
    public string Name { get; }
    public string Section { get; }
    public string Address => Va.ToString("X");

    public FunctionItem(Function fn, string section) { Function = fn; Va = fn.Va; Name = fn.Name; Section = section; }
    public FunctionItem(ulong va, string name, string section) { Va = va; Name = name; Section = section; }
}

/// <summary>Row in the Strings list.</summary>
public sealed class StringItem(FoundString s)
{
    public ulong Va => s.Va;
    public string Address => s.Va.ToString("X");
    public bool Wide => s.Wide;
    public int Length => s.Length;
    public string Kind => s.Wide ? "wide" : "ascii";
    public string Text => s.Text;

    /// <summary>True when this string was recovered from a live argument/register pointer at the current stop
    /// (heap/stack/other module) rather than swept from a data section.</summary>
    public bool Referenced => s.Referenced;

    /// <summary>Glyph shown for a <see cref="Referenced"/> row so it stands out at the top of the live list.</summary>
    public string Marker => s.Referenced ? "→" : "";

    /// <summary>Byte span of the string content (chars × 2 for wide), for range-based xref lookup.</summary>
    public int ByteLength => s.Wide ? s.Length * 2 : s.Length;
}

/// <summary>Row in the Imports list.</summary>
public sealed class ImportItem(ImportEntry imp)
{
    public ulong Va => imp.IatVa;
    public string Address => imp.IatVa.ToString("X");
    public string Module => imp.Module;
    public string Name => Demangler.Demangle(imp.Name);
}

/// <summary>Row in the Exports list.</summary>
public sealed class ExportItem(NamedSymbol s)
{
    public ulong Va => s.Va;
    public string Address => s.Va.ToString("X");
    public string Name => Demangler.Demangle(s.Name);
}

/// <summary>Row in the Breakpoints list. <see cref="Va"/> is a static VA before/between runs and a live
/// (rebased) VA during a session — the same address space the listing is showing, so a double-click navigates
/// straight to it. <see cref="Label"/> is the resolved symbol (and, for hardware breakpoints, the kind).</summary>
public sealed class BreakpointItem(ulong va, string label, bool enabled)
{
    public ulong Va => va;
    public string Address => va.ToString("X");
    public string Label => label;

    /// <summary>Whether the breakpoint is armed. Bound to the list's tick-box (untick = disabled, kept but not armed).</summary>
    public bool Enabled => enabled;
}

/// <summary>The user's definition of a breakpoint, held in the pre-run / cross-run set keyed by static VA.
/// Carries everything needed to (re)create and configure it on the engine each run: software vs. hardware
/// (+ kind/size), the enabled flag, an optional condition expression, and a hit-count rule.</summary>
public sealed class BpDef
{
    public bool Hardware;
    public HwKind Kind;            // when Hardware
    public int Size = 1;           // 1/2/4/8 when Hardware (1 for Execute)
    public bool Memory;            // software memory (data) breakpoint on a byte range
    public int MemLength = 1;      // range length in bytes (when Memory)
    public MemAccess MemAccess;    // read / write / read-write (when Memory)
    public bool Enabled = true;
    public string? Condition;      // raw expression text, null = unconditional
    public HitCountMode HitMode = HitCountMode.None;
    public int HitTarget;

    /// <summary>One-line summary of the non-default attributes for the breakpoint lists (empty for a plain,
    /// enabled software breakpoint with no condition / hit-count).</summary>
    public string Describe()
    {
        var parts = new List<string>();
        if (Hardware) parts.Add($"hw {Kind}{(Kind == HwKind.Execute ? "" : "/" + Size)}");
        if (Memory) parts.Add($"mem {MemAccess} · {MemLength} B");
        if (!string.IsNullOrEmpty(Condition)) parts.Add($"if ({Condition})");
        parts.Add(HitMode switch
        {
            HitCountMode.Equals => $"hit = {HitTarget}",
            HitCountMode.AtLeast => $"hit ≥ {HitTarget}",
            HitCountMode.Multiple => $"every {HitTarget}",
            _ => "",
        });
        if (!Enabled) parts.Add("disabled");
        return string.Join("  ·  ", parts.Where(p => p.Length > 0));
    }
}

/// <summary>Row in the Bookmarks list. <see cref="Va"/> is a static VA before/between runs and a live
/// (rebased) VA while the live view is up — the same space the listing shows — so a double-click navigates
/// straight to it. <see cref="Label"/> is the resolved symbol name (and any user comment).</summary>
public sealed class BookmarkItem(ulong va, string label)
{
    public ulong Va => va;
    public string Address => va.ToString("X");
    public string Label => label;
}

/// <summary>Row in the Xrefs list.</summary>
public sealed class XrefItem(Xref x)
{
    public ulong Va => x.From;
    public string From => x.From.ToString("X");
    public string Kind => x.Kind.ToString().ToLowerInvariant();
}

/// <summary>Row in the unified Search panel — a function, import, export or string that matched the query.
/// <see cref="ByteLength"/> is the span used for range-based reference lookup: 1 for a point target (a
/// function/import/export entry), or the string's byte length so a reference into the middle of a merged
/// literal is still found.</summary>
public sealed class SearchResultItem(ulong va, string kind, string text, int byteLength = 1)
{
    public ulong Va => va;
    public string Address => va.ToString("X");

    /// <summary>Short category tag shown in the list: "fn", "imp", "exp" or "str".</summary>
    public string Kind => kind;

    /// <summary>The function/symbol name, or the string's content.</summary>
    public string Text => text;

    /// <summary>Byte span of the target, for range-based xref lookup (≥ 1).</summary>
    public int ByteLength => Math.Max(1, byteLength);
}

/// <summary>Row in the Search panel's references list — a site that references the selected result, with the
/// enclosing function (or section) for orientation. <see cref="Va"/> is the referencing address, so a
/// double-click navigates straight to the call/branch/access site.</summary>
public sealed class ReferenceItem(Xref x, string context)
{
    public ulong Va => x.From;
    public string From => x.From.ToString("X");
    public string Kind => x.Kind.ToString().ToLowerInvariant();
    public string Context => context;
}

/// <summary>Row in the Find (instruction search) list — one matched instruction. <see cref="Hit"/> is toggled
/// live while hit-tracing so the row shows a ● once that site has executed.</summary>
public sealed class InsnMatchItem(ulong va, string text) : INotifyPropertyChanged
{
    public ulong Va => va;
    public string Address => va.ToString("X");
    public string Text => text;

    private bool _hit;
    public bool Hit
    {
        get => _hit;
        set
        {
            if (_hit == value) return;
            _hit = value;
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(Hit)));
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(HitMark)));
        }
    }

    /// <summary>"●" once this site has been hit during a trace, else empty.</summary>
    public string HitMark => _hit ? "●" : "";

    public event PropertyChangedEventHandler? PropertyChanged;
}

/// <summary>Node in the Resources tree. Carries the top-level resource <see cref="TypeId"/> down to every
/// descendant so a selected leaf knows which preview renderer to use.</summary>
public sealed class ResourceNodeVm
{
    private readonly ResourceNode _n;
    public ResourceNodeVm(ResourceNode n, uint? typeId)
    {
        _n = n;
        TypeId = typeId;
        Children = n.Children.Select(c => new ResourceNodeVm(c, typeId)).ToList();
    }

    public uint? TypeId { get; }
    public IReadOnlyList<ResourceNodeVm> Children { get; }
    public ResourceDataEntry? Data => _n.Data;
    public bool IsLeaf => _n.IsLeaf;
    public string Display => IsLeaf && _n.Data is { } d ? $"{_n.Name}  ({d.Size:N0} bytes)" : _n.Name;
}

/// <summary>Node in the Obj-C browser: a class whose children are its methods (instance then class).</summary>
public sealed class ObjCClassVm
{
    public ObjCClassVm(ObjCClass c)
    {
        Va = c.Va;
        Display = c.SuperName is { Length: > 0 } s ? $"{c.Name} : {s}" : c.Name;
        Children = c.InstanceMethods.Concat(c.ClassMethods).Select(m => new ObjCMethodVm(m, c.Name)).ToList();
    }

    public ulong Va { get; }
    public string Display { get; }
    public IReadOnlyList<ObjCMethodVm> Children { get; }
}

/// <summary>Leaf node in the Obj-C browser: one method, navigable to its IMP.</summary>
public sealed class ObjCMethodVm
{
    public ObjCMethodVm(ObjCMethod m, string className)
    {
        Va = m.Imp;
        Display = $"{(m.IsClassMethod ? '+' : '-')}[{className} {m.Selector}]   {m.Imp:X}";
    }

    public ulong Va { get; }
    public string Display { get; }
    public IReadOnlyList<ObjCMethodVm> Children => [];
}

/// <summary>Row in the Sections list. <see cref="Loaded"/> tracks whether the section/header is folded
/// into the linear listing as data; executable sections are always loaded and can't be toggled.</summary>
public sealed class SectionItem(Section s, bool loaded, bool isHeader = false)
{
    public ulong Va => s.StartVa;
    public string Name => s.Name;
    public string Range => $"{s.StartVa:X}-{s.EndVa:X}";
    public string Perms => $"{(s.IsReadable ? "R" : "-")}{(s.IsWritable ? "W" : "-")}{(s.IsExecutable ? "X" : "-")}";

    /// <summary>True for the synthetic PE-header row (vs. a real section).</summary>
    public bool IsHeader => isHeader;

    /// <summary>Code sections are always in the listing, and a section with no file bytes (e.g. .bss) has
    /// nothing to render — only non-code sections with data (and the header) can be toggled.</summary>
    public bool CanToggle => !s.IsExecutable && s.FileSize > 0;

    /// <summary>Whether this section/header is currently folded into the listing.</summary>
    public bool Loaded { get; set; } = loaded || s.IsExecutable;
}

/// <summary>Permission/colour class of a <see cref="MemoryMapItem"/>, driving the Memory Map strip's block colour.</summary>
public enum MemKind { Header, Code, ReadOnly, Writable, Gap }

/// <summary>Row in the Memory Map: a real section (or the synthetic PE-header region), or a synthetic
/// <c>&lt;gap&gt;</c> of unmapped address space between two mapped regions. <see cref="Va"/> is the region
/// start — a double-click navigates there; gaps don't navigate. Sizes/offset are pre-formatted hex strings
/// ("-" where not applicable) for direct binding; <see cref="SizeBytes"/> feeds the strip's proportional layout.</summary>
public sealed class MemoryMapItem
{
    public ulong Va { get; }
    public ulong EndVa { get; }
    public ulong SizeBytes => EndVa - Va;
    public bool IsGap { get; }
    public MemKind Kind { get; }
    public string Name { get; }
    public string Start => Va.ToString("X");
    public string End => EndVa.ToString("X");
    public string Size => SizeBytes.ToString("X");
    public string VSize { get; }
    public string RSize { get; }
    public string FileOff { get; }
    public string Perms { get; }

    /// <summary>A real section, or the synthetic PE-header region when <paramref name="isHeader"/> is set.</summary>
    public MemoryMapItem(Section s, bool isHeader)
    {
        Va = s.StartVa;
        EndVa = s.EndVa;
        Name = s.Name;
        VSize = s.VirtualSize.ToString("X");
        RSize = s.FileSize.ToString("X");
        FileOff = s.FileOffset.ToString("X");
        Perms = $"{(s.IsReadable ? "R" : "-")}{(s.IsWritable ? "W" : "-")}{(s.IsExecutable ? "X" : "-")}";
        Kind = isHeader ? MemKind.Header
             : s.IsExecutable ? MemKind.Code
             : s.IsWritable ? MemKind.Writable
             : MemKind.ReadOnly;
    }

    /// <summary>A gap [<paramref name="start"/>, <paramref name="end"/>) of unmapped address space.</summary>
    public MemoryMapItem(ulong start, ulong end)
    {
        Va = start;
        EndVa = end;
        IsGap = true;
        Kind = MemKind.Gap;
        Name = "<gap>";
        VSize = RSize = FileOff = "-";
        Perms = "";
    }
}

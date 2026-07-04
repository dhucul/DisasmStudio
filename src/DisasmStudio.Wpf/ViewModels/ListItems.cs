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
public sealed class BreakpointItem(ulong va, string label)
{
    public ulong Va => va;
    public string Address => va.ToString("X");
    public string Label => label;
}

/// <summary>The user's definition of a breakpoint, held in the pre-run / cross-run set keyed by static VA.
/// Carries everything needed to (re)create and configure it on the engine each run: software vs. hardware
/// (+ kind/size), the enabled flag, an optional condition expression, and a hit-count rule.</summary>
public sealed class BpDef
{
    public bool Hardware;
    public HwKind Kind;            // when Hardware
    public int Size = 1;           // 1/2/4/8 when Hardware (1 for Execute)
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

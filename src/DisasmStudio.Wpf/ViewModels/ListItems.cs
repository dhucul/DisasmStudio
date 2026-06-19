using DisasmStudio.Core.Analysis;
using DisasmStudio.Core.Formats;

namespace DisasmStudio.Wpf.ViewModels;

/// <summary>Row in the Functions list.</summary>
public sealed class FunctionItem(Function fn)
{
    public Function Function { get; } = fn;
    public ulong Va => Function.Va;
    public string Address => Function.Va.ToString("X");
    public string Name => Function.Name;
}

/// <summary>Row in the Strings list.</summary>
public sealed class StringItem(FoundString s)
{
    public ulong Va => s.Va;
    public string Address => s.Va.ToString("X");
    public string Kind => s.Wide ? "wide" : "ascii";
    public string Text => s.Text;

    /// <summary>Byte span of the string content (chars × 2 for wide), for range-based xref lookup.</summary>
    public int ByteLength => s.Wide ? s.Length * 2 : s.Length;
}

/// <summary>Row in the Imports list.</summary>
public sealed class ImportItem(ImportEntry imp)
{
    public ulong Va => imp.IatVa;
    public string Address => imp.IatVa.ToString("X");
    public string Module => imp.Module;
    public string Name => imp.Name;
}

/// <summary>Row in the Exports list.</summary>
public sealed class ExportItem(NamedSymbol s)
{
    public ulong Va => s.Va;
    public string Address => s.Va.ToString("X");
    public string Name => s.Name;
}

/// <summary>Row in the Xrefs list.</summary>
public sealed class XrefItem(Xref x)
{
    public ulong Va => x.From;
    public string From => x.From.ToString("X");
    public string Kind => x.Kind.ToString().ToLowerInvariant();
}

/// <summary>Row in the Sections list.</summary>
public sealed class SectionItem(Section s)
{
    public ulong Va => s.StartVa;
    public string Name => s.Name;
    public string Range => $"{s.StartVa:X}-{s.EndVa:X}";
    public string Perms => $"{(s.IsReadable ? "R" : "-")}{(s.IsWritable ? "W" : "-")}{(s.IsExecutable ? "X" : "-")}";
}

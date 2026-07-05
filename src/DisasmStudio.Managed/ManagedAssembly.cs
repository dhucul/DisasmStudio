using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Reflection.PortableExecutable;
using DisasmStudio.Core.Disasm;
using DisasmStudio.Core.Formats;
using DisasmStudio.Core.IL;
using ICSharpCode.Decompiler;
using ICSharpCode.Decompiler.CSharp;
using ICSharpCode.Decompiler.CSharp.OutputVisitor;
using ICSharpCode.Decompiler.CSharp.Syntax;
using ICSharpCode.Decompiler.Disassembler;
using ICSharpCode.Decompiler.Metadata;
using ICSharpCode.Decompiler.TypeSystem;

namespace DisasmStudio.Managed;

/// <summary>
/// The managed-analysis model for a .NET assembly: a type/member tree, on-demand C# and IL for any node, the
/// assembly metadata, and its extractable embedded resources. Wraps ICSharpCode.Decompiler (the ILSpy engine)
/// and is the only type in the app that references it — the WPF layer talks to this via plain records
/// (<see cref="ManagedTypeNode"/> etc.), so the decompiler dependency stays isolated in this project.
///
/// Decompilation is not thread-safe in ICSharpCode, so every decompile/disassemble call is serialised on
/// <see cref="_gate"/>; callers still invoke on a background thread so the UI never blocks.
/// </summary>
public sealed class ManagedAssembly : IDisposable
{
    private readonly PEFile _pe;
    private readonly CSharpDecompiler _decompiler;
    private readonly DecompilerSettings _settings;
    private readonly object _gate = new();
    private ManagedTypeNode? _root;

    public AssemblyMetadata Metadata { get; }
    public IReadOnlyList<ManagedResourceEntry> Resources { get; }

    private ManagedAssembly(PEFile pe, CSharpDecompiler decompiler, DecompilerSettings settings,
        AssemblyMetadata meta, IReadOnlyList<ManagedResourceEntry> resources)
    {
        _pe = pe;
        _decompiler = decompiler;
        _settings = settings;
        Metadata = meta;
        Resources = resources;
    }

    /// <summary>Build a managed model for <paramref name="img"/> if it is a .NET assembly; false for native/non-PE.</summary>
    public static bool TryLoad(IBinaryImage img, out ManagedAssembly? asm)
    {
        asm = null;
        if (ManagedPeInfo.TryRead(img) is not { } net) return false;
        try
        {
            // Load from a copy of the on-disk bytes (not by locking the path), then let the whole image prefetch
            // so the decompiler doesn't hold the file open.
            byte[] bytes = File.ReadAllBytes(img.FilePath);
            var pe = new PEFile(img.FilePath, new MemoryStream(bytes, writable: false), PEStreamOptions.PrefetchEntireImage);

            string tfm = "";
            try { tfm = pe.DetectTargetFrameworkId() ?? ""; } catch { /* best-effort */ }

            // Resolve references from the target's own directory (and any sibling DLLs the user extracts); missing
            // reference assemblies degrade to stubs rather than throwing.
            var resolver = new UniversalAssemblyResolver(img.FilePath, throwOnError: false, tfm);
            var settings = new DecompilerSettings { ThrowOnAssemblyResolveErrors = false };
            var decompiler = new CSharpDecompiler(pe, resolver, settings);

            var meta = BuildMetadata(pe, net, tfm);
            var resources = ManagedResourceExtractor.Enumerate(pe);
            asm = new ManagedAssembly(pe, decompiler, settings, meta, resources);
            return true;
        }
        catch { asm = null; return false; }
    }

    public ManagedTypeNode Root => _root ??= BuildTree();

    /// <summary>A readable label for a method metadata token (for the managed call stack), or its hex token
    /// if not found in the tree.</summary>
    public string MethodName(int token)
    {
        static string? Find(ManagedTypeNode n, int tok)
        {
            if (n.Token == tok && n.Kind == ManagedNodeKind.Method) return n.Display;
            foreach (var c in n.Children) { var r = Find(c, tok); if (r is not null) return r; }
            return null;
        }
        return Find(Root, token) ?? $"0x{token:X8}";
    }

    /// <summary>The tree node for a method metadata token (to navigate to a stopped/selected frame), or null
    /// (e.g. a compiler-generated method not shown in the tree).</summary>
    public ManagedTypeNode? FindNode(int token)
    {
        static ManagedTypeNode? Find(ManagedTypeNode n, int tok)
        {
            if (n.Token == tok && n.Kind == ManagedNodeKind.Method) return n;
            foreach (var c in n.Children) { var r = Find(c, tok); if (r is not null) return r; }
            return null;
        }
        return Find(Root, token);
    }

    // ---- decompilation ----

    /// <summary>Decompiled C# for a tree node (whole type or single member); assembly/namespace nodes get a header.</summary>
    public IReadOnlyList<DecompLine> DecompileCSharp(ManagedTypeNode node)
        => CodeTokenizer.Tokenize(CSharpText(node), il: false);

    /// <summary>Decompiled C# for a node PLUS a line ↔ IL mapping (via ICSharpCode sequence points), so the
    /// debug UI can turn a clicked line into a (methodToken, ilOffset) breakpoint and highlight the line for a
    /// stop. The text is produced by a position-setting token writer so sequence-point lines match the rendered
    /// lines 1:1 (see <see cref="CodeTokenizer"/>, which emits one <see cref="DecompLine"/> per text line).</summary>
    public (IReadOnlyList<DecompLine> Lines, ManagedLineMap Map) DecompileCSharpForDebug(ManagedTypeNode node)
    {
        lock (_gate)
        {
            try
            {
                SyntaxTree? tree = node.Kind switch
                {
                    ManagedNodeKind.Namespace => null,
                    ManagedNodeKind.Assembly => _decompiler.DecompileModuleAndAssemblyAttributes(),
                    _ => _decompiler.Decompile(new[] { MetadataTokens.EntityHandle(node.Token) }),
                };
                if (tree is null)
                    return (Hint($"// namespace {node.Display}\n// Select a type or member to decompile."), ManagedLineMap.Empty);

                // Write the tree through a writer that records each node's text position, THEN read sequence
                // points — CreateSequencePoints reads those positions, so it must run after the write.
                var sw = new StringWriter();
                var tw = TokenWriter.CreateWriterThatSetsLocationsInAST(sw, "\t");
                tree.AcceptVisitor(new CSharpOutputVisitor(tw, _settings.CSharpFormattingOptions));
                string text = sw.ToString();
                var lines = CodeTokenizer.Tokenize(text, il: false);

                var points = new List<ManagedSeqPoint>();
                foreach (var (func, sps) in _decompiler.CreateSequencePoints(tree))
                {
                    if (func.Method is null) continue;
                    int mtok;
                    try { mtok = MetadataTokens.GetToken(func.Method.MetadataToken); } catch { continue; }
                    foreach (var p in sps)
                    {
                        if (p.IsHidden || p.StartLine < 1) continue;   // skip compiler-generated / unmapped points
                        points.Add(new ManagedSeqPoint(mtok, p.Offset, p.EndOffset, p.StartLine, p.EndLine));
                    }
                }
                return (lines, new ManagedLineMap(points));
            }
            catch (Exception ex)
            {
                return (Hint($"// C# decompilation failed: {ex.Message}"), ManagedLineMap.Empty);
            }
        }
    }

    /// <summary>Raw decompiled C# text for a node (for saving to a .cs file).</summary>
    public string CSharpText(ManagedTypeNode node)
    {
        lock (_gate)
        {
            try
            {
                return node.Kind switch
                {
                    ManagedNodeKind.Assembly => _decompiler.DecompileModuleAndAssemblyAttributesToString(),
                    ManagedNodeKind.Namespace => $"// namespace {node.Display}\n// Select a type or member to decompile.",
                    _ => _decompiler.DecompileAsString(new[] { MetadataTokens.EntityHandle(node.Token) }),
                };
            }
            catch (Exception ex) { return $"// C# decompilation failed: {ex.Message}"; }
        }
    }

    /// <summary>Raw decompiled C# for the whole assembly as one source string (for "Save C#…").</summary>
    public string WholeModuleCSharp()
    {
        lock (_gate)
        {
            try { return _decompiler.DecompileWholeModuleAsString(); }
            catch (Exception ex) { return $"// Whole-module decompilation failed: {ex.Message}"; }
        }
    }

    /// <summary>ILAsm for a tree node.</summary>
    public IReadOnlyList<DecompLine> DecompileIl(ManagedTypeNode node)
    {
        lock (_gate)
        {
            try
            {
                var output = new PlainTextOutput();
                var rd = new ReflectionDisassembler(output, default);
                switch (node.Kind)
                {
                    case ManagedNodeKind.Assembly:
                        rd.WriteAssemblyHeader(_pe);
                        break;
                    case ManagedNodeKind.Namespace:
                        return Hint($"// namespace {node.Display}");
                    default:
                        var h = MetadataTokens.EntityHandle(node.Token);
                        switch (h.Kind)
                        {
                            case HandleKind.TypeDefinition: rd.DisassembleType(_pe, (TypeDefinitionHandle)h); break;
                            case HandleKind.MethodDefinition: rd.DisassembleMethod(_pe, (MethodDefinitionHandle)h); break;
                            case HandleKind.FieldDefinition: rd.DisassembleField(_pe, (FieldDefinitionHandle)h); break;
                            case HandleKind.PropertyDefinition: rd.DisassembleProperty(_pe, (PropertyDefinitionHandle)h); break;
                            case HandleKind.EventDefinition: rd.DisassembleEvent(_pe, (EventDefinitionHandle)h); break;
                            default: return Hint("// No IL for this node.");
                        }
                        break;
                }
                return CodeTokenizer.Tokenize(output.ToString(), il: true);
            }
            catch (Exception ex) { return Hint($"// IL disassembly failed: {ex.Message}"); }
        }
    }

    private static IReadOnlyList<DecompLine> Hint(string text) =>
        [new DecompLine(0, [new AsmToken(text, AsmTokenKind.Comment)], 0)];

    // ---- tree ----

    private ManagedTypeNode BuildTree()
    {
        var module = _decompiler.TypeSystem.MainModule;
        var byNamespace = new SortedDictionary<string, List<ManagedTypeNode>>(StringComparer.Ordinal);
        foreach (var td in module.TopLevelTypeDefinitions)
        {
            string ns = string.IsNullOrEmpty(td.Namespace) ? "<global>" : td.Namespace;
            if (!byNamespace.TryGetValue(ns, out var list)) byNamespace[ns] = list = [];
            list.Add(BuildTypeNode(td));
        }

        var nsNodes = new List<ManagedTypeNode>();
        foreach (var (ns, types) in byNamespace)
        {
            types.Sort((a, b) => string.CompareOrdinal(a.Display, b.Display));
            nsNodes.Add(new ManagedTypeNode(ns, ManagedNodeKind.Namespace, 0, types));
        }
        return new ManagedTypeNode(Metadata.Name, ManagedNodeKind.Assembly, 0, nsNodes);
    }

    private ManagedTypeNode BuildTypeNode(ITypeDefinition td)
    {
        var children = new List<ManagedTypeNode>();
        foreach (var nt in td.NestedTypes) children.Add(BuildTypeNode(nt) with { Kind = ManagedNodeKind.NestedType });
        // Skip compiler-generated property/event accessor methods — the property/event nodes represent them.
        foreach (var m in td.Methods)
            if (m.SymbolKind != SymbolKind.Accessor)
                children.Add(Leaf(m, ManagedNodeKind.Method, m.Name + "()"));
        foreach (var p in td.Properties) children.Add(Leaf(p, ManagedNodeKind.Property, p.Name));
        foreach (var e in td.Events) children.Add(Leaf(e, ManagedNodeKind.Event, e.Name));
        foreach (var f in td.Fields) children.Add(Leaf(f, ManagedNodeKind.Field, f.Name));

        int token = MetadataTokens.GetToken(td.MetadataToken);
        return new ManagedTypeNode(td.Name, ManagedNodeKind.Type, token, children);
    }

    private static ManagedTypeNode Leaf(IEntity e, ManagedNodeKind kind, string display) =>
        new(display, kind, MetadataTokens.GetToken(e.MetadataToken), []);

    // ---- metadata ----

    private static AssemblyMetadata BuildMetadata(PEFile pe, ManagedPeInfo net, string tfm)
    {
        var md = pe.Metadata;
        string name = pe.Name;
        string? version = net.RuntimeVersion;
        var refs = new List<string>();
        try
        {
            if (md.IsAssembly)
            {
                var ad = md.GetAssemblyDefinition();
                name = md.GetString(ad.Name);
                version = ad.Version.ToString();
            }
            foreach (var arh in md.AssemblyReferences)
            {
                var ar = md.GetAssemblyReference(arh);
                refs.Add($"{md.GetString(ar.Name)} {ar.Version}");
            }
        }
        catch { /* best-effort metadata */ }
        refs.Sort(StringComparer.OrdinalIgnoreCase);
        return new AssemblyMetadata(name, version, string.IsNullOrEmpty(tfm) ? net.RuntimeVersion : tfm, net.IsILOnly, refs);
    }

    public void Dispose() => (_pe as IDisposable)?.Dispose();
}

/// <summary>One statement's mapping: an IL range [<see cref="IlOffset"/>, <see cref="IlEndOffset"/>) inside a
/// method (metadata <see cref="MethodToken"/>) ↔ a 1-based line range in the rendered C# text.</summary>
public readonly record struct ManagedSeqPoint(int MethodToken, int IlOffset, int IlEndOffset, int StartLine, int EndLine);

/// <summary>Maps the rendered C# text of one decompiled node to IL: a clicked line becomes a
/// (methodToken, ilOffset) breakpoint target, and a stopped (methodToken, ilOffset) becomes a line to
/// highlight. Lines are 1-based (a <see cref="DecompLine"/> at index i is line i+1).</summary>
public sealed class ManagedLineMap
{
    private readonly List<ManagedSeqPoint> _points;   // non-hidden, sorted by StartLine
    private readonly HashSet<int> _bpLines;

    public ManagedLineMap(List<ManagedSeqPoint> points)
    {
        points.Sort((a, b) => a.StartLine != b.StartLine ? a.StartLine.CompareTo(b.StartLine) : a.IlOffset.CompareTo(b.IlOffset));
        _points = points;
        _bpLines = points.Select(p => p.StartLine).ToHashSet();
    }

    public static ManagedLineMap Empty { get; } = new([]);

    public bool HasMappings => _points.Count > 0;

    /// <summary>Does a statement start on this 1-based line (i.e. is it a valid breakpoint target)?</summary>
    public bool IsBreakpointLine(int line) => _bpLines.Contains(line);

    /// <summary>Resolve a clicked line to a breakpoint target: the statement on that line, else the next one below
    /// (so clicking a blank/brace line binds to the following statement, like Visual Studio).</summary>
    public (int Token, int IlOffset)? Resolve(int line)
    {
        ManagedSeqPoint? after = null;
        foreach (var p in _points)   // sorted by StartLine
        {
            if (p.StartLine == line) return (p.MethodToken, p.IlOffset);
            if (p.StartLine > line) { after = p; break; }
        }
        return after is { } a ? (a.MethodToken, a.IlOffset) : null;
    }

    /// <summary>The 1-based line to highlight for a stop at (token, ilOffset): the statement whose IL range
    /// contains it, else the nearest statement at/before it (so a Pause or exception landing in the trailing
    /// compiler IL of a line still highlights that line rather than clearing the marker).</summary>
    public int? LineFor(int token, int ilOffset)
    {
        foreach (var p in _points)
            if (p.MethodToken == token && ilOffset >= p.IlOffset && ilOffset < p.IlEndOffset)
                return p.StartLine;
        ManagedSeqPoint? best = null;
        foreach (var p in _points)
            if (p.MethodToken == token && p.IlOffset <= ilOffset && (best is null || p.IlOffset > best.Value.IlOffset))
                best = p;
        return best?.StartLine;
    }

    /// <summary>The IL range to step over the whole C# statement at (token, ilOffset): from the statement's
    /// start to the NEXT statement's start — absorbing any trailing compiler-generated IL of the same source
    /// line (e.g. a string-interpolation build), so one Step Over advances exactly one C# line.</summary>
    public (int Start, int End)? StatementStepRange(int token, int ilOffset)
    {
        if (ilOffset < 0) return null;   // unknown IP → let the host fall back to a single-IL step
        var pts = _points.Where(p => p.MethodToken == token).OrderBy(p => p.IlOffset).ToList();
        if (pts.Count == 0) return null;

        int start, end;
        int idx = -1;
        for (int i = 0; i < pts.Count; i++)
            if (ilOffset >= pts[i].IlOffset && (i + 1 == pts.Count || ilOffset < pts[i + 1].IlOffset)) { idx = i; break; }
        if (idx >= 0)
        {
            start = pts[idx].IlOffset;
            end = idx + 1 < pts.Count ? pts[idx + 1].IlOffset : Math.Max(pts[idx].IlEndOffset, ilOffset + 1);
        }
        else
        {
            // IP is before the first mapped statement (e.g. a Pause in the prologue): step from HERE (so the
            // range contains the current IP) to the first statement — else StepRange sees the IP already outside.
            start = ilOffset;
            end = pts[0].IlOffset;
        }
        return end > start ? (start, end) : null;   // guard a zero-width/inverted range
    }
}

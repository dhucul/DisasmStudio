using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Reflection.PortableExecutable;
using DisasmStudio.Core.Disasm;
using DisasmStudio.Core.Formats;
using DisasmStudio.Core.IL;
using ICSharpCode.Decompiler;
using ICSharpCode.Decompiler.CSharp;
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
    private readonly object _gate = new();
    private ManagedTypeNode? _root;

    public AssemblyMetadata Metadata { get; }
    public IReadOnlyList<ManagedResourceEntry> Resources { get; }

    private ManagedAssembly(PEFile pe, CSharpDecompiler decompiler, AssemblyMetadata meta,
        IReadOnlyList<ManagedResourceEntry> resources)
    {
        _pe = pe;
        _decompiler = decompiler;
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
            asm = new ManagedAssembly(pe, decompiler, meta, resources);
            return true;
        }
        catch { asm = null; return false; }
    }

    public ManagedTypeNode Root => _root ??= BuildTree();

    // ---- decompilation ----

    /// <summary>Decompiled C# for a tree node (whole type or single member); assembly/namespace nodes get a header.</summary>
    public IReadOnlyList<DecompLine> DecompileCSharp(ManagedTypeNode node)
        => CodeTokenizer.Tokenize(CSharpText(node), il: false);

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

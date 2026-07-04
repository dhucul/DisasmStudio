namespace DisasmStudio.Managed;

/// <summary>What a node in the managed assembly tree represents. Drives the .NET tab's icons and the
/// C#/IL decompiler view's per-node behaviour (a namespace is a container; a type/member decompiles).</summary>
public enum ManagedNodeKind { Assembly, Namespace, Type, NestedType, Method, Property, Field, Event }

/// <summary>
/// One node of the managed type tree (assembly → namespace → type → member). Deliberately a plain record
/// carrying an opaque metadata <see cref="Token"/> (0 for the synthetic assembly/namespace containers) rather
/// than an ICSharpCode handle, so the WPF layer never references the decompiler library. <see cref="ManagedAssembly"/>
/// maps the token back to an <c>EntityHandle</c> when it decompiles the node.
/// </summary>
public sealed record ManagedTypeNode(
    string Display,
    ManagedNodeKind Kind,
    int Token,
    IReadOnlyList<ManagedTypeNode> Children);

/// <summary>How an embedded manifest resource is classified, so the .NET tab can label it and the extractor
/// knows whether to inflate it before writing.</summary>
public enum ManagedResourceKind { ResourcesBlob, EmbeddedAssembly, CompressedAssembly, NativeImage, Raw }

/// <summary>
/// An extractable manifest resource (or an inner entry of a <c>.resources</c> blob). <see cref="GetBytes"/>
/// returns the ready-to-write bytes — already inflated for <see cref="ManagedResourceKind.CompressedAssembly"/>.
/// </summary>
public sealed record ManagedResourceEntry(
    string Name,
    ManagedResourceKind Kind,
    int Size,
    Func<byte[]> GetBytes);

/// <summary>Assembly-level facts shown at the top of the .NET tab.</summary>
public sealed record AssemblyMetadata(
    string Name,
    string? Version,
    string? TargetFramework,
    bool IsILOnly,
    IReadOnlyList<string> ReferencedAssemblies);

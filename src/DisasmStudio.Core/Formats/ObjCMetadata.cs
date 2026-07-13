namespace DisasmStudio.Core.Formats;

/// <summary>Objective-C metadata recovered from a Mach-O's <c>__objc_*</c> sections: the classes, their
/// methods, and a flat list of <c>-[Class sel]</c> / <c>+[Class sel]</c> symbols at each method's IMP address
/// (merged into <see cref="MachOImage.Symbols"/> so they name the disassembly listing automatically).</summary>
public sealed class ObjCImage
{
    public IReadOnlyList<ObjCClass> Classes { get; init; } = [];
    public IReadOnlyList<NamedSymbol> MethodSymbols { get; init; } = [];
}

public sealed record ObjCClass(string Name, string? SuperName, ulong Va,
    IReadOnlyList<ObjCMethod> InstanceMethods, IReadOnlyList<ObjCMethod> ClassMethods, IReadOnlyList<ObjCIvar> Ivars);

public sealed record ObjCMethod(string Selector, ulong Imp, bool IsClassMethod);

public sealed record ObjCIvar(string Name, uint Offset);

/// <summary>
/// Parses the 64-bit Objective-C ABI class/method tables out of a Mach-O. Handles both classic
/// (non-chained, pointers already rebased on disk) and relative/"small" method lists (self-relative int32
/// offsets, immune to pointer rebasing — the common arm64 case). Pointer fields go through
/// <see cref="MachOImage.ResolvePtr"/>, which consults the chained-fixups rebase map when present.
/// </summary>
public static class ObjCMetadata
{
    public static ObjCImage? Parse(MachOImage image)
    {
        if (!image.Is64) return null;                       // 64-bit Obj-C ABI only

        var classlist = image.FindSectionByName("__objc_classlist");
        if (classlist is null || classlist.VirtualSize == 0) return null;

        var classes = new List<ObjCClass>();
        var methodSyms = new List<NamedSymbol>();
        var seen = new HashSet<ulong>();
        int n = (int)(classlist.VirtualSize / 8);

        for (int i = 0; i < n && i < 50_000; i++)
        {
            ulong slotVa = classlist.StartVa + (ulong)i * 8;
            ulong classVa = image.ResolvePtr(image.ReadU64AtVa(slotVa), slotVa);
            if (classVa == 0 || !seen.Add(classVa)) continue;
            var c = ReadClass(image, classVa, methodSyms);
            if (c is not null) classes.Add(c);
        }

        return classes.Count == 0 ? null : new ObjCImage { Classes = classes, MethodSymbols = methodSyms };
    }

    // objc_class: isa@0, superclass@8, cache@0x10, vtable@0x18, data@0x20
    // class_ro_t: flags@0, ..., name@0x18, baseMethods@0x20, ..., ivars@0x30
    private static ObjCClass? ReadClass(MachOImage image, ulong classVa, List<NamedSymbol> methodSyms)
    {
        ulong roVa = RoData(image, classVa);
        if (roVa == 0) return null;

        ulong nameVa = image.ResolvePtr(image.ReadU64AtVa(roVa + 0x18), roVa + 0x18);
        string name = nameVa != 0 ? image.ReadCStrAtVa(nameVa) : "";
        if (string.IsNullOrEmpty(name)) return null;

        var instance = ReadMethodList(image, MethodListVa(image, roVa), name, isClass: false, methodSyms);

        // class ("+") methods live on the metaclass, reached through isa
        var classMethods = new List<ObjCMethod>();
        ulong metaVa = image.ResolvePtr(image.ReadU64AtVa(classVa + 0), classVa + 0);
        if (metaVa != 0 && metaVa != classVa)
        {
            ulong metaRo = RoData(image, metaVa);
            if (metaRo != 0) classMethods = ReadMethodList(image, MethodListVa(image, metaRo), name, isClass: true, methodSyms);
        }

        string? superName = null;
        ulong superVa = image.ResolvePtr(image.ReadU64AtVa(classVa + 8), classVa + 8);
        if (superVa != 0)
        {
            ulong superRo = RoData(image, superVa);
            if (superRo != 0)
            {
                ulong snVa = image.ResolvePtr(image.ReadU64AtVa(superRo + 0x18), superRo + 0x18);
                if (snVa != 0) superName = image.ReadCStrAtVa(snVa);
            }
        }

        return new ObjCClass(name, superName, classVa, instance, classMethods, []);
    }

    private static ulong RoData(MachOImage image, ulong classVa)
    {
        ulong data = image.ResolvePtr(image.ReadU64AtVa(classVa + 0x20), classVa + 0x20);
        return data & ~7UL;   // low 3 bits are RW/realized flags
    }

    private static ulong MethodListVa(MachOImage image, ulong roVa) =>
        image.ResolvePtr(image.ReadU64AtVa(roVa + 0x20), roVa + 0x20);

    // method_list_t: entsizeAndFlags@0, count@4, then `count` elements.
    //   big   (24B): name(ptr)@0, types(ptr)@8, imp(ptr)@0x10
    //   small (12B): relName(i32)@0, relTypes(i32)@4, relImp(i32)@8   — all self-relative to their own field
    private static List<ObjCMethod> ReadMethodList(MachOImage image, ulong listVa, string className, bool isClass, List<NamedSymbol> methodSyms)
    {
        var result = new List<ObjCMethod>();
        if (listVa == 0 || !image.IsMappedVa(listVa)) return result;

        uint header = image.ReadU32AtVa(listVa + 0);
        uint count = image.ReadU32AtVa(listVa + 4);
        bool isSmall = (header & 0x80000000) != 0;
        bool selDirect = (header & 0x40000000) != 0;
        uint entsize = header & 0x0000FFFC;
        if (entsize == 0) entsize = isSmall ? 12u : 24u;
        if (count > 100_000) count = 100_000;

        for (uint i = 0; i < count; i++)
        {
            ulong elemVa = listVa + 8 + (ulong)i * entsize;
            string sel; ulong imp;

            if (isSmall)
            {
                int relName = image.ReadI32AtVa(elemVa + 0);
                int relImp = image.ReadI32AtVa(elemVa + 8);
                imp = (ulong)((long)(elemVa + 8) + relImp);
                ulong nameTarget = (ulong)((long)elemVa + relName);
                if (selDirect)
                {
                    sel = image.ReadCStrAtVa(nameTarget);           // points straight at the selector string
                }
                else
                {
                    // nameTarget points into __objc_selrefs — a SEL* slot; dereference to the string
                    ulong strVa = image.ResolvePtr(image.ReadU64AtVa(nameTarget), nameTarget);
                    sel = strVa != 0 ? image.ReadCStrAtVa(strVa) : "";
                }
            }
            else
            {
                ulong selVa = image.ResolvePtr(image.ReadU64AtVa(elemVa + 0), elemVa + 0);
                sel = selVa != 0 ? image.ReadCStrAtVa(selVa) : "";
                imp = image.ResolvePtr(image.ReadU64AtVa(elemVa + 0x10), elemVa + 0x10);
            }

            if (string.IsNullOrEmpty(sel) || imp == 0) continue;
            result.Add(new ObjCMethod(sel, imp, isClass));
            methodSyms.Add(new NamedSymbol(imp, $"{(isClass ? '+' : '-')}[{className} {sel}]", NamedSymbolKind.Function));
        }

        return result;
    }
}

using System.IO;
using System.Text.Json;
using DisasmStudio.Debug;

namespace DisasmStudio.Wpf;

/// <summary>Loads/saves the debugger's <see cref="ExceptionFilter"/> to a per-user JSON file
/// (<c>%AppData%\DisasmStudio\exceptions.json</c>) so the exception policy persists across sessions.</summary>
internal static class ExceptionStore
{
    private static readonly JsonSerializerOptions Opts = new() { WriteIndented = true };

    private static string FilePath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "DisasmStudio", "exceptions.json");

    public static ExceptionFilter Load()
    {
        try
        {
            if (File.Exists(FilePath))
            {
                var f = JsonSerializer.Deserialize<ExceptionFilter>(File.ReadAllText(FilePath));
                if (f is not null) { UpgradeDefaults(f); return f; }
            }
        }
        catch { }
        return ExceptionFilter.CreateDefault();   // first run (or unreadable): sensible starter policy
    }

    /// <summary>Seed newer default rows into a config saved by an older build, so an existing user still gains
    /// the .NET-friendly policy — only added when the code isn't already present (a deliberate user edit wins).</summary>
    private static void UpgradeDefaults(ExceptionFilter f)
    {
        if (!f.Rules.Any(r => r.CodeLow <= 0xE0434352 && r.CodeHigh >= 0xE0434352))
            f.SetCode(0xE0434352, "CLR/.NET exception", breakFirst: false, breakSecond: true, pass: true);
        // Cosmetic parity with CreateDefault (the engine swallows 0x04242420 before the filter, but show it too).
        if (!f.Rules.Any(r => r.CodeLow <= 0x04242420 && r.CodeHigh >= 0x04242420))
            f.SetCode(0x04242420, "CLR debugger notification", breakFirst: false, breakSecond: false, pass: false);
    }

    public static void Save(ExceptionFilter filter)
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(FilePath)!);
            File.WriteAllText(FilePath, JsonSerializer.Serialize(filter, Opts));
        }
        catch { }
    }
}

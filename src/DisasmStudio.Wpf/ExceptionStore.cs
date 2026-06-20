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
                return JsonSerializer.Deserialize<ExceptionFilter>(File.ReadAllText(FilePath)) ?? ExceptionFilter.CreateDefault();
        }
        catch { }
        return ExceptionFilter.CreateDefault();   // first run (or unreadable): sensible starter policy
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

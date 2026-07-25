using System.IO;
using System.Text;

namespace DisasmStudio.Wpf.Services;

/// <summary>Writes beside the destination and publishes the completed file in one rename.</summary>
internal static class AtomicFile
{
    public static string TempBeside(string destination)
    {
        string full = Path.GetFullPath(destination);
        string? directory = Path.GetDirectoryName(full);
        if (string.IsNullOrEmpty(directory))
            throw new IOException("The destination has no parent directory.");
        return Path.Combine(directory, $".{Path.GetFileName(full)}.{Guid.NewGuid():N}.tmp");
    }

    public static void Replace(string tempPath, string destination) =>
        File.Move(tempPath, Path.GetFullPath(destination), overwrite: true);

    public static void WriteAllBytes(string destination, ReadOnlySpan<byte> bytes)
    {
        string temp = TempBeside(destination);
        try
        {
            File.WriteAllBytes(temp, bytes);
            Replace(temp, destination);
        }
        finally
        {
            TryDelete(temp);
        }
    }

    public static void WriteAllText(string destination, string text)
    {
        string temp = TempBeside(destination);
        try
        {
            File.WriteAllText(temp, text);
            Replace(temp, destination);
        }
        finally
        {
            TryDelete(temp);
        }
    }

    public static void WriteText(string destination, Action<TextWriter> write)
    {
        string temp = TempBeside(destination);
        try
        {
            using (var writer = new StreamWriter(temp, append: false, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false)))
                write(writer);
            Replace(temp, destination);
        }
        finally
        {
            TryDelete(temp);
        }
    }

    public static async Task WriteAsync(string destination,
        Func<Stream, CancellationToken, Task> write, CancellationToken cancellationToken = default)
    {
        string temp = TempBeside(destination);
        try
        {
            await using (var stream = new FileStream(temp, FileMode.CreateNew, FileAccess.Write, FileShare.None,
                1 << 20, FileOptions.Asynchronous | FileOptions.SequentialScan))
            {
                await write(stream, cancellationToken).ConfigureAwait(false);
                await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
            }
            cancellationToken.ThrowIfCancellationRequested();
            Replace(temp, destination);
        }
        finally
        {
            TryDelete(temp);
        }
    }

    private static void TryDelete(string path)
    {
        try { File.Delete(path); }
        catch { /* preserve the original exception; a stale temp file is recoverable */ }
    }
}

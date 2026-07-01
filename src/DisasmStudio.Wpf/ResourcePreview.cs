using System.IO;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using DisasmStudio.Core.Formats;

namespace DisasmStudio.Wpf;

/// <summary>
/// Best-effort previews for a leaf resource's bytes, chosen by the top-level resource type: manifests /
/// HTML as text, RT_VERSION as parsed version + strings, RT_STRING as its string table, bitmaps/icons as
/// images (the DIB wrapped into a BMP / ICO so WPF can decode it), and everything else as a hex dump.
/// All paths are guarded — a malformed resource degrades to a hex dump rather than throwing.
/// </summary>
internal static class ResourcePreview
{
    private static readonly Brush Fg = new SolidColorBrush(Color.FromRgb(0xD3, 0xDA, 0xE3));
    private static readonly FontFamily Mono = new("Cascadia Mono, Consolas");

    public static UIElement Build(byte[] data, uint? typeId)
    {
        try
        {
            return typeId switch
            {
                ResourceTree.RT_MANIFEST or ResourceTree.RT_HTML => TextView(DecodeText(data)),
                ResourceTree.RT_VERSION => TextView(PreviewVersion(data)),
                ResourceTree.RT_STRING => TextView(PreviewStringTable(data)),
                ResourceTree.RT_BITMAP => TryImage(DibToBmp(data)) ?? TextView(HexDump(data)),
                ResourceTree.RT_ICON => TryImage(DibToIco(data)) ?? TextView(HexDump(data)),
                _ => LooksTextual(data) ? TextView(DecodeText(data)) : TextView(HexDump(data)),
            };
        }
        catch
        {
            return TextView(HexDump(data));
        }
    }

    private static UIElement TextView(string text) => new TextBox
    {
        Text = text,
        IsReadOnly = true,
        TextWrapping = TextWrapping.NoWrap,
        FontFamily = Mono,
        FontSize = 12,
        Foreground = Fg,
        Background = Brushes.Transparent,
        BorderThickness = new Thickness(0),
        VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
        HorizontalScrollBarVisibility = ScrollBarVisibility.Auto,
    };

    private static UIElement? TryImage(byte[]? container)
    {
        if (container is null) return null;
        try
        {
            using var ms = new MemoryStream(container);
            var dec = BitmapDecoder.Create(ms, BitmapCreateOptions.PreservePixelFormat, BitmapCacheOption.OnLoad);
            if (dec.Frames.Count == 0) return null;
            var img = new Image
            {
                Source = dec.Frames[0],
                Stretch = Stretch.None,
                HorizontalAlignment = HorizontalAlignment.Left,
                VerticalAlignment = VerticalAlignment.Top,
                Margin = new Thickness(8),
            };
            return new ScrollViewer
            {
                Content = img,
                HorizontalScrollBarVisibility = ScrollBarVisibility.Auto,
                VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
            };
        }
        catch { return null; }
    }

    // ---- bitmap / icon: wrap the raw DIB so WPF's decoders accept it ----

    /// <summary>Prepend a BITMAPFILEHEADER to a packed DIB (RT_BITMAP has no file header).</summary>
    private static byte[]? DibToBmp(byte[] dib)
    {
        if (dib.Length < 40) return null;
        uint biSize = BitConverter.ToUInt32(dib, 0);
        ushort bitCount = BitConverter.ToUInt16(dib, 14);
        uint compression = BitConverter.ToUInt32(dib, 16);
        uint clrUsed = BitConverter.ToUInt32(dib, 32);
        uint palette = clrUsed != 0 ? clrUsed : (bitCount <= 8 ? 1u << bitCount : 0);
        int maskBytes = compression == 3 ? 12 : 0;   // BI_BITFIELDS
        long offBits = 14 + biSize + maskBytes + (long)palette * 4;

        var bmp = new byte[14 + dib.Length];
        bmp[0] = (byte)'B'; bmp[1] = (byte)'M';
        BitConverter.GetBytes((uint)(14 + dib.Length)).CopyTo(bmp, 2);
        BitConverter.GetBytes((uint)offBits).CopyTo(bmp, 10);
        dib.CopyTo(bmp, 14);
        return bmp;
    }

    /// <summary>Wrap an RT_ICON image (a DIB whose height covers XOR+AND masks, or a PNG) into a 1-entry .ico.</summary>
    private static byte[]? DibToIco(byte[] img)
    {
        if (img.Length < 16) return null;
        int width = 0, height = 0, planes = 1, bitCount = 0;
        // A Vista+ icon may store a PNG directly; its 0x89504E47 magic would read as a huge "biSize", so
        // detect PNG by signature first and only then treat the bytes as a packed DIB (header size 40..124).
        bool isPng = img.Length >= 8 && img[0] == 0x89 && img[1] == 0x50 && img[2] == 0x4E && img[3] == 0x47;
        bool isDib = !isPng && img.Length >= 40 && BitConverter.ToUInt32(img, 0) is >= 40 and <= 256;
        if (isDib)
        {
            width = BitConverter.ToInt32(img, 4);
            height = BitConverter.ToInt32(img, 8) / 2;   // DIB height includes the AND mask
            planes = BitConverter.ToUInt16(img, 12);
            bitCount = BitConverter.ToUInt16(img, 14);
        }
        else if (isPng && img.Length >= 24)   // PNG-compressed icon — dimensions from the IHDR (big-endian)
        {
            width = (img[16] << 24) | (img[17] << 16) | (img[18] << 8) | img[19];
            height = (img[20] << 24) | (img[21] << 16) | (img[22] << 8) | img[23];
        }

        var ico = new byte[6 + 16 + img.Length];
        ico[2] = 1; ico[4] = 1;                                   // type = icon, count = 1
        ico[6] = (byte)(width is >= 256 or < 0 ? 0 : width);
        ico[7] = (byte)(height is >= 256 or < 0 ? 0 : height);
        BitConverter.GetBytes((ushort)planes).CopyTo(ico, 10);
        BitConverter.GetBytes((ushort)bitCount).CopyTo(ico, 12);
        BitConverter.GetBytes((uint)img.Length).CopyTo(ico, 14);  // bytes in resource
        BitConverter.GetBytes((uint)22).CopyTo(ico, 18);          // image offset
        img.CopyTo(ico, 22);
        return ico;
    }

    // ---- text-ish previews ----

    private static string DecodeText(byte[] b)
    {
        if (b.Length >= 2 && b[0] == 0xFF && b[1] == 0xFE) return Encoding.Unicode.GetString(b, 2, b.Length - 2);
        if (b.Length >= 3 && b[0] == 0xEF && b[1] == 0xBB && b[2] == 0xBF) return Encoding.UTF8.GetString(b, 3, b.Length - 3);
        int sample = Math.Min(b.Length, 512), zeros = 0;
        for (int i = 1; i < sample; i += 2) if (b[i] == 0) zeros++;
        return sample > 0 && zeros > sample / 4 ? Encoding.Unicode.GetString(b) : Encoding.UTF8.GetString(b);
    }

    private static bool LooksTextual(byte[] b)
    {
        if (b.Length == 0) return false;
        int sample = Math.Min(b.Length, 256), printable = 0;
        for (int i = 0; i < sample; i++)
        {
            byte c = b[i];
            if (c is >= 0x20 and < 0x7F or (byte)'\t' or (byte)'\n' or (byte)'\r' or 0) printable++;
        }
        return printable >= sample * 0.85;
    }

    private static string PreviewVersion(byte[] b)
    {
        var sb = new StringBuilder();
        int sig = IndexOf(b, [0xBD, 0x04, 0xEF, 0xFE]);   // VS_FIXEDFILEINFO signature 0xFEEF04BD (LE)
        if (sig >= 0 && sig + 24 <= b.Length)
        {
            uint fMs = BitConverter.ToUInt32(b, sig + 8), fLs = BitConverter.ToUInt32(b, sig + 12);
            uint pMs = BitConverter.ToUInt32(b, sig + 16), pLs = BitConverter.ToUInt32(b, sig + 20);
            sb.AppendLine($"FileVersion:    {fMs >> 16}.{fMs & 0xFFFF}.{fLs >> 16}.{fLs & 0xFFFF}");
            sb.AppendLine($"ProductVersion: {pMs >> 16}.{pMs & 0xFFFF}.{pLs >> 16}.{pLs & 0xFFFF}");
            sb.AppendLine();
        }
        foreach (var s in Utf16Runs(b, 3)) sb.AppendLine(s);
        return sb.Length == 0 ? HexDump(b) : sb.ToString();
    }

    private static string PreviewStringTable(byte[] b)
    {
        var sb = new StringBuilder();
        int i = 0, n = 0;
        while (i + 2 <= b.Length && n < 16)
        {
            int len = b[i] | (b[i + 1] << 8);
            i += 2; n++;
            if (len <= 0) continue;
            int bytes = Math.Min(len * 2, b.Length - i);
            if (bytes <= 0) break;
            sb.AppendLine(Encoding.Unicode.GetString(b, i, bytes));
            i += bytes;
        }
        return sb.Length == 0 ? "(empty string table)" : sb.ToString();
    }

    private static IEnumerable<string> Utf16Runs(byte[] b, int minChars)
    {
        int i = 0;
        while (i + 1 < b.Length)
        {
            int start = i, chars = 0;
            while (i + 1 < b.Length && b[i + 1] == 0 && b[i] is >= 0x20 and < 0x7F) { i += 2; chars++; }
            if (chars >= minChars) yield return Encoding.Unicode.GetString(b, start, chars * 2);
            if (chars == 0) i += 2;
        }
    }

    private static string HexDump(byte[] b, int max = 8192)
    {
        var sb = new StringBuilder();
        int len = Math.Min(b.Length, max);
        for (int o = 0; o < len; o += 16)
        {
            sb.Append(o.ToString("X8")).Append("  ");
            for (int j = 0; j < 16; j++) sb.Append(o + j < len ? b[o + j].ToString("X2") + " " : "   ");
            sb.Append(' ');
            for (int j = 0; j < 16 && o + j < len; j++) { byte c = b[o + j]; sb.Append(c is >= 0x20 and < 0x7F ? (char)c : '.'); }
            sb.AppendLine();
        }
        if (b.Length > max) sb.AppendLine($"… ({b.Length - max:N0} more bytes)");
        return sb.ToString();
    }

    private static int IndexOf(byte[] hay, byte[] needle)
    {
        for (int i = 0; i + needle.Length <= hay.Length; i++)
        {
            bool ok = true;
            for (int j = 0; j < needle.Length; j++) if (hay[i + j] != needle[j]) { ok = false; break; }
            if (ok) return i;
        }
        return -1;
    }
}

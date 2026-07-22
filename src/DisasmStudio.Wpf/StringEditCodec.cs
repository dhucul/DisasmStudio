namespace DisasmStudio.Wpf;

/// <summary>Validates and encodes an in-place edit of a scanned ASCII or UTF-16LE string.</summary>
internal static class StringEditCodec
{
    /// <summary>
    /// Encode <paramref name="text"/> into the existing character allocation. Replacements may be shorter
    /// (the unused tail is NUL-filled) but may not grow, and use the same printable character set as
    /// <c>StringScanner</c> so the edited value remains discoverable on the next scan.
    /// </summary>
    public static bool TryEncode(string text, int capacityChars, bool wide, out byte[] bytes, out string error)
        => TryEncode(text, capacityChars, wide, allowLineBreaks: false, out bytes, out error);

    /// <summary>Encode with the live ANSI scanner's optional CR/LF character set.</summary>
    public static bool TryEncode(string text, int capacityChars, bool wide, bool allowLineBreaks,
        out byte[] bytes, out string error)
    {
        bytes = [];
        error = "";
        if (capacityChars < 0)
        {
            error = "The string has an invalid capacity.";
            return false;
        }
        if (text.Length > capacityChars)
        {
            error = $"The replacement is {text.Length:N0} characters; this string has room for {capacityChars:N0}.";
            return false;
        }

        foreach (char c in text)
        {
            if (c == '\t' || c is >= ' ' and <= '~') continue;
            if (!wide && allowLineBreaks && c is '\r' or '\n') continue;
            string allowed = !wide && allowLineBreaks
                ? "printable ASCII characters, tabs, or line breaks"
                : "printable ASCII characters or a tab";
            error = $"Unsupported character U+{(int)c:X4}. Use {allowed}.";
            return false;
        }

        bytes = new byte[checked(capacityChars * (wide ? 2 : 1))];
        for (int i = 0; i < text.Length; i++)
        {
            bytes[i * (wide ? 2 : 1)] = (byte)text[i];
            // The high byte of a UTF-16LE character and the unused tail are already zero-filled.
        }
        return true;
    }
}

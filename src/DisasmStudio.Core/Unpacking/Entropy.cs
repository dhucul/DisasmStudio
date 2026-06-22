namespace DisasmStudio.Core.Unpacking;

/// <summary>Shannon entropy of a byte buffer, in bits/byte (0…8). High values (&gt;~7.0) indicate
/// compressed or encrypted data — the hallmark of a packed section.</summary>
public static class Entropy
{
    public static double Shannon(ReadOnlySpan<byte> data)
    {
        if (data.Length == 0) return 0;
        Span<int> counts = stackalloc int[256];
        foreach (byte b in data) counts[b]++;
        double e = 0, n = data.Length;
        foreach (int c in counts)
            if (c > 0) { double p = c / n; e -= p * Math.Log2(p); }
        return e;
    }
}

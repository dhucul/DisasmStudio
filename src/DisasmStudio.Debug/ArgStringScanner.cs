using System.Text;
using DisasmStudio.Core.Analysis;

namespace DisasmStudio.Debug;

/// <summary>
/// Recovers the strings the <em>current call</em> is actually using by dereferencing the live
/// argument/register pointers at a debugger stop — the host-side enrichment CDA.Modern does. This catches
/// strings the section sweep (<see cref="StringScanner"/>) can't: heap and stack buffers, runtime-built
/// strings, and strings in <em>other</em> modules, because it follows the pointer the program is holding
/// rather than re-dumping the main image's data sections.
/// <para>
/// At a stop it reads every general-purpose register and a window of stack words above SP, and for each
/// value that looks like an address it reads a little memory and keeps it if it is (or points one hop on to)
/// a printable, NUL-terminated ASCII / UTF-16LE run. Every read is a host-side <c>ReadProcessMemory</c>, so a
/// bad pointer simply yields nothing and the target is never touched. Bounded by a per-stop read budget and a
/// pointer cache so a recurring argument pointer is read once.
/// </para>
/// </summary>
public static class ArgStringScanner
{
    private const int ReadLength = 512;   // bytes read per candidate pointer
    private const int MaxDepth = 2;       // pointer hops to follow (recovers LPWSTR* / a string at a struct head)
    private const int StackWords = 64;    // stack slots scanned from SP upward (stack args + local string ptrs)
    private const int MinChars = 4;       // matches the section scanner's default; rejects 3-char heap noise
    private const int ReadBudget = 8192;  // cap on ReadProcessMemory calls per stop

    // Registers worth dereferencing: all general-purpose regs, not just the x64 arg registers — a string
    // pointer is just as likely to sit in a scratch/non-volatile register mid-function. SP/IP/flags/segments
    // never name an argument string (and SP is walked separately), so they are skipped.
    private static readonly HashSet<string> Skip = new(StringComparer.OrdinalIgnoreCase)
    {
        "rsp", "esp", "rip", "eip", "rflags", "eflags", "cs", "ds", "es", "fs", "gs", "ss",
    };

    /// <summary>Scan the stopped thread's registers and nearby stack for pointers into strings. Returns
    /// <see cref="FoundString"/>s flagged <see cref="FoundString.Referenced"/>, each at the VA the string
    /// actually lives at, deduped by that VA. <paramref name="regs"/> is captured by the caller on the UI
    /// thread (it is read-only here), while the memory reads run on the caller's background thread — the same
    /// off-thread read pattern the section sweep already uses. Empty if <paramref name="regs"/> is null.</summary>
    public static List<FoundString> Scan(DebuggerEngine eng, RegisterSet? regs, int maxResults = 4096)
    {
        var found = new List<FoundString>();
        if (regs is null) return found;

        bool is32 = regs.Is32;
        int ptr = is32 ? 4 : 8;
        ulong maxAddr = is32 ? 0xFFFF_FFFFUL : 0x0000_7FFF_FFFF_FFFFUL;
        int budget = ReadBudget;
        var cache = new Dictionary<ulong, FoundString?>();   // a recurring pointer is resolved once per stop
        var seenVa = new HashSet<ulong>();                   // dedup resulting string addresses

        // (a) general-purpose registers
        foreach (var (name, value) in regs.Items)
        {
            if (Skip.Contains(name)) continue;
            TryDeref(eng, value, is32, maxAddr, cache, seenVa, found, ref budget);
            if (found.Count >= maxResults || budget <= 0) return found;
        }

        // (b) stack words from SP upward — x86 passes all arguments here; on x64 the 5th argument onward sits
        //     past the 32-byte shadow space, and local string pointers live nearby. Bounded by StackWords.
        var stack = eng.ReadMemory(regs.Sp, StackWords * ptr);
        for (int i = 0; i + ptr <= stack.Length; i += ptr)
        {
            ulong word = is32 ? BitConverter.ToUInt32(stack, i) : BitConverter.ToUInt64(stack, i);
            TryDeref(eng, word, is32, maxAddr, cache, seenVa, found, ref budget);
            if (found.Count >= maxResults || budget <= 0) break;
        }
        return found;
    }

    private static void TryDeref(DebuggerEngine eng, ulong p, bool is32, ulong maxAddr,
        Dictionary<ulong, FoundString?> cache, HashSet<ulong> seenVa, List<FoundString> found, ref int budget)
    {
        if (p < 0x10000 || p >= maxAddr) return;
        if (!cache.TryGetValue(p, out var proto))
        {
            proto = Resolve(eng, p, MaxDepth, is32, maxAddr, ref budget);
            cache[p] = proto;
        }
        if (proto is not null && seenVa.Add(proto.Va)) found.Add(proto);
    }

    /// <summary>Follow up to <paramref name="depth"/> pointer hops from <paramref name="p"/> looking for a
    /// string; the returned <see cref="FoundString"/>'s VA is where the string actually lives (so its text and
    /// address agree), else null.</summary>
    private static FoundString? Resolve(DebuggerEngine eng, ulong p, int depth, bool is32, ulong maxAddr, ref int budget)
    {
        if (budget <= 0 || depth < 0 || p < 0x10000 || p >= maxAddr) return null;
        budget--;
        var mem = eng.ReadMemory(p, ReadLength);
        if (mem.Length == 0) return null;

        if (Classify(mem, p) is { } s) return s;

        if (depth > 0)
        {
            ulong inner = is32
                ? (mem.Length >= 4 ? BitConverter.ToUInt32(mem, 0) : 0)
                : (mem.Length >= 8 ? BitConverter.ToUInt64(mem, 0) : 0);
            if (inner != p) return Resolve(eng, inner, depth - 1, is32, maxAddr, ref budget);
        }
        return null;
    }

    private static bool IsPrint(byte c) => c is >= 0x20 and <= 0x7E;
    private static bool IsStringHead(byte c) => IsPrint(c) || c == 0x09;
    private static bool IsStrChar(byte c) => IsPrint(c) || c is 0x09 or 0x0A or 0x0D;   // allow tab/LF/CR inside

    /// <summary>Classify a freshly-read buffer as an ANSI or UTF-16LE string located at <paramref name="va"/>,
    /// or null. UTF-16 is preferred when the head alternates printable/zero so wide strings aren't read as a
    /// one-char ASCII run.</summary>
    private static FoundString? Classify(byte[] b, ulong va)
    {
        int n = b.Length;
        // UTF-16LE: alternating printable / zero bytes, terminated by a wide NUL.
        if (n >= 4 && b[1] == 0 && b[3] == 0 && IsStringHead(b[0]) && IsStringHead(b[2]))
        {
            int len = 0;
            while (len + 1 < n && !(b[len] == 0 && b[len + 1] == 0)) len += 2;
            int chars = len / 2;
            if (chars >= MinChars)
            {
                var sb = new StringBuilder(chars);
                for (int k = 0; k < len; k += 2) sb.Append((char)b[k]);
                return new FoundString(va, chars, true, sb.ToString()) { Referenced = true };
            }
        }
        // ANSI: a printable run (tab/LF/CR allowed inside so a "…%s\n" message isn't truncated) ending in NUL.
        if (IsStringHead(b[0]))
        {
            int len = 0;
            while (len < n && b[len] != 0 && IsStrChar(b[len])) len++;
            if (len >= MinChars && len < n && b[len] == 0)
            {
                var sb = new StringBuilder(len);
                for (int k = 0; k < len; k++) sb.Append((char)b[k]);
                return new FoundString(va, len, false, sb.ToString()) { Referenced = true };
            }
        }
        return null;
    }
}

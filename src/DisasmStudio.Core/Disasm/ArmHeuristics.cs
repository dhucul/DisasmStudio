using DisasmStudio.Core.Formats;

namespace DisasmStudio.Core.Disasm;

/// <summary>
/// A cheap byte-frequency guess at whether a headerless blob is ARM or Thumb code, used only to pre-select
/// the raw-load dialog's architecture (the user always confirms). Thumb is flagged by the density of its
/// function prologue/epilogue opcodes — <c>push {…,lr}</c> (0xB5xx) and <c>pop {…,pc}</c> (0xBDxx); 32-bit
/// ARM by the density of <c>bl</c> (top byte 0xEB). Returns null when neither is clearly present.
/// </summary>
public static class ArmHeuristics
{
    public static Architecture? Detect(ReadOnlySpan<byte> d)
    {
        int n = Math.Min(d.Length, 0x40000);
        if (n < 256) return null;

        int thumb = 0;
        for (int i = 1; i < n; i += 2) if (d[i] is 0xB5 or 0xBD) thumb++;   // push {…,lr} / pop {…,pc}
        int arm = 0;
        for (int i = 3; i < n; i += 4) if (d[i] == 0xEB) arm++;             // bl (AL condition)

        double thumbPerKiB = thumb * 1024.0 / n;
        double armPerKiB = arm * 1024.0 / n;
        if (thumbPerKiB < 0.3 && armPerKiB < 0.3) return null;              // neither reads as ARM code
        return thumbPerKiB >= armPerKiB ? Architecture.Thumb : Architecture.Arm;
    }
}

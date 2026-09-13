namespace DisasmStudio.Core.IL;

/// <summary>Fixed-width integer semantics shared by folding and emulation.</summary>
internal static class IntegerSemantics
{
    public static long Mask(long value, int width) => width is <= 0 or >= 8
        ? value : value & ((1L << (width * 8)) - 1);

    public static long SignExtend(long value, int width)
    {
        if (width is <= 0 or >= 8) return value;
        long sign = 1L << (width * 8 - 1);
        return (Mask(value, width) ^ sign) - sign;
    }

    public static bool TryBinary(BinOp op, long left, long right, int width, out long value)
    {
        int w = width <= 0 ? 8 : width;
        value = 0;
        if (w > 8) return false;
        ulong l = (ulong)Mask(left, w), r = (ulong)Mask(right, w);
        int shift = (int)(right & (w == 8 ? 63 : 31));
        unchecked
        {
            switch (op)
            {
                case BinOp.Add: value = (long)(l + r); break;
                case BinOp.Sub: value = (long)(l - r); break;
                case BinOp.Mul: case BinOp.UMul: value = (long)(l * r); break;
                case BinOp.And: value = (long)(l & r); break;
                case BinOp.Or: value = (long)(l | r); break;
                case BinOp.Xor: value = (long)(l ^ r); break;
                case BinOp.Shl: value = (long)(l << shift); break;
                case BinOp.Shr: value = (long)(l >> shift); break;
                case BinOp.Sar: value = SignExtend(left, w) >> shift; break;
                case BinOp.Rol: case BinOp.Ror:
                    int bits = w * 8, count = shift % bits;
                    value = count == 0 ? (long)l : op == BinOp.Rol
                        ? (long)((l << count) | (l >> (bits - count)))
                        : (long)((l >> count) | (l << (bits - count)));
                    break;
                case BinOp.UDiv: case BinOp.UMod:
                    if (r == 0) return false;
                    value = (long)(op == BinOp.UDiv ? l / r : l % r); break;
                case BinOp.SDiv: case BinOp.SMod:
                    long n = SignExtend(left, w), d = SignExtend(right, w);
                    if (d == 0 || (d == -1 && n == (w == 8 ? long.MinValue : -(1L << (w * 8 - 1))))) return false;
                    value = op == BinOp.SDiv ? n / d : n % d; break;
                default: return false;
            }
            value = Mask(value, w);
            return true;
        }
    }
}

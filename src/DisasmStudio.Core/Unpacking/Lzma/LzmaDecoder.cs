// LZMA decompressor — a self-contained port of Igor Pavlov's public-domain LZMA SDK (the C# reference
// decoder: range decoder + output window + the LZMA decoder). It is used to undo VMProtect's "Pack the
// Output File" LZMA compression statically (see VmpStaticUnpacker), so the project gains LZMA support
// without a NuGet dependency — in keeping with the "Iced + OS + BCL only" philosophy.
//
// The SDK predates nullable reference types; its logic is reproduced faithfully (only renamed from its
// RangeCoder/LZ sub-namespaces to flat internal types) and kept isolated behind the small Lzma.Decode
// facade at the bottom. Public domain.
#nullable disable
using System.IO;

namespace DisasmStudio.Core.Unpacking.Lzma;

/// <summary>Public entry point: decode a raw LZMA stream given its 5-byte properties. VMProtect stores the
/// 5 property bytes and a raw (header-less, end-marker-terminated) LZMA stream per packed block.</summary>
public static class LzmaCodec
{
    /// <summary>Decode a raw LZMA stream.</summary>
    /// <param name="props">The 5 LZMA property bytes (lc/lp/pb + 4-byte dictionary size).</param>
    /// <param name="input">The raw compressed stream (no .lzma alone-header, no size prefix).</param>
    /// <param name="outSizeHint">Exact uncompressed size when known — the decoder then stops precisely;
    /// pass -1 to decode until the end-of-stream marker.</param>
    public static byte[] Decode(ReadOnlySpan<byte> props, ReadOnlySpan<byte> input, long outSizeHint)
    {
        var arr = input.ToArray();
        return Decode(props, arr, 0, arr.Length, outSizeHint);
    }

    /// <summary>Decode a raw LZMA stream that lives at <paramref name="offset"/> in <paramref name="input"/>
    /// (no copy — the unpacker hands the tail of a large mapped file).</summary>
    public static byte[] Decode(ReadOnlySpan<byte> props, byte[] input, int offset, int count, long outSizeHint)
    {
        if (props.Length < 5) throw new ArgumentException("LZMA properties must be at least 5 bytes.", nameof(props));
        var dec = new LzmaDecoder();
        dec.SetDecoderProperties(props[..5].ToArray());
        using var inStream = new MemoryStream(input, offset, count, writable: false);
        using var outStream = new MemoryStream(outSizeHint > 0 && outSizeHint < int.MaxValue ? (int)outSizeHint : 0);
        dec.Code(inStream, outStream, count, outSizeHint);
        return outStream.ToArray();
    }
}

internal static class LzmaBase
{
    public const uint kNumStates = 12;

    public struct State
    {
        public uint Index;
        public void Init() => Index = 0;
        public void UpdateChar()
        {
            if (Index < 4) Index = 0;
            else if (Index < 10) Index -= 3;
            else Index -= 6;
        }
        public void UpdateMatch() => Index = (uint)(Index < 7 ? 7 : 10);
        public void UpdateRep() => Index = (uint)(Index < 7 ? 8 : 11);
        public void UpdateShortRep() => Index = (uint)(Index < 7 ? 9 : 11);
        public readonly bool IsCharState() => Index < 7;
    }

    public const int kNumPosSlotBits = 6;

    public const int kNumLenToPosStatesBits = 2;
    public const uint kNumLenToPosStates = 1 << kNumLenToPosStatesBits;

    public const uint kMatchMinLen = 2;

    public static uint GetLenToPosState(uint len)
    {
        len -= kMatchMinLen;
        if (len < kNumLenToPosStates) return len;
        return kNumLenToPosStates - 1;
    }

    public const int kNumAlignBits = 4;
    public const int kEndPosModelIndex = 14;
    public const int kNumFullDistances = 1 << (kEndPosModelIndex / 2);
    public const int kNumPosStatesBitsMax = 4;

    public const int kNumLowLenBits = 3;
    public const int kNumMidLenBits = 3;
    public const int kNumHighLenBits = 8;
    public const uint kNumLowLenSymbols = 1 << kNumLowLenBits;
    public const uint kNumMidLenSymbols = 1 << kNumMidLenBits;

    public const int kStartPosModelIndex = 4;
}

/// <summary>LZMA range decoder.</summary>
internal sealed class RangeDecoder
{
    public const uint kTopValue = 1 << 24;
    public uint Range;
    public uint Code;
    public Stream Stream;

    public void Init(Stream stream)
    {
        Stream = stream;
        Code = 0;
        Range = 0xFFFFFFFF;
        for (int i = 0; i < 5; i++)
            Code = (Code << 8) | (byte)Stream.ReadByte();
    }

    public void ReleaseStream() => Stream = null;

    public uint DecodeDirectBits(int numTotalBits)
    {
        uint range = Range;
        uint code = Code;
        uint result = 0;
        for (int i = numTotalBits; i > 0; i--)
        {
            range >>= 1;
            uint t = (code - range) >> 31;
            code -= range & (t - 1);
            result = (result << 1) | (1 - t);
            if (range < kTopValue)
            {
                code = (code << 8) | (byte)Stream.ReadByte();
                range <<= 8;
            }
        }
        Range = range;
        Code = code;
        return result;
    }
}

internal struct BitDecoder
{
    private const int kNumBitModelTotalBits = 11;
    private const uint kBitModelTotal = 1 << kNumBitModelTotalBits;
    private const int kNumMoveBits = 5;
    private uint Prob;

    public void Init() => Prob = kBitModelTotal >> 1;

    public uint Decode(RangeDecoder rangeDecoder)
    {
        uint newBound = (rangeDecoder.Range >> kNumBitModelTotalBits) * Prob;
        if (rangeDecoder.Code < newBound)
        {
            rangeDecoder.Range = newBound;
            Prob += (kBitModelTotal - Prob) >> kNumMoveBits;
            if (rangeDecoder.Range < RangeDecoder.kTopValue)
            {
                rangeDecoder.Code = (rangeDecoder.Code << 8) | (byte)rangeDecoder.Stream.ReadByte();
                rangeDecoder.Range <<= 8;
            }
            return 0;
        }
        rangeDecoder.Range -= newBound;
        rangeDecoder.Code -= newBound;
        Prob -= Prob >> kNumMoveBits;
        if (rangeDecoder.Range < RangeDecoder.kTopValue)
        {
            rangeDecoder.Code = (rangeDecoder.Code << 8) | (byte)rangeDecoder.Stream.ReadByte();
            rangeDecoder.Range <<= 8;
        }
        return 1;
    }
}

internal struct BitTreeDecoder
{
    private readonly BitDecoder[] Models;
    private readonly int NumBitLevels;

    public BitTreeDecoder(int numBitLevels)
    {
        NumBitLevels = numBitLevels;
        Models = new BitDecoder[1 << numBitLevels];
    }

    public void Init()
    {
        for (uint i = 1; i < (1 << NumBitLevels); i++)
            Models[i].Init();
    }

    public uint Decode(RangeDecoder rangeDecoder)
    {
        uint m = 1;
        for (int bitIndex = NumBitLevels; bitIndex > 0; bitIndex--)
            m = (m << 1) + Models[m].Decode(rangeDecoder);
        return m - ((uint)1 << NumBitLevels);
    }

    public uint ReverseDecode(RangeDecoder rangeDecoder)
    {
        uint m = 1;
        uint symbol = 0;
        for (int bitIndex = 0; bitIndex < NumBitLevels; bitIndex++)
        {
            uint bit = Models[m].Decode(rangeDecoder);
            m <<= 1;
            m += bit;
            symbol |= bit << bitIndex;
        }
        return symbol;
    }

    public static uint ReverseDecode(BitDecoder[] models, uint startIndex, RangeDecoder rangeDecoder, int numBitLevels)
    {
        uint m = 1;
        uint symbol = 0;
        for (int bitIndex = 0; bitIndex < numBitLevels; bitIndex++)
        {
            uint bit = models[startIndex + m].Decode(rangeDecoder);
            m <<= 1;
            m += bit;
            symbol |= bit << bitIndex;
        }
        return symbol;
    }
}

/// <summary>LZMA sliding-window output buffer.</summary>
internal sealed class OutWindow
{
    private byte[] _buffer;
    private uint _pos;
    private uint _windowSize;
    private uint _streamPos;
    private Stream _stream;

    public uint TrainSize;

    public void Create(uint windowSize)
    {
        if (_windowSize != windowSize)
            _buffer = new byte[windowSize];
        _windowSize = windowSize;
        _pos = 0;
        _streamPos = 0;
    }

    public void Init(Stream stream, bool solid)
    {
        ReleaseStream();
        _stream = stream;
        if (!solid)
        {
            _streamPos = 0;
            _pos = 0;
            TrainSize = 0;
        }
    }

    public void ReleaseStream()
    {
        Flush();
        _stream = null;
    }

    public void Flush()
    {
        uint size = _pos - _streamPos;
        if (size == 0) return;
        _stream.Write(_buffer, (int)_streamPos, (int)size);
        if (_pos >= _windowSize) _pos = 0;
        _streamPos = _pos;
    }

    public void CopyBlock(uint distance, uint len)
    {
        uint pos = _pos - distance - 1;
        if (pos >= _windowSize) pos += _windowSize;
        for (; len > 0; len--)
        {
            if (pos >= _windowSize) pos = 0;
            _buffer[_pos++] = _buffer[pos++];
            if (_pos >= _windowSize) Flush();
        }
    }

    public void PutByte(byte b)
    {
        _buffer[_pos++] = b;
        if (_pos >= _windowSize) Flush();
    }

    public byte GetByte(uint distance)
    {
        uint pos = _pos - distance - 1;
        if (pos >= _windowSize) pos += _windowSize;
        return _buffer[pos];
    }
}

internal sealed class LzmaDecoder
{
    private sealed class LenDecoder
    {
        private BitDecoder m_Choice = new();
        private BitDecoder m_Choice2 = new();
        private readonly BitTreeDecoder[] m_LowCoder = new BitTreeDecoder[1 << LzmaBase.kNumPosStatesBitsMax];
        private readonly BitTreeDecoder[] m_MidCoder = new BitTreeDecoder[1 << LzmaBase.kNumPosStatesBitsMax];
        private BitTreeDecoder m_HighCoder = new(LzmaBase.kNumHighLenBits);
        private uint m_NumPosStates;

        public void Create(uint numPosStates)
        {
            for (uint posState = m_NumPosStates; posState < numPosStates; posState++)
            {
                m_LowCoder[posState] = new BitTreeDecoder(LzmaBase.kNumLowLenBits);
                m_MidCoder[posState] = new BitTreeDecoder(LzmaBase.kNumMidLenBits);
            }
            m_NumPosStates = numPosStates;
        }

        public void Init()
        {
            m_Choice.Init();
            for (uint posState = 0; posState < m_NumPosStates; posState++)
            {
                m_LowCoder[posState].Init();
                m_MidCoder[posState].Init();
            }
            m_Choice2.Init();
            m_HighCoder.Init();
        }

        public uint Decode(RangeDecoder rangeDecoder, uint posState)
        {
            if (m_Choice.Decode(rangeDecoder) == 0)
                return m_LowCoder[posState].Decode(rangeDecoder);
            uint symbol = LzmaBase.kNumLowLenSymbols;
            if (m_Choice2.Decode(rangeDecoder) == 0)
                symbol += m_MidCoder[posState].Decode(rangeDecoder);
            else
            {
                symbol += LzmaBase.kNumMidLenSymbols;
                symbol += m_HighCoder.Decode(rangeDecoder);
            }
            return symbol;
        }
    }

    private sealed class LiteralDecoder
    {
        private struct Decoder2
        {
            private BitDecoder[] m_Decoders;
            public void Create() => m_Decoders = new BitDecoder[0x300];
            public void Init() { for (int i = 0; i < 0x300; i++) m_Decoders[i].Init(); }

            public byte DecodeNormal(RangeDecoder rangeDecoder)
            {
                uint symbol = 1;
                do
                    symbol = (symbol << 1) | m_Decoders[symbol].Decode(rangeDecoder);
                while (symbol < 0x100);
                return (byte)symbol;
            }

            public byte DecodeWithMatchByte(RangeDecoder rangeDecoder, byte matchByte)
            {
                uint symbol = 1;
                do
                {
                    uint matchBit = (uint)(matchByte >> 7) & 1;
                    matchByte <<= 1;
                    uint bit = m_Decoders[((1 + matchBit) << 8) + symbol].Decode(rangeDecoder);
                    symbol = (symbol << 1) | bit;
                    if (matchBit != bit)
                    {
                        while (symbol < 0x100)
                            symbol = (symbol << 1) | m_Decoders[symbol].Decode(rangeDecoder);
                        break;
                    }
                }
                while (symbol < 0x100);
                return (byte)symbol;
            }
        }

        private Decoder2[] m_Coders;
        private int m_NumPrevBits;
        private int m_NumPosBits;
        private uint m_PosMask;

        public void Create(int numPosBits, int numPrevBits)
        {
            if (m_Coders != null && m_NumPrevBits == numPrevBits && m_NumPosBits == numPosBits)
                return;
            m_NumPosBits = numPosBits;
            m_PosMask = ((uint)1 << numPosBits) - 1;
            m_NumPrevBits = numPrevBits;
            uint numStates = (uint)1 << (m_NumPrevBits + m_NumPosBits);
            m_Coders = new Decoder2[numStates];
            for (uint i = 0; i < numStates; i++)
                m_Coders[i].Create();
        }

        public void Init()
        {
            uint numStates = (uint)1 << (m_NumPrevBits + m_NumPosBits);
            for (uint i = 0; i < numStates; i++)
                m_Coders[i].Init();
        }

        private uint GetState(uint pos, byte prevByte)
            => ((pos & m_PosMask) << m_NumPrevBits) + (uint)(prevByte >> (8 - m_NumPrevBits));

        public byte DecodeNormal(RangeDecoder rangeDecoder, uint pos, byte prevByte)
            => m_Coders[GetState(pos, prevByte)].DecodeNormal(rangeDecoder);

        public byte DecodeWithMatchByte(RangeDecoder rangeDecoder, uint pos, byte prevByte, byte matchByte)
            => m_Coders[GetState(pos, prevByte)].DecodeWithMatchByte(rangeDecoder, matchByte);
    }

    private readonly OutWindow m_OutWindow = new();
    private readonly RangeDecoder m_RangeDecoder = new();

    private readonly BitDecoder[] m_IsMatchDecoders = new BitDecoder[LzmaBase.kNumStates << LzmaBase.kNumPosStatesBitsMax];
    private readonly BitDecoder[] m_IsRepDecoders = new BitDecoder[LzmaBase.kNumStates];
    private readonly BitDecoder[] m_IsRepG0Decoders = new BitDecoder[LzmaBase.kNumStates];
    private readonly BitDecoder[] m_IsRepG1Decoders = new BitDecoder[LzmaBase.kNumStates];
    private readonly BitDecoder[] m_IsRepG2Decoders = new BitDecoder[LzmaBase.kNumStates];
    private readonly BitDecoder[] m_IsRep0LongDecoders = new BitDecoder[LzmaBase.kNumStates << LzmaBase.kNumPosStatesBitsMax];

    private readonly BitTreeDecoder[] m_PosSlotDecoder = new BitTreeDecoder[LzmaBase.kNumLenToPosStates];
    private readonly BitDecoder[] m_PosDecoders = new BitDecoder[LzmaBase.kNumFullDistances - LzmaBase.kEndPosModelIndex];

    private BitTreeDecoder m_PosAlignDecoder = new(LzmaBase.kNumAlignBits);

    private readonly LenDecoder m_LenDecoder = new();
    private readonly LenDecoder m_RepLenDecoder = new();

    private readonly LiteralDecoder m_LiteralDecoder = new();

    private uint m_DictionarySize = 0xFFFFFFFF;
    private uint m_DictionarySizeCheck;

    private uint m_PosStateMask;

    public LzmaDecoder()
    {
        for (int i = 0; i < LzmaBase.kNumLenToPosStates; i++)
            m_PosSlotDecoder[i] = new BitTreeDecoder(LzmaBase.kNumPosSlotBits);
    }

    private void SetDictionarySize(uint dictionarySize)
    {
        if (m_DictionarySize != dictionarySize)
        {
            m_DictionarySize = dictionarySize;
            m_DictionarySizeCheck = Math.Max(m_DictionarySize, 1);
            uint blockSize = Math.Max(m_DictionarySizeCheck, 1 << 12);
            m_OutWindow.Create(blockSize);
        }
    }

    private void SetLiteralProperties(int lp, int lc)
    {
        if (lp > 8) throw new InvalidDataException("Invalid LZMA lp.");
        if (lc > 8) throw new InvalidDataException("Invalid LZMA lc.");
        m_LiteralDecoder.Create(lp, lc);
    }

    private void SetPosBitsProperties(int pb)
    {
        if (pb > LzmaBase.kNumPosStatesBitsMax) throw new InvalidDataException("Invalid LZMA pb.");
        uint numPosStates = (uint)1 << pb;
        m_LenDecoder.Create(numPosStates);
        m_RepLenDecoder.Create(numPosStates);
        m_PosStateMask = numPosStates - 1;
    }

    private void Init(Stream inStream, Stream outStream)
    {
        m_RangeDecoder.Init(inStream);
        m_OutWindow.Init(outStream, false);

        uint i;
        for (i = 0; i < LzmaBase.kNumStates; i++)
        {
            for (uint j = 0; j <= m_PosStateMask; j++)
            {
                uint index = (i << LzmaBase.kNumPosStatesBitsMax) + j;
                m_IsMatchDecoders[index].Init();
                m_IsRep0LongDecoders[index].Init();
            }
            m_IsRepDecoders[i].Init();
            m_IsRepG0Decoders[i].Init();
            m_IsRepG1Decoders[i].Init();
            m_IsRepG2Decoders[i].Init();
        }
        m_LiteralDecoder.Init();
        for (i = 0; i < LzmaBase.kNumLenToPosStates; i++)
            m_PosSlotDecoder[i].Init();
        for (i = 0; i < LzmaBase.kNumFullDistances - LzmaBase.kEndPosModelIndex; i++)
            m_PosDecoders[i].Init();
        m_LenDecoder.Init();
        m_RepLenDecoder.Init();
        m_PosAlignDecoder.Init();
    }

    /// <summary>Decode the LZMA stream. <paramref name="outSize"/> is the expected uncompressed length, or
    /// -1 to run until the end-of-stream marker.</summary>
    public void Code(Stream inStream, Stream outStream, long inSize, long outSize)
    {
        Init(inStream, outStream);

        LzmaBase.State state = new();
        state.Init();
        uint rep0 = 0, rep1 = 0, rep2 = 0, rep3 = 0;

        ulong nowPos64 = 0;
        ulong outSize64 = (ulong)outSize;
        if (nowPos64 < outSize64)
        {
            if (m_IsMatchDecoders[state.Index << LzmaBase.kNumPosStatesBitsMax].Decode(m_RangeDecoder) != 0)
                throw new InvalidDataException("LZMA: corrupt stream (unexpected match at start).");
            state.UpdateChar();
            byte b = m_LiteralDecoder.DecodeNormal(m_RangeDecoder, 0, 0);
            m_OutWindow.PutByte(b);
            nowPos64++;
        }
        while (nowPos64 < outSize64)
        {
            uint posState = (uint)nowPos64 & m_PosStateMask;
            if (m_IsMatchDecoders[(state.Index << LzmaBase.kNumPosStatesBitsMax) + posState].Decode(m_RangeDecoder) == 0)
            {
                byte prevByte = m_OutWindow.GetByte(0);
                byte b = state.IsCharState()
                    ? m_LiteralDecoder.DecodeNormal(m_RangeDecoder, (uint)nowPos64, prevByte)
                    : m_LiteralDecoder.DecodeWithMatchByte(m_RangeDecoder, (uint)nowPos64, prevByte, m_OutWindow.GetByte(rep0));
                m_OutWindow.PutByte(b);
                state.UpdateChar();
                nowPos64++;
            }
            else
            {
                uint len;
                if (m_IsRepDecoders[state.Index].Decode(m_RangeDecoder) == 1)
                {
                    if (m_IsRepG0Decoders[state.Index].Decode(m_RangeDecoder) == 0)
                    {
                        if (m_IsRep0LongDecoders[(state.Index << LzmaBase.kNumPosStatesBitsMax) + posState].Decode(m_RangeDecoder) == 0)
                        {
                            state.UpdateShortRep();
                            m_OutWindow.PutByte(m_OutWindow.GetByte(rep0));
                            nowPos64++;
                            continue;
                        }
                    }
                    else
                    {
                        uint distance;
                        if (m_IsRepG1Decoders[state.Index].Decode(m_RangeDecoder) == 0)
                        {
                            distance = rep1;
                        }
                        else
                        {
                            if (m_IsRepG2Decoders[state.Index].Decode(m_RangeDecoder) == 0)
                                distance = rep2;
                            else
                            {
                                distance = rep3;
                                rep3 = rep2;
                            }
                            rep2 = rep1;
                        }
                        rep1 = rep0;
                        rep0 = distance;
                    }
                    len = m_RepLenDecoder.Decode(m_RangeDecoder, posState) + LzmaBase.kMatchMinLen;
                    state.UpdateRep();
                }
                else
                {
                    rep3 = rep2;
                    rep2 = rep1;
                    rep1 = rep0;
                    len = LzmaBase.kMatchMinLen + m_LenDecoder.Decode(m_RangeDecoder, posState);
                    state.UpdateMatch();
                    uint posSlot = m_PosSlotDecoder[LzmaBase.GetLenToPosState(len)].Decode(m_RangeDecoder);
                    if (posSlot >= LzmaBase.kStartPosModelIndex)
                    {
                        int numDirectBits = (int)((posSlot >> 1) - 1);
                        rep0 = (2 | (posSlot & 1)) << numDirectBits;
                        if (posSlot < LzmaBase.kEndPosModelIndex)
                            rep0 += BitTreeDecoder.ReverseDecode(m_PosDecoders, rep0 - posSlot - 1, m_RangeDecoder, numDirectBits);
                        else
                        {
                            rep0 += m_RangeDecoder.DecodeDirectBits(numDirectBits - LzmaBase.kNumAlignBits) << LzmaBase.kNumAlignBits;
                            rep0 += m_PosAlignDecoder.ReverseDecode(m_RangeDecoder);
                        }
                    }
                    else
                        rep0 = posSlot;
                }
                if (rep0 >= m_OutWindow.TrainSize + nowPos64 || rep0 >= m_DictionarySizeCheck)
                {
                    if (rep0 == 0xFFFFFFFF)
                        break;   // end-of-stream marker
                    throw new InvalidDataException("LZMA: corrupt stream (distance out of range).");
                }
                m_OutWindow.CopyBlock(rep0, len);
                nowPos64 += len;
            }
        }
        m_OutWindow.Flush();
        m_OutWindow.ReleaseStream();
        m_RangeDecoder.ReleaseStream();
    }

    public void SetDecoderProperties(byte[] properties)
    {
        if (properties.Length < 5)
            throw new InvalidDataException("LZMA: properties too short.");
        int lc = properties[0] % 9;
        int remainder = properties[0] / 9;
        int lp = remainder % 5;
        int pb = remainder / 5;
        if (pb > LzmaBase.kNumPosStatesBitsMax)
            throw new InvalidDataException("LZMA: invalid pb in properties.");
        uint dictionarySize = 0;
        for (int i = 0; i < 4; i++)
            dictionarySize += (uint)properties[1 + i] << (i * 8);
        SetDictionarySize(dictionarySize);
        SetLiteralProperties(lp, lc);
        SetPosBitsProperties(pb);
    }
}

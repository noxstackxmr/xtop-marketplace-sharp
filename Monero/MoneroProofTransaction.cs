using System.Buffers.Binary;

namespace MarketplaceCore.Monero;
public sealed record MoneroProofOutput(byte[] Key, byte ViewTag, byte[] EncryptedAmount, byte[] Commitment);

public sealed record MoneroProofTransaction(byte[] PrefixWithoutCarrier, byte[] RingCtBase,
    byte[] TransactionKey, MoneroProofOutput[] Outputs, byte[] Message, ulong Fee, int ExtraLength)
{
    public byte[][] InputKeyImages { get; init; } = [];
    public static MoneroProofTransaction Parse(byte[] blob)
    {
        if (blob.Length > 1_000_000) throw new FormatException("transaction exceeds the proof parser size limit");
        var reader = new NativeByteReader(blob);
        if (reader.VarInt() != 2 || reader.VarInt() != 0) throw new FormatException("Expected an unlocked v2 transaction.");
        int inputs = reader.Count(128);
        if (inputs == 0) throw new FormatException("Missing inputs.");
        var images = new byte[inputs][];
        for (int i = 0; i < inputs; i++)
        {
            if (reader.Byte() != 2 || reader.VarInt() != 0 || reader.VarInt() != 16)
                throw new FormatException("Expected RingCT inputs with 16 ring members.");
            for (int j = 0; j < 16; j++) reader.VarInt();
            images[i] = reader.Bytes(32); MoneroProofCrypto.RequirePoint(images[i]);
        }
        int count = reader.Count(16);
        if (count < 2) throw new FormatException("Expected at least two outputs.");
        var keys = new byte[count][];
        var tags = new byte[count];
        for (int i = 0; i < count; i++)
        {
            if (reader.VarInt() != 0 || reader.Byte() != 3) throw new FormatException("Expected tagged RingCT outputs.");
            keys[i] = reader.Bytes(32); MoneroProofCrypto.RequirePoint(keys[i]);
            tags[i] = reader.Byte();
        }
        int extraOffset = reader.Position;
        byte[] extra = reader.Bytes(reader.Count(1060));
        var er = new NativeByteReader(extra);
        var retained = new List<byte>();
        byte[]? r = null, message = null;
        while (er.Remaining > 0)
        {
            int start = er.Position;
            byte tag = er.Byte();
            switch (tag)
            {
                case 1:
                    if (r != null) throw new FormatException("Duplicate transaction key.");
                    r = er.Bytes(32); MoneroProofCrypto.RequirePoint(r);
                    break;
                case 2: er.Bytes(er.Count(255)); break;
                case 0xDE:
                    if (message != null) throw new FormatException("Duplicate XTOP carrier.");
                    message = er.Bytes(er.Count(1024));
                    break;
                default: throw new FormatException("unsupported extra field in the proof profile");
            }
            if (tag != 0xDE) retained.AddRange(extra.AsSpan(start, er.Position - start).ToArray());
        }
        if (r == null || message == null) throw new FormatException("Missing transaction key or XTOP carrier.");
        byte[] prefix = [.. blob.AsSpan(0, extraOffset), .. NativeVarInt.Encode((ulong)retained.Count), .. retained];
        int baseOffset = reader.Position;
        if (reader.Byte() != 6) throw new FormatException("Expected CLSAG/Bulletproof+ (RingCT type 6).");
        ulong fee = reader.VarInt();
        var amounts = new byte[count][];
        for (int i = 0; i < count; i++) amounts[i] = reader.Bytes(8);
        var outputs = new MoneroProofOutput[count];
        for (int i = 0; i < count; i++)
        {
            byte[] commitment = reader.Bytes(32); MoneroProofCrypto.RequirePoint(commitment);
            outputs[i] = new(keys[i], tags[i], amounts[i], commitment);
        }
        return new(prefix, blob.AsSpan(baseOffset, reader.Position - baseOffset).ToArray(), r, outputs, message, fee, extra.Length) { InputKeyImages = images };
    }
}

internal sealed class NativeByteReader(byte[] data)
{
    public int Position { get; private set; }
    public int Remaining => data.Length - Position;
    public byte Byte() => Bytes(1)[0];
    public byte[] Bytes(int length)
    {
        if (length < 0 || length > Remaining) throw new FormatException("Truncated byte sequence.");
        byte[] result = data.AsSpan(Position, length).ToArray(); Position += length; return result;
    }
    public ushort UInt16() => BinaryPrimitives.ReadUInt16LittleEndian(Bytes(2));
    public uint UInt32() => BinaryPrimitives.ReadUInt32LittleEndian(Bytes(4));
    public ulong UInt64() => BinaryPrimitives.ReadUInt64LittleEndian(Bytes(8));
    public ulong VarInt()
    {
        ulong result = 0;
        for (int i = 0; i < 10; i++)
        {
            byte b = Byte();
            if (i == 9 && b > 1) throw new FormatException("Varint overflow.");
            result |= (ulong)(b & 127) << (7 * i);
            if ((b & 128) == 0)
            {
                if (i > 0 && b == 0) throw new FormatException("Noncanonical varint.");
                return result;
            }
        }
        throw new FormatException("Varint overflow.");
    }
    public int Count(int maximum)
    {
        ulong count = VarInt();
        if (count > (ulong)maximum) throw new FormatException("Count exceeds the profile limit.");
        return (int)count;
    }
    public void End() { if (Remaining != 0) throw new FormatException("Unexpected trailing bytes."); }
}

using MarketplaceCore.Protocol.Attachments;
using System.Buffers.Binary;

namespace MarketplaceCore.Protocol.Messages;

internal ref struct PayloadReader(ReadOnlySpan<byte> data)
{
    private ReadOnlySpan<byte> remaining = data;

    public byte ReadByte() => Take(1)[0];
    public ushort ReadUInt16() => BinaryPrimitives.ReadUInt16LittleEndian(Take(2));
    public uint ReadUInt32() => BinaryPrimitives.ReadUInt32LittleEndian(Take(4));
    public ulong ReadUInt64() => BinaryPrimitives.ReadUInt64LittleEndian(Take(8));

    public ChunkReference ReadChunkReference()
    {
        var hash = Take(32).ToArray();
        var length = ReadUInt32();
        if (length is < 1 or > 16_777_216) throw new FormatException("invalid attachment reference length");
        return new ChunkReference(hash, length, Take(32).ToArray());
    }

    public ReadOnlySpan<byte> Take(int length)
    {
        if (length < 0 || length > remaining.Length)
            throw new FormatException("truncated payload");
        var value = remaining[..length];
        remaining = remaining[length..];
        return value;
    }

    public void EnsureEnd()
    {
        if (!remaining.IsEmpty) throw new FormatException("unexpected trailing payload bytes");
    }
}

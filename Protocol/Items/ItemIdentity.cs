using System.Buffers.Binary;
using MarketplaceCore.Monero;

namespace MarketplaceCore.Protocol.Items;

public static class ItemIdentity
{
    public static byte[] Derive(byte[] collectionId, uint serial)
    {
        if (collectionId.Length != 32) throw new ArgumentException("collection id must contain 32 bytes", nameof(collectionId));
        var bytes = new byte[49];
        "XTOP:ITEM:V1\0"u8.CopyTo(bytes);
        collectionId.CopyTo(bytes, 13);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(45), serial);
        return MoneroProofCrypto.Hash(bytes);
    }
}

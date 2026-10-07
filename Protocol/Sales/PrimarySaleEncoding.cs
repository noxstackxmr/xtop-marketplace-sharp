using MarketplaceCore.Protocol.Attachments;

namespace MarketplaceCore.Protocol.Sales;

internal static class PrimarySaleEncoding
{
    public static byte[] Write(Action<BinaryWriter> write)
    {
        using var stream = new MemoryStream();
        using var writer = new BinaryWriter(stream);
        write(writer);
        return stream.ToArray();
    }

    public static void Reference(BinaryWriter writer, ChunkReference reference)
    {
        writer.Write(reference.Hash); writer.Write(reference.TotalLength); writer.Write(reference.MerkleRoot);
    }
}

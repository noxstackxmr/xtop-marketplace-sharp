namespace MarketplaceCore.Protocol.Attachments;

public sealed record ChunkReference(byte[] Hash, uint TotalLength, byte[] MerkleRoot);

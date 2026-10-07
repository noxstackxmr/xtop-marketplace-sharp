namespace MarketplaceCore.Protocol.Collections;

public sealed record CollectionCreatePolicy(byte Network, byte[] ConfigHash, byte[] FeeSpendKey, byte[] FeeViewKey,
    ulong CreationFee, ulong ControlAmount, ulong NftAmount)
{
    public byte WireVersion { get; init; } = 15;
}

public sealed record NewBinding(byte OutputIndex, byte[] KeyImage, byte[] OwnerKey, ulong NominalAmount,
    byte OwnershipWitness, byte AmountWitness);

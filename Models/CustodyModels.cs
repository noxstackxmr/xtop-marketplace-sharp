using MarketplaceCore.Crypto;
using MarketplaceCore.Protocol.Collections;
using MarketplaceCore.Protocol.Sales;

namespace MarketplaceCore.Models;

public sealed record CustodyAddress(string PublicSpendKey, string PublicViewKey)
{
    public byte[] Bytes()
    {
        var bytes = OwnerSignature.Hex(PublicSpendKey, 32).Concat(OwnerSignature.Hex(PublicViewKey, 32)).ToArray();
        Protocol.Marketplaces.MarketplaceFormat.Address(bytes);
        return bytes;
    }
    public static CustodyAddress From(byte[] bytes) => new(Convert.ToHexStringLower(bytes[..32]), Convert.ToHexStringLower(bytes[32..]));
    public object Payment(ulong amount) => new { spend_public = PublicSpendKey, view_public = PublicViewKey, amount };
    public object Native() => new { spend_public = PublicSpendKey, view_public = PublicViewKey };
}

public sealed record CustodyTip(long Height, string Hash);
public sealed record CustodyOutput(string TransactionId, byte OutputIndex, string PublicKey, string KeyImage,
    string NominalAmountAtomic, long BlockHeight, string BlockHash, byte OwnershipWitness = 0, byte AmountWitness = 0)
{
    public NewBinding Binding(string owner) => new(OutputIndex, OwnerSignature.Hex(KeyImage, 32), OwnerSignature.Hex(owner, 32),
        ulong.Parse(NominalAmountAtomic, System.Globalization.CultureInfo.InvariantCulture), OwnershipWitness, AmountWitness);
}
public sealed record CustodyItem(string ItemId, string CollectionId, uint Serial, string Status, string OwnerKey, CustodyOutput Output)
{
    public ListingItem ProofItem() => new(OwnerSignature.Hex(CollectionId, 32), Serial, Output.Binding(OwnerKey), OwnerSignature.Hex(Output.PublicKey, 32));
}
public sealed record CustodyListing(string Id, string ItemId, string CollectionId, uint Serial, string Status, string Mode,
    string PriceAtomic, ushort PlatformFeeBps, ushort RoyaltyBps, string SellerOwnerKey, string SignerOwnerKey,
    CustodyAddress SellerPayout, CustodyAddress ReturnAddress, CustodyAddress ListingAddress,
    CustodyAddress RoyaltyPayout, CustodyAddress PlatformPayout, CustodyOutput Output, CustodyOutput PreviousOutput,
    bool IsUnlocked, string MarketplaceId, string MarketplaceConfigHash)
{
    public ListingState ProofListing() => new(new(OwnerSignature.Hex(CollectionId, 32), Serial, PreviousOutput.Binding(SellerOwnerKey),
        OwnerSignature.Hex(PreviousOutput.PublicKey, 32)), new(ulong.Parse(PriceAtomic, System.Globalization.CultureInfo.InvariantCulture),
        SellerPayout.Bytes(), ReturnAddress.Bytes(), ListingAddress.Bytes()), Output.Binding(SignerOwnerKey),
        OwnerSignature.Hex(Output.PublicKey, 32), OwnerSignature.Hex(Id, 32));
    public SecondaryFeePolicy Fees() => new(RoyaltyBps, RoyaltyPayout.Bytes(), PlatformFeeBps);
}
public sealed record CustodyMarketplace(string Id, string ConfigHash, string SecondaryPolicy);
public sealed record CustodyContext(CustodyItem? Item, CustodyListing? Listing, CustodyMarketplace Marketplace, CustodyTip Tip);

public sealed record CustodyOpen(string Operation, string Reference, string ConfigHash, string OwnerKey,
    string EncryptionKey, string Nonce, long ExpiresAt, string Signature);
public sealed record CustodyHandshake(string SessionId, long ExpiresAt, string ServiceOwnerKey,
    string EncryptionKey, string ContextHash, string Signature);
public sealed record CustodyEnvelope(long Sequence, string Ciphertext);

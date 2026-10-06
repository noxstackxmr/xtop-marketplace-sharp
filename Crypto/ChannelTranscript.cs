using System.Security.Cryptography;
using System.Text;
using MarketplaceCore.Models;
using MarketplaceCore.Options;

namespace MarketplaceCore.Crypto;

public static class ChannelTranscript
{
    public static string Authentication(MarketplaceOptions options, string owner, string nonce, long expiresAt)
        => Digest("xtop/relay/auth/1", options.NetworkId, options.Id, options.PublicOrigin,
            owner, nonce, expiresAt);

    public static string Offer(ChannelOffer offer)
        => Digest("xtop/relay/offer/1", offer.NetworkId, offer.MarketplaceId, offer.Origin,
            offer.ChannelId, offer.ListingId, offer.MarketplaceConfigHash, offer.BuyerOwnerKey,
            offer.SellerOwnerKey, offer.BuyerEncryptionKey, offer.ExpiresAt);

    public static string Acceptance(ChannelOffer offer, string sellerEncryptionKey)
        => Digest("xtop/relay/accept/1", offer.OfferHash, offer.BuyerSignature!, sellerEncryptionKey);

    private static string Digest(params object[] fields)
    {
        using var stream = new MemoryStream();
        using var writer = new BinaryWriter(stream, Encoding.UTF8, true);
        foreach (var field in fields)
        {
            switch (field)
            {
                case byte number: writer.Write(number); break;
                case long number: writer.Write(number); break;
                case string text:
                    var bytes = Encoding.UTF8.GetBytes(text);
                    writer.Write((uint)bytes.Length);
                    writer.Write(bytes);
                    break;
                default: throw new InvalidOperationException("unsupported transcript field");
            }
        }
        return Convert.ToHexStringLower(SHA256.HashData(stream.ToArray()));
    }
}

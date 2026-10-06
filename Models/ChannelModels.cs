namespace MarketplaceCore.Models;

public sealed record AuthChallenge(string OwnerKey, string Nonce, long ExpiresAt, byte NetworkId,
    string MarketplaceId, string Origin, string MessageHash);

public sealed record ChannelOffer(string ChannelId, string ListingId, string MarketplaceConfigHash,
    byte NetworkId, string MarketplaceId, string Origin, string BuyerOwnerKey, string SellerOwnerKey,
    string BuyerEncryptionKey, long ExpiresAt, string OfferHash, string? BuyerSignature = null);

public sealed record ChannelAcceptance(ChannelOffer Offer, string SellerEncryptionKey,
    string SellerSignature, string HandshakeHash);

public sealed record EncryptedMessage(string ChannelId, string Sender, long Sequence, byte[] Ciphertext);

public sealed record ChannelClosed(string ChannelId, string Reason);

public sealed record Availability(string ListingId, string? SellerOwnerKey, bool SellerOnline,
    bool CanRequestChannel, string? Reason);

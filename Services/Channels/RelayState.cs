using System.Security.Cryptography;
using MarketplaceCore.Crypto;
using MarketplaceCore.Models;
using MarketplaceCore.Options;
using MarketplaceCore.Services.Indexer;
using Microsoft.Extensions.Options;

namespace MarketplaceCore.Services.Channels;

public sealed class RelayState(IOptions<MarketplaceOptions> marketplace, IOptions<ChannelOptions> settings, TimeProvider clock)
{
    private readonly object gate = new();
    private readonly Dictionary<string, Connection> connections = [];
    private readonly Dictionary<string, Channel> channels = [];
    private MarketplaceOptions Marketplace => marketplace.Value;
    private ChannelOptions Settings => settings.Value;
    private long Now => clock.GetUtcNow().ToUnixTimeSeconds();

    public void Connect(string connectionId, string ip, Action abort)
    {
        lock (gate)
        {
            if (connections.Count >= Settings.MaximumConnections ||
                connections.Values.Count(c => c.Ip == ip) >= Settings.MaximumConnectionsPerIp)
                throw new RelayException("connection_limit");
            connections.Add(connectionId, new Connection(ip, abort, Now));
        }
    }

    public void CheckRate(string connectionId)
    {
        lock (gate)
        {
            var connection = GetConnection(connectionId);
            if (Now - connection.WindowStarted >= 10)
            {
                connection.WindowStarted = Now;
                connection.Requests = 0;
            }
            if (++connection.Requests > 40) throw new RelayException("rate_limit");
        }
    }

    public AuthChallenge Challenge(string connectionId, string ownerKey)
    {
        if (!OwnerSignature.IsOwner(ownerKey)) throw new RelayException("invalid_owner_key");
        lock (gate)
        {
            var connection = GetConnection(connectionId);
            if (connection.Owner != null) throw new RelayException("already_authenticated");
            if (connection.Challenge != null)
            {
                if (connection.Challenge.OwnerKey != ownerKey) throw new RelayException("challenge_already_issued");
                return connection.Challenge;
            }
            var nonce = RandomHex();
            var expires = connection.CreatedAt + 120;
            return connection.Challenge = new(ownerKey, nonce, expires, Marketplace.NetworkId,
                Marketplace.Id, Marketplace.PublicOrigin,
                ChannelTranscript.Authentication(Marketplace, ownerKey, nonce, expires));
        }
    }

    public void Authenticate(string connectionId, string signature)
    {
        lock (gate)
        {
            var connection = GetConnection(connectionId);
            var challenge = connection.Challenge;
            if (connection.Owner != null || challenge == null || Now >= challenge.ExpiresAt || ++connection.Attempts > 3)
                throw new RelayException("authentication_failed");
            if (!OwnerSignature.Verify(challenge.MessageHash, challenge.OwnerKey, signature))
                throw new RelayException("authentication_failed");
            if (connections.Values.Count(c => c.Owner == challenge.OwnerKey) >= Settings.MaximumConnectionsPerOwner)
                throw new RelayException("owner_connection_limit");
            connection.Owner = challenge.OwnerKey;
            connection.Challenge = null;
            connection.LastHeartbeat = Now;
        }
    }

    public string Owner(string connectionId)
    {
        lock (gate) return Authenticated(connectionId).Owner!;
    }

    public long Heartbeat(string connectionId)
    {
        lock (gate)
        {
            var connection = Authenticated(connectionId);
            return connection.LastHeartbeat = Now;
        }
    }

    public void SetReady(string connectionId, bool ready)
    {
        lock (gate)
        {
            var connection = Authenticated(connectionId);
            connection.LastHeartbeat = Now;
            connection.Ready = ready;
        }
    }

    public bool IsOnline(string owner)
    {
        lock (gate) return SellerConnection(owner) != null;
    }

    public string? ListingUnavailable(ListingState? listing)
    {
        if (listing == null) return "listing_not_found";
        if (listing.MarketplaceId != Marketplace.Id) return "different_marketplace";
        if (listing.Mode != "client") return "unsupported_mode";
        if (listing.SignerOwnerKey != listing.SellerOwnerKey) return "invalid_listing_owner";
        if (listing.Status != "active") return "listing_inactive";
        if (!listing.IsUnlocked) return "listing_locked";
        return null;
    }

    public ChannelOffer Prepare(string connectionId, ListingState listing, string encryptionKey)
    {
        OwnerSignature.RequireEncryptionKey(encryptionKey);
        if (ListingUnavailable(listing) is { } reason) throw new RelayException(reason);
        lock (gate)
        {
            var buyer = Authenticated(connectionId);
            if (!Fresh(buyer)) throw new RelayException("heartbeat_required");
            var seller = SellerConnection(listing.SellerOwnerKey) ?? throw new RelayException("seller_offline");
            if (buyer.Owner == listing.SellerOwnerKey) throw new RelayException("same_participant");
            if (channels.Count >= Settings.MaximumChannels ||
                channels.Values.Count(c => c.Offer.BuyerOwnerKey == buyer.Owner) >= Settings.MaximumOpenChannelsPerBuyer)
                throw new RelayException("channel_limit");
            var offer = new ChannelOffer(RandomHex(), listing.Id, listing.MarketplaceConfigHash,
                Marketplace.NetworkId, Marketplace.Id, Marketplace.PublicOrigin, buyer.Owner!, listing.SellerOwnerKey,
                encryptionKey, Now + Settings.LifetimeMinutes * 60, "");
            offer = offer with { OfferHash = ChannelTranscript.Offer(offer) };
            channels.Add(offer.ChannelId, new Channel(offer, connectionId, seller, Now + Settings.AcceptTimeoutSeconds));
            return offer;
        }
    }

    public ChannelOffer GetOffer(string connectionId, string channelId)
    {
        lock (gate) return GetChannel(connectionId, channelId).Offer;
    }

    public Delivery<ChannelOffer> Request(string connectionId, string channelId, string signature, ListingState? listing)
    {
        lock (gate)
        {
            var channel = GetChannel(connectionId, channelId);
            if (connectionId != channel.Buyer || channel.Requested) throw new RelayException("invalid_channel_state");
            CheckListing(channel, listing);
            RequireSeller(channel);
            if (!OwnerSignature.Verify(channel.Offer.OfferHash, channel.Offer.BuyerOwnerKey, signature))
                throw new RelayException("invalid_signature");
            channel.Offer = channel.Offer with { BuyerSignature = signature };
            channel.Requested = true;
            return new(channel.Seller, channel.Offer);
        }
    }

    public Delivery<ChannelAcceptance> Accept(string connectionId, string channelId, string encryptionKey,
        string signature, ListingState? listing)
    {
        OwnerSignature.RequireEncryptionKey(encryptionKey);
        lock (gate)
        {
            var channel = GetChannel(connectionId, channelId);
            if (connectionId != channel.Seller || !channel.Requested || channel.Accepted)
                throw new RelayException("invalid_channel_state");
            CheckListing(channel, listing);
            RequireSeller(channel);
            var hash = ChannelTranscript.Acceptance(channel.Offer, encryptionKey);
            if (!OwnerSignature.Verify(hash, channel.Offer.SellerOwnerKey, signature))
                throw new RelayException("invalid_signature");
            channel.Accepted = true;
            return new(channel.Buyer, new(channel.Offer, encryptionKey, signature, hash));
        }
    }

    public Delivery<EncryptedMessage> Message(string connectionId, string channelId, long sequence, byte[] ciphertext)
    {
        if (ciphertext == null || ciphertext.Length < 16 || ciphertext.Length > Settings.MaximumMessageBytes)
            throw new RelayException("invalid_message_size");
        lock (gate)
        {
            var channel = GetChannel(connectionId, channelId);
            if (!channel.Accepted) throw new RelayException("channel_not_accepted");
            var buyer = connectionId == channel.Buyer;
            var previous = buyer ? channel.BuyerSequence : channel.SellerSequence;
            if (sequence != previous + 1) throw new RelayException("invalid_sequence");
            if (channel.BuyerSequence + channel.SellerSequence >= Settings.MaximumMessages)
                throw new RelayException("message_limit");
            if (buyer) channel.BuyerSequence = sequence;
            else channel.SellerSequence = sequence;
            return new(buyer ? channel.Seller : channel.Buyer,
                new(channelId, buyer ? "buyer" : "seller", sequence, ciphertext));
        }
    }

    public Delivery<ChannelClosed> Close(string connectionId, string channelId)
    {
        lock (gate)
        {
            Authenticated(connectionId);
            if (!channels.TryGetValue(channelId, out var channel) ||
                (connectionId != channel.Buyer && connectionId != channel.Seller))
                throw new RelayException("channel_not_found");
            channels.Remove(channelId);
            return new(connectionId == channel.Buyer ? channel.Seller : channel.Buyer, new(channelId, "closed"));
        }
    }

    public Delivery<ChannelClosed>[] Disconnect(string connectionId)
    {
        lock (gate)
        {
            connections.Remove(connectionId);
            return RemoveChannels(c => c.Buyer == connectionId || c.Seller == connectionId, "peer_disconnected");
        }
    }

    public (Action[] Aborts, Delivery<ChannelClosed>[] Notifications) Sweep()
    {
        lock (gate)
        {
            var dead = connections.Where(p => Now - p.Value.CreatedAt >= 28800 ||
                (p.Value.Owner == null ? Now - p.Value.CreatedAt >= 120 : !Fresh(p.Value))).ToArray();
            foreach (var entry in dead) connections.Remove(entry.Key);
            var notifications = RemoveChannels(c => !Usable(c), "channel_expired");
            return (dead.Select(p => p.Value.Abort).ToArray(), notifications);
        }
    }

    private Delivery<ChannelClosed>[] RemoveChannels(Func<Channel, bool> predicate, string reason)
    {
        var removed = channels.Where(p => predicate(p.Value)).ToArray();
        List<Delivery<ChannelClosed>> notifications = [];
        foreach (var (id, channel) in removed)
        {
            channels.Remove(id);
            if (connections.ContainsKey(channel.Buyer)) notifications.Add(new(channel.Buyer, new(id, reason)));
            if (channel.Requested && connections.ContainsKey(channel.Seller)) notifications.Add(new(channel.Seller, new(id, reason)));
        }
        return notifications.ToArray();
    }

    private Connection GetConnection(string id)
        => connections.TryGetValue(id, out var connection) ? connection : throw new RelayException("connection_expired");

    private Connection Authenticated(string id)
    {
        var connection = GetConnection(id);
        if (connection.Owner == null) throw new RelayException("authentication_required");
        if (!Fresh(connection) || Now - connection.CreatedAt >= 28800) throw new RelayException("connection_expired");
        return connection;
    }

    private bool Fresh(Connection connection) => Now - connection.LastHeartbeat < Settings.PresenceTimeoutSeconds;

    private string? SellerConnection(string owner)
        => connections.FirstOrDefault(p => p.Value.Owner == owner && p.Value.Ready && Fresh(p.Value)).Key;

    private void RequireSeller(Channel channel)
    {
        if (!connections.TryGetValue(channel.Seller, out var seller) || !seller.Ready || !Fresh(seller))
            throw new RelayException("seller_offline");
    }

    private bool Usable(Channel channel)
        => Now < channel.Offer.ExpiresAt && (channel.Accepted || Now < channel.AcceptBy) &&
            connections.TryGetValue(channel.Buyer, out var buyer) && Fresh(buyer) &&
            connections.TryGetValue(channel.Seller, out var seller) && Fresh(seller);

    private Channel GetChannel(string connectionId, string channelId)
    {
        Authenticated(connectionId);
        if (!channels.TryGetValue(channelId, out var channel) ||
            (channel.Buyer != connectionId && channel.Seller != connectionId))
            throw new RelayException("channel_not_found");
        if (!Usable(channel)) throw new RelayException("channel_expired");
        return channel;
    }

    private void CheckListing(Channel channel, ListingState? listing)
    {
        if (ListingUnavailable(listing) is { } reason) throw new RelayException(reason);
        if (listing!.Id != channel.Offer.ListingId || listing.SellerOwnerKey != channel.Offer.SellerOwnerKey ||
            listing.MarketplaceConfigHash != channel.Offer.MarketplaceConfigHash)
            throw new RelayException("listing_changed");
    }

    private static string RandomHex() => Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(32));

    private sealed class Connection(string ip, Action abort, long createdAt)
    {
        public string Ip { get; } = ip;
        public Action Abort { get; } = abort;
        public long CreatedAt { get; } = createdAt;
        public string? Owner { get; set; }
        public AuthChallenge? Challenge { get; set; }
        public int Attempts { get; set; }
        public bool Ready { get; set; }
        public long LastHeartbeat { get; set; } = createdAt;
        public long WindowStarted { get; set; } = createdAt;
        public int Requests { get; set; }
    }

    private sealed class Channel(ChannelOffer offer, string buyer, string seller, long acceptBy)
    {
        public ChannelOffer Offer { get; set; } = offer;
        public string Buyer { get; } = buyer;
        public string Seller { get; } = seller;
        public long AcceptBy { get; } = acceptBy;
        public bool Requested { get; set; }
        public bool Accepted { get; set; }
        public long BuyerSequence { get; set; }
        public long SellerSequence { get; set; }
    }
}

public sealed record Delivery<T>(string ConnectionId, T Payload);

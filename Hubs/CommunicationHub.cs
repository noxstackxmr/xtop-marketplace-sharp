using MarketplaceCore.Models;
using MarketplaceCore.Services.Channels;
using MarketplaceCore.Services.Indexer;
using Microsoft.AspNetCore.SignalR;

namespace MarketplaceCore.Hubs;

public sealed class CommunicationHub(RelayState state, IListingDirectory listings) : Hub
{
    public override Task OnConnectedAsync()
    {
        try
        {
            var context = Context;
            state.Connect(context.ConnectionId, context.GetHttpContext()?.Connection.RemoteIpAddress?.ToString() ?? "unknown",
                context.Abort);
        }
        catch (RelayException) { Context.Abort(); }
        return base.OnConnectedAsync();
    }

    public override async Task OnDisconnectedAsync(Exception? exception)
    {
        foreach (var delivery in state.Disconnect(Context.ConnectionId))
            await SendAsync(delivery, "ChannelClosed");
        await base.OnDisconnectedAsync(exception);
    }

    public AuthChallenge GetChallenge(string ownerKey) => state.Challenge(Context.ConnectionId, ownerKey);
    public void Authenticate(string signature) => state.Authenticate(Context.ConnectionId, signature);
    public void SetReady(bool ready) => state.SetReady(Context.ConnectionId, ready);
    public long Heartbeat() => state.Heartbeat(Context.ConnectionId);

    public async Task<ChannelOffer> PrepareChannel(string listingId, string buyerEncryptionKey)
    {
        state.Owner(Context.ConnectionId);
        var listing = await listings.GetAsync(listingId, Context.ConnectionAborted);
        if (listing == null) throw new RelayException("listing_not_found");
        return state.Prepare(Context.ConnectionId, listing, buyerEncryptionKey);
    }

    public async Task RequestChannel(string channelId, string buyerSignature)
    {
        var offer = state.GetOffer(Context.ConnectionId, channelId);
        var listing = await listings.GetAsync(offer.ListingId, Context.ConnectionAborted);
        await SendAsync(state.Request(Context.ConnectionId, channelId, buyerSignature, listing), "ChannelRequested");
    }

    public async Task<ChannelAcceptance> AcceptChannel(string channelId, string sellerEncryptionKey, string sellerSignature)
    {
        var offer = state.GetOffer(Context.ConnectionId, channelId);
        var listing = await listings.GetAsync(offer.ListingId, Context.ConnectionAborted);
        var delivery = state.Accept(Context.ConnectionId, channelId, sellerEncryptionKey, sellerSignature, listing);
        await SendAsync(delivery, "ChannelAccepted");
        return delivery.Payload;
    }

    public async Task SendMessage(string channelId, long sequence, byte[] ciphertext)
        => await SendAsync(state.Message(Context.ConnectionId, channelId, sequence, ciphertext), "MessageReceived");

    public async Task CloseChannel(string channelId)
        => await SendAsync(state.Close(Context.ConnectionId, channelId), "ChannelClosed");

    private async Task SendAsync<T>(Delivery<T> delivery, string method)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        try { await Clients.Client(delivery.ConnectionId).SendAsync(method, delivery.Payload, timeout.Token); }
        catch (OperationCanceledException)
        {
            Context.Abort();
            throw new HubException("delivery_failed");
        }
    }
}

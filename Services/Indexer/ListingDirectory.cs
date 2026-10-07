using System.Net;
using System.Text.Json;
using MarketplaceCore.Crypto;
using MarketplaceCore.Options;
using Microsoft.Extensions.Options;

namespace MarketplaceCore.Services.Indexer;

public sealed record ListingState(string Id, string Status, string Mode, bool IsUnlocked,
    string SellerOwnerKey, string SignerOwnerKey, string MarketplaceId, string MarketplaceConfigHash);

public interface IListingDirectory
{
    Task<ListingState?> GetAsync(string listingId, CancellationToken cancellationToken);
}

public sealed class ListingDirectory(HttpClient http, IOptions<MarketplaceOptions> options) : IListingDirectory
{
    public async Task<ListingState?> GetAsync(string listingId, CancellationToken cancellationToken)
    {
        OwnerSignature.Hex(listingId, 32);
        for (var attempt = 0; ; attempt++)
        {
            try { return await ReadAsync(listingId, cancellationToken); }
            catch (IndexerSyncException) when (attempt < 4) { await Task.Delay(750, cancellationToken); }
        }
    }

    private async Task<ListingState?> ReadAsync(string listingId, CancellationToken cancellationToken)
    {
        using var response = await http.GetAsync($"api/listings/{listingId}", cancellationToken);
        if (response.StatusCode == HttpStatusCode.NotFound) return null;
        response.EnsureSuccessStatusCode();
        var result = await response.Content.ReadFromJsonAsync<ListingEnvelope>(cancellationToken)
            ?? throw new InvalidDataException("invalid indexer response");
        if (result.NetworkId != options.Value.NetworkId || result.Network != options.Value.Network ||
            result.Listing == null || result.Listing.Id != listingId)
            throw new InvalidDataException("indexer state unavailable");
        if (result.ScannedTip == null || result.SpendCheckedTip != result.ScannedTip)
            throw new IndexerSyncException();
        var listing = result.Listing;
        OwnerSignature.Hex(listing.MarketplaceId, 32);
        OwnerSignature.Hex(listing.MarketplaceConfigHash, 32);
        if (!OwnerSignature.IsOwner(listing.SellerOwnerKey) || !OwnerSignature.IsOwner(listing.SignerOwnerKey))
            throw new InvalidDataException("invalid listing owner");
        return listing;
    }

    private sealed record Tip(long Height, string Hash);
    private sealed class IndexerSyncException() : InvalidOperationException("indexer state unavailable");
    private sealed record ListingEnvelope(string Network, byte NetworkId, Tip? ScannedTip,
        Tip? SpendCheckedTip, ListingState? Listing);
}

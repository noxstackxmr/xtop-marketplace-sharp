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
    Task<ListingState?> SellerAsync(string ownerKey, CancellationToken cancellationToken);
}

public sealed class ListingDirectory(HttpClient http, IOptions<MarketplaceOptions> options) : IListingDirectory
{
    public async Task<ListingState?> SellerAsync(string ownerKey, CancellationToken cancellationToken)
    {
        if (!OwnerSignature.IsOwner(ownerKey)) throw new FormatException("invalid_owner_key");
        using var response = await http.GetAsync($"api/listings?sellerOwnerKey={ownerKey}&marketplaceId={options.Value.Id}&mode=client&pageSize=1", cancellationToken);
        response.EnsureSuccessStatusCode();
        var result = await response.Content.ReadFromJsonAsync<SellerEnvelope>(cancellationToken) ?? throw new InvalidDataException("invalid indexer response");
        if (result.NetworkId != options.Value.NetworkId || result.Network != options.Value.Network || result.ScannedTip == null || result.ScannedTip != result.SpendCheckedTip)
            throw new IndexerSyncException();
        if (result.Listings is not { Length: <= 1 }) throw new InvalidDataException("invalid seller listings");
        var listing = result.Listings.FirstOrDefault();
        if (listing != null && (listing.SellerOwnerKey != ownerKey || listing.SignerOwnerKey != ownerKey || listing.MarketplaceId != options.Value.Id || listing.Mode != "client" || listing.Status != "active"))
            throw new InvalidDataException("invalid seller listing");
        return listing;
    }
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
    private sealed record SellerEnvelope(string Network, byte NetworkId, Tip? ScannedTip, Tip? SpendCheckedTip, ListingState[] Listings);
}

using System.Net.Http.Json;
using MarketplaceCore.Crypto;
using MarketplaceCore.Models;
using MarketplaceCore.Options;
using Microsoft.Extensions.Options;

namespace MarketplaceCore.Services.Indexer;

public interface ICustodyDirectory
{
    Task<CustodyContext> GetAsync(string operation, string reference, string configHash, CancellationToken cancellationToken);
}

public sealed class CustodyDirectory(HttpClient http, IOptions<MarketplaceOptions> options) : ICustodyDirectory
{
    private sealed record Envelope(string Network, byte NetworkId, CustodyTip? ScannedTip, CustodyTip? SpendCheckedTip,
        CustodyItem? Item, CustodyListing? Listing, CustodyMarketplace? Marketplace);

    public async Task<CustodyContext> GetAsync(string operation, string reference, string configHash, CancellationToken cancellationToken)
    {
        OwnerSignature.Hex(reference, 32); OwnerSignature.Hex(configHash, 32);
        if (operation is not ("list" or "cancel" or "purchase")) throw new FormatException("invalid operation");
        var item = await ReadAsync($"api/{(operation == "list" ? "items" : "listings")}/{reference}", cancellationToken);
        if (item.ScannedTip == null || item.SpendCheckedTip != item.ScannedTip) throw new InvalidOperationException("indexer_syncing");
        var market = await ReadAsync($"api/marketplaces/{options.Value.Id}?configHash={configHash}", cancellationToken);
        if (market.ScannedTip != item.ScannedTip) throw new InvalidOperationException("indexer_changed");
        if (market.Marketplace == null || market.Marketplace.Id != options.Value.Id || market.Marketplace.ConfigHash != configHash ||
            (operation == "list" ? item.Item?.ItemId : item.Listing?.Id) != reference) throw new InvalidDataException("indexer_identity_mismatch");
        return new(item.Item, item.Listing, market.Marketplace, item.ScannedTip);
    }

    private async Task<Envelope> ReadAsync(string path, CancellationToken cancellationToken)
    {
        var data = await http.GetFromJsonAsync<Envelope>(path, cancellationToken) ?? throw new InvalidDataException("invalid_indexer_response");
        if (data.Network != options.Value.Network || data.NetworkId != options.Value.NetworkId) throw new InvalidDataException("wrong_network");
        return data;
    }
}

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
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(TimeSpan.FromSeconds(35));
        try { return await ReadContextAsync(operation, reference, configHash, deadline.Token); }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested && deadline.IsCancellationRequested)
        { throw new InvalidOperationException("indexer_syncing"); }
    }

    private async Task<CustodyContext> ReadContextAsync(string operation, string reference, string configHash, CancellationToken cancellationToken)
    {
        OwnerSignature.Hex(reference, 32); OwnerSignature.Hex(configHash, 32);
        if (operation is not ("list" or "cancel" or "purchase")) throw new FormatException("invalid operation");
        for (var attempt = 0; attempt <= 10; attempt++)
        {
            var itemRead = ReadAsync($"api/{(operation == "list" ? "items" : "listings")}/{reference}", cancellationToken);
            var marketRead = ReadAsync($"api/marketplaces/{options.Value.Id}?configHash={configHash}", cancellationToken);
            await Task.WhenAll(itemRead, marketRead);
            var item = await itemRead;
            var market = await marketRead;
            if (market.Marketplace == null || market.Marketplace.Id != options.Value.Id || market.Marketplace.ConfigHash != configHash ||
                (operation == "list" ? item.Item?.ItemId : item.Listing?.Id) != reference) throw new InvalidDataException("indexer_identity_mismatch");
            if (item.ScannedTip != null && item.SpendCheckedTip == item.ScannedTip && market.ScannedTip == item.ScannedTip)
                return new(item.Item, item.Listing, market.Marketplace, item.ScannedTip);
            if (attempt < 10) await Task.Delay(3000, cancellationToken);
        }
        throw new InvalidOperationException("indexer_syncing");
    }

    private async Task<Envelope> ReadAsync(string path, CancellationToken cancellationToken)
    {
        var data = await http.GetFromJsonAsync<Envelope>(path, cancellationToken) ?? throw new InvalidDataException("invalid_indexer_response");
        if (data.Network != options.Value.Network || data.NetworkId != options.Value.NetworkId) throw new InvalidDataException("wrong_network");
        return data;
    }
}

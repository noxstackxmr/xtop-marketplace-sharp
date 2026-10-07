using System.Net.Http.Json;
using System.Text.Json;
using System.Text;
using MarketplaceCore.Models;
using MarketplaceCore.Options;
using Microsoft.Extensions.Options;

namespace MarketplaceCore.Services.Custody;

public interface ICustodyNode
{
    Task CheckAsync(CustodyTip tip, CustodyOutput output, bool unlocked, CancellationToken cancellationToken);
}

public sealed class CustodyNode(HttpClient http, IOptions<MarketplaceOptions> market, IOptions<CustodyOptions> custody) : ICustodyNode
{
    public async Task CheckAsync(CustodyTip tip, CustodyOutput output, bool unlocked, CancellationToken cancellationToken)
    {
        var info = await Post("get_info", new { }, cancellationToken);
        if (info.GetProperty("nettype").GetString() != market.Value.Network || info.GetProperty("height").GetInt64() - 1 - tip.Height is < 0 or > 2)
            throw new InvalidOperationException("node_or_indexer_not_ready");
        var genesis = await Header(0, cancellationToken);
        if (genesis.GetProperty("hash").GetString() != custody.Value.GenesisHash) throw new InvalidOperationException("wrong_genesis");
        var head = await Header(tip.Height, cancellationToken);
        var source = await Header(output.BlockHeight, cancellationToken);
        if (head.GetProperty("hash").GetString() != tip.Hash || source.GetProperty("hash").GetString() != output.BlockHash)
            throw new InvalidOperationException("chain_changed");
        if (unlocked && tip.Height < checked(output.BlockHeight + 10)) throw new InvalidOperationException("output_locked");
        var spent = await Post("is_key_image_spent", new { key_images = new[] { output.KeyImage } }, cancellationToken);
        if (spent.GetProperty("spent_status").GetArrayLength() != 1 || spent.GetProperty("spent_status")[0].GetInt32() != 0)
            throw new InvalidOperationException("output_spent_or_pending");
    }

    private async Task<JsonElement> Header(long height, CancellationToken cancellationToken)
    {
        var result = await Post("json_rpc", new { jsonrpc = "2.0", id = "custody", method = "get_block_header_by_height", @params = new { height } }, cancellationToken);
        return result.GetProperty("result").GetProperty("block_header").Clone();
    }
    private async Task<JsonElement> Post(string path, object body, CancellationToken cancellationToken)
    {
        using var content = new StringContent(JsonSerializer.Serialize(body), Encoding.UTF8, "application/json");
        using var response = await http.PostAsync(path, content, cancellationToken);
        response.EnsureSuccessStatusCode();
        var data = await response.Content.ReadFromJsonAsync<JsonElement>(cancellationToken);
        if (data.TryGetProperty("error", out _) || (data.TryGetProperty("status", out var status) && status.GetString() != "OK"))
            throw new InvalidDataException("node_unavailable");
        return data;
    }
}

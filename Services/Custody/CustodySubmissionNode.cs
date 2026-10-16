using System.Net.Http.Json;
using System.Text.Json;
using System.Text;
using MarketplaceCore.Crypto;
using MarketplaceCore.Monero;
using MarketplaceCore.Options;
using Microsoft.Extensions.Options;

namespace MarketplaceCore.Services.Custody;

public interface ICustodySubmissionNode
{
    Task<string> ReconcileAsync(CustodyReceipt receipt, CancellationToken token);
}

public sealed class CustodySubmissionNode(HttpClient http, IOptions<CustodyOptions> custody,
    IOptions<MarketplaceOptions> marketplace) : ICustodySubmissionNode
{
    public async Task<string> ReconcileAsync(CustodyReceipt receipt, CancellationToken token)
    {
        var info = await Post("get_info", new { }, token);
        if (info.GetProperty("nettype").GetString() != marketplace.Value.Network ||
            (info.TryGetProperty("synchronized", out var sync) && !sync.GetBoolean()) ||
            (info.TryGetProperty("busy_syncing", out var busy) && busy.GetBoolean())) throw new InvalidOperationException("node_not_ready");
        var genesis = await Post("json_rpc", new { jsonrpc = "2.0", id = "custody", method = "get_block_header_by_height", @params = new { height = 0 } }, token);
        if (genesis.GetProperty("result").GetProperty("block_header").GetProperty("hash").GetString() != custody.Value.GenesisHash)
            throw new InvalidOperationException("wrong_genesis");
        var txid = receipt.Transaction.GetProperty("txid").GetString()!; OwnerSignature.Hex(txid, 32);
        var lookup = await Post("get_transactions", new { txs_hashes = new[] { txid }, decode_as_json = false }, token);
        var rows = lookup.TryGetProperty("txs", out var txs) ? txs.EnumerateArray().ToArray() : [];
        if (rows.Length > 1 || rows.Any(t => t.GetProperty("tx_hash").GetString() != txid)) throw new InvalidDataException("unexpected_transaction");
        if (rows.Length == 1) return rows[0].GetProperty("in_pool").GetBoolean() ? "submitted" : "confirmed";
        if (!lookup.TryGetProperty("missed_tx", out var missed) || missed.GetArrayLength() != 1 || missed[0].GetString() != txid)
            throw new InvalidDataException("incomplete_transaction_lookup");
        var blob = receipt.Transaction.GetProperty("blob").GetString()!;
        var transaction = MoneroProofTransaction.Parse(Convert.FromHexString(blob));
        var images = transaction.InputKeyImages.Select(Convert.ToHexStringLower).ToArray();
        if (images.Length != 2 || images.Distinct().Count() != images.Length || !images.Contains(receipt.KeyImage))
            throw new InvalidDataException("invalid_saved_inputs");
        var spent = await Post("is_key_image_spent", new { key_images = images }, token);
        var states = spent.GetProperty("spent_status").EnumerateArray().Select(s => s.GetInt32()).ToArray();
        if (states.Length != images.Length || states.Any(s => s is < 0 or > 2)) throw new InvalidDataException("invalid_spent_status");
        if (states.Any(s => s != 0)) return "conflict_pending";
        var sent = await Post("send_raw_transaction", new { tx_as_hex = blob, do_not_relay = false }, token);
        if (sent.TryGetProperty("not_relayed", out var notRelayed) && notRelayed.GetBoolean())
            throw new InvalidDataException("transaction_not_relayed");
        return "submitted";
    }
    private async Task<JsonElement> Post(string path, object body, CancellationToken token)
    {
        using var content = new StringContent(JsonSerializer.Serialize(body), Encoding.UTF8, "application/json");
        using var response = await http.PostAsync(path, content, token);
        response.EnsureSuccessStatusCode();
        var result = await response.Content.ReadFromJsonAsync<JsonElement>(token);
        if (result.TryGetProperty("error", out _) ||
            (result.TryGetProperty("untrusted", out var untrusted) && untrusted.GetBoolean()) ||
            (result.TryGetProperty("status", out var status) && status.GetString() != "OK")) throw new InvalidDataException("node_rejected_request");
        if (result.TryGetProperty("result", out var nested) &&
            ((nested.TryGetProperty("status", out var nestedStatus) && nestedStatus.GetString() != "OK") ||
             (nested.TryGetProperty("untrusted", out var nestedUntrusted) && nestedUntrusted.GetBoolean())))
            throw new InvalidDataException("node_rejected_request");
        return result;
    }
}

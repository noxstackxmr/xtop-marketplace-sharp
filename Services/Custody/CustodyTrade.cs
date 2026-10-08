using System.Globalization;
using System.Text.Json;
using MarketplaceCore.Crypto;
using MarketplaceCore.Models;
using MarketplaceCore.Monero;
using MarketplaceCore.Options;
using MarketplaceCore.Protocol.Marketplaces;
using MarketplaceCore.Protocol.Sales;
using MarketplaceCore.Services.Indexer;

namespace MarketplaceCore.Services.Custody;

public sealed class CustodyTrade(CustodyOpen request, CustodyContext initial, CustodyKeys keys, CustodyProofs proofs,
    ICustodyDirectory directory, ICustodyNode node, ICustodySignerFactory signers, CustodyJournal journal,
    MarketplaceOptions market, CustodyOptions options) : IDisposable
{
    private ICustodySigner? signer;
    private CustodyAddress? recipient;
    private CustodyAddress? change;
    private object[]? payments;
    private string stage = "new";
    private string? signatureHash;
    private readonly MarketplacePolicy policy = ReadPolicy(initial, request, keys, market);

    public static MarketplacePolicy ReadPolicy(CustodyContext context, CustodyOpen request, CustodyKeys keys, MarketplaceOptions market)
    {
        var policy = MarketplacePolicyReader.Read(OwnerSignature.Hex(context.Marketplace.SecondaryPolicy, MarketplacePolicyReader.SecondaryLength),
            market.NetworkId, OwnerSignature.Hex(request.ConfigHash, 32), true);
        if (Convert.ToHexStringLower(policy.Identity(market.NetworkId)) != market.Id || (policy.Modes & 1) == 0 ||
            !keys.Address.SequenceEqual(policy.CustodyAddress!)) throw new InvalidOperationException("custody_configuration_mismatch");
        if (request.Operation == "list")
        {
            if (context.Item == null || context.Item.OwnerKey != request.OwnerKey) throw new InvalidOperationException("not_item_owner");
        }
        else
        {
            var l = context.Listing ?? throw new InvalidDataException("missing_listing");
            if (l.Mode != "marketplace" || l.MarketplaceId != market.Id || l.MarketplaceConfigHash != request.ConfigHash ||
                l.SignerOwnerKey != Convert.ToHexStringLower(keys.Owner) || !l.ListingAddress.Bytes().SequenceEqual(keys.Address) ||
                l.PlatformFeeBps != policy.FeeBps || !l.PlatformPayout.Bytes().SequenceEqual(policy.FeeAddress))
                throw new InvalidOperationException("custody_listing_mismatch");
            if (request.Operation == "cancel" && l.SellerOwnerKey != request.OwnerKey) throw new InvalidOperationException("not_listing_seller");
        }
        return policy;
    }

    private async Task Fresh(CancellationToken cancellationToken)
    {
        var current = await directory.GetAsync(request.Operation, request.Reference, request.ConfigHash, cancellationToken);
        ReadPolicy(current, request, keys, market);
        if (JsonSerializer.Serialize(current.Item) != JsonSerializer.Serialize(initial.Item) ||
            JsonSerializer.Serialize(current.Listing) != JsonSerializer.Serialize(initial.Listing)) throw new InvalidOperationException("item_or_listing_changed");
        if (request.Operation == "list" ? current.Item!.Status != "sold" : current.Listing!.Status != "active" || !current.Listing.IsUnlocked)
            throw new InvalidOperationException("item_or_listing_unavailable");
        await node.CheckAsync(current.Tip, current.Item?.Output ?? current.Listing!.Output, true, cancellationToken);
    }

    public async Task<object> ProcessAsync(JsonElement packet, CancellationToken cancellationToken)
    {
        if (stage == "failed") throw new InvalidOperationException("trade_failed");
        var type = packet.GetProperty("type").GetString();
        if (type == "recover" && request.Operation != "list")
        {
            var records = journal.ReadAll(initial.Listing!.Output.KeyImage);
            var hash = packet.TryGetProperty("signatureHash", out var hashField) ? hashField.GetString() : null;
            if (hash != null) OwnerSignature.Hex(hash, 32);
            var receipt = records.LastOrDefault(r => r.OwnerKey == request.OwnerKey && r.Reference == request.Reference &&
                r.ConfigHash == request.ConfigHash && r.Operation == request.Operation && (hash == null || r.SignatureHash == hash));
            if (receipt == null) return new { type = "not-signed" };
            return new { type = "signed", transaction = receipt.Transaction };
        }
        await Fresh(cancellationToken);
        var collectionPolicy = policy.BuildPolicy(market.NetworkId);
        if (type == "listing" && request.Operation == "list" && stage == "new")
        {
            var tx = MoneroProofTransaction.Parse(Hex(packet, "unsignedBlob", 100000));
            var payout = Address(packet, "sellerPayout"); var returns = Address(packet, "returnAddress");
            var price = ulong.Parse(packet.GetProperty("priceAtomic").GetString()!, CultureInfo.InvariantCulture);
            var message = proofs.List(tx, collectionPolicy, policy, initial.Item!.ProofItem(),
                new(price, payout.Bytes(), returns.Bytes(), keys.Address));
            stage = "listed";
            return new { type = "listing-proof", message = Convert.ToHexStringLower(message), serviceOwnerKey = Convert.ToHexStringLower(keys.Owner) };
        }
        if (request.Operation == "list") throw new InvalidOperationException("unexpected_trade_step");
        var listing = initial.Listing!;
        if (request.Operation != "cancel" && journal.Read(listing.Output.KeyImage) != null) throw new InvalidOperationException("output_already_signed");
        if (type == "input" && stage == "new")
        {
            recipient = Address(packet, "recipient"); change = Address(packet, "change");
            if (request.Operation == "cancel" && recipient != listing.ReturnAddress) throw new InvalidOperationException("wrong_return_address");
            if (recipient.Bytes().SequenceEqual(keys.Address) || change.Bytes().SequenceEqual(keys.Address))
                throw new InvalidOperationException("unexpected_custody_recipient");
            payments = new[] { recipient.Payment(MarketplaceFormat.ItemAmount) }.Concat(request.Operation == "cancel" ? [] :
                SecondaryPurchaseProofs.Payments(collectionPolicy, listing.ProofListing().Terms, listing.Fees())
                    .Select(p => CustodyAddress.From(p.Address).Payment(p.Amount))).ToArray();
            signer = signers.Create();
            var input = await signer.CallAsync(new { command = "joint_input", role = "seller", rpc = options.RpcUrl,
                network = market.Network, spend_secret = keys.SpendSecret, view_secret = keys.ViewSecret,
                input_height = listing.Output.BlockHeight, input_txid = listing.Output.TransactionId, input_index = listing.Output.OutputIndex }, cancellationToken);
            if (input.GetProperty("key_image").GetString() != listing.Output.KeyImage ||
                input.GetProperty("input_key").GetString() != listing.Output.PublicKey ||
                input.GetProperty("amount").GetUInt64() != MarketplaceFormat.ItemAmount) throw new InvalidOperationException("wrong_custody_input");
            stage = "input";
            return new { type = "item-input", input };
        }
        if (type == "intent" && stage == "input")
        {
            var blob = Hex(packet, "unsignedBlob", 100000); var tx = MoneroProofTransaction.Parse(blob);
            var proposed = Hex(packet, "message", 1024);
            if (tx.Message.Length != proposed.Length) throw new FormatException("carrier_length_mismatch");
            var message = proofs.Authorize(tx, proposed, collectionPolicy, listing.ProofListing(), listing.Fees(), request.Operation, request.OwnerKey);
            await signer!.CallAsync(new { command = "joint_accept", package = packet.GetProperty("package"),
                rpc = options.RpcUrl, network = market.Network,
                unsigned_blob = Convert.ToHexStringLower(blob), payments, change = change!.Native() }, cancellationToken);
            var bound = await signer.CallAsync(new { command = "joint_bind", message = Convert.ToHexStringLower(message) }, cancellationToken);
            signatureHash = bound.GetProperty("signature_hash").GetString()!;
            stage = "bound";
            return new { type = "bound", message = Convert.ToHexStringLower(message), transaction = bound };
        }
        if (type == "sign" && stage == "bound")
        {
            await signer!.CallAsync(new { command = "joint_check_inputs", rpc = options.RpcUrl, network = market.Network }, cancellationToken);
            var prior = packet.GetProperty("contribution");
            var contribution = await signer!.CallAsync(new { command = "joint_sign", prior_contribution = prior }, cancellationToken);
            var final = await signer.CallAsync(new { command = "joint_assemble", contributions = new[] { prior, contribution } }, cancellationToken);
            var verified = await signer.CallAsync(new { command = "joint_verify", blob = final.GetProperty("blob").GetString() }, cancellationToken);
            if (!verified.GetProperty("valid").GetBoolean() || verified.GetProperty("verified_clsags").GetInt32() != 2 ||
                !verified.GetProperty("verified_balance").GetBoolean() || !verified.GetProperty("verified_bulletproof_plus").GetBoolean())
                throw new InvalidOperationException("native_verification_failed");
            var tx = MoneroProofTransaction.Parse(Hex(final, "blob", 100000));
            if (request.Operation == "cancel") ListingProofs.VerifyCancel(tx, collectionPolicy, listing.ProofListing());
            else SecondaryPurchaseProofs.Verify(tx, collectionPolicy, listing.ProofListing(), listing.Fees());
            journal.Save(new(request.Reference, request.ConfigHash, request.Operation, request.OwnerKey, listing.Output.KeyImage, signatureHash!, final));
            stage = "signed"; signer.Dispose(); signer = null;
            return new { type = "signed", transaction = final };
        }
        throw new InvalidOperationException("unexpected_trade_step");
    }
    private static CustodyAddress Address(JsonElement packet, string name)
    {
        var address = packet.GetProperty(name).Deserialize<CustodyAddress>(new JsonSerializerOptions(JsonSerializerDefaults.Web)) ?? throw new FormatException("invalid_address");
        address.Bytes(); return address;
    }
    private static byte[] Hex(JsonElement packet, string field, int maximum)
    {
        var value = packet.GetProperty(field).GetString()!;
        if (value.Length == 0 || value.Length > maximum * 2 || value.Length % 2 != 0) throw new FormatException("invalid_blob_length");
        return OwnerSignature.Hex(value, value.Length / 2);
    }
    public void Dispose() { signer?.Dispose(); signer = null; stage = "failed"; }
}

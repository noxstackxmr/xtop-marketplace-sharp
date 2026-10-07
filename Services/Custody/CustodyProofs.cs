using System.Security.Cryptography;
using MarketplaceCore.Crypto;
using MarketplaceCore.Models;
using MarketplaceCore.Monero;
using MarketplaceCore.Protocol.Collections;
using MarketplaceCore.Protocol.Marketplaces;
using MarketplaceCore.Protocol.Messages;
using MarketplaceCore.Protocol.Sales;

namespace MarketplaceCore.Services.Custody;

public sealed class CustodyProofs(CustodyKeys keys)
{
    public static byte[] Encode(XtopMessage message, byte network) => PrimarySaleEncoding.Write(w =>
    {
        w.Write("XTOP"u8); w.Write(message.Version); w.Write(network); w.Write(message.ConfigHash);
        w.Write(message.Operation); w.Write((uint)message.Payload.Length); w.Write(message.Payload); w.Write((byte)message.Witnesses.Length);
        foreach (var witness in message.Witnesses) { w.Write(witness.Kind); w.Write(witness.Profile); w.Write((ushort)witness.Proof.Length); w.Write(witness.Proof); }
    });

    public byte[] List(MoneroProofTransaction tx, CollectionCreatePolicy policy, MarketplacePolicy market,
        ListingItem previous, ListedTerms terms)
    {
        if (terms.Price == 0 || terms.Mode != ListingModes.Marketplace || !terms.ServiceAddress.SequenceEqual(keys.Address) ||
            tx.InputKeyImages.Length != 2 || tx.Outputs.Length != 2 || tx.InputKeyImages.Count(i => i.SequenceEqual(previous.Binding.KeyImage)) != 1 ||
            tx.InputKeyImages[0].SequenceEqual(tx.InputKeyImages[1])) throw new FormatException("invalid_listing_transaction");
        MarketplaceFormat.Address(terms.SellerPayout); MarketplaceFormat.Address(terms.ReturnAddress);
        var derivation = keys.Derivation(tx.TransactionKey);
        var matches = Enumerable.Range(0, tx.Outputs.Length).Where(i =>
            MoneroProofCrypto.OutputKey(derivation, (ulong)i, keys.Address[..32]).SequenceEqual(tx.Outputs[i].Key)).ToArray();
        if (matches.Length != 1) throw new FormatException("expected_one_custody_output");
        var index = checked((byte)matches[0]);
        var output = tx.Outputs[index];
        var (amount, mask) = MoneroProofCrypto.DecodeAmount(derivation, index, output.EncryptedAmount);
        if (amount != policy.NftAmount || !MoneroProofCrypto.Commitment(mask, amount).SequenceEqual(output.Commitment))
            throw new FormatException("custody_nominal_mismatch");
        var secret = keys.OutputSecret(derivation, index);
        try
        {
            var image = MoneroProofCrypto.Multiply(MoneroProofCrypto.HashToPoint(output.Key), secret);
            if (tx.InputKeyImages.Any(i => i.SequenceEqual(image))) throw new FormatException("reused_output_image");
            var next = new NewBinding(index, image, keys.Owner, amount, 0, 0);
            var message = new XtopMessage(15, policy.ConfigHash, ListingProofs.ListOperation,
                [.. ListingProofs.ListPayload(previous, terms, next), .. market.Bytes], [new(7, ListingProofs.ListProfile, new byte[320])]);
            var encoded = Encode(message, policy.Network);
            if (tx.Message.Length != encoded.Length) throw new FormatException("listing_carrier_mismatch");
            var context = ListingProofs.Context(tx, message, policy, previous, null);
            var proof = message.Witnesses[0].Proof;
            CustodyKeys.Dleq(context, output.Key, MoneroProofCrypto.HashToPoint(output.Key), image, secret).CopyTo(proof, 0);
            keys.Sign(context).CopyTo(proof, 64); mask.CopyTo(proof, 128);
            return Encode(message, policy.Network);
        }
        finally { CryptographicOperations.ZeroMemory(secret); }
    }

    public byte[] Authorize(MoneroProofTransaction tx, byte[] bytes, CollectionCreatePolicy policy,
        Protocol.Sales.ListingState listing, SecondaryFeePolicy fees, string operation, string nextOwner)
    {
        var message = XtopMessageReader.ReadMessage(bytes, policy.Network);
        var payload = ListingProofs.ReadCancel(message);
        if (!payload.Successor.OwnerKey.SequenceEqual(OwnerSignature.Hex(nextOwner, 32)) || message.Witnesses.Length != 1 ||
            message.Witnesses[0].Proof.Length < 224 || !listing.Binding.OwnerKey.SequenceEqual(keys.Owner))
            throw new FormatException("wrong_successor_or_signer");
        var proof = message.Witnesses[0].Proof;
        if (proof.AsSpan(160, 64).ContainsAnyExcept((byte)0)) throw new FormatException("unexpected_service_authorization");
        var context = operation == "cancel" ? ListingProofs.Context(tx, message, policy, listing.Seller, listing) :
            SecondaryPurchaseProofs.Context(tx, message, policy, listing, fees);
        keys.Sign(context).CopyTo(proof, 160);
        var result = Encode(message, policy.Network);
        if (operation == "cancel") ListingProofs.VerifyCancel(tx with { Message = result }, policy, listing);
        else SecondaryPurchaseProofs.Verify(tx with { Message = result }, policy, listing, fees);
        return result;
    }
}

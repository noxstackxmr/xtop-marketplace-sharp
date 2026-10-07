using System.Security.Cryptography;
using MarketplaceCore.Protocol.Collections;
using MarketplaceCore.Protocol.Messages;
using MarketplaceCore.Monero;

namespace MarketplaceCore.Protocol.Sales;

public sealed record SecondaryFeePolicy(ushort RoyaltyBps, byte[] RoyaltyAddress, ushort PlatformBps);
public sealed record SecondaryPayment(byte Role, byte[] Address, ulong Amount);

public static class SecondaryPurchaseProofs
{
    public const byte Operation = 0x16;
    public const ushort Profile = 0xFF0B;
    public const ushort ClientProfile = 0xFF0F;
    private static bool Same(byte[] a, byte[] b) => a.AsSpan().SequenceEqual(b);
    public static SecondaryPayment[] Payments(CollectionCreatePolicy policy, ListedTerms terms, SecondaryFeePolicy fees)
    {
        if (terms.Price == 0 || fees.RoyaltyBps > 10000 || fees.PlatformBps > 10000)
            throw new FormatException("invalid secondary price or rate");
        foreach (var address in new[] { terms.SellerPayout, fees.RoyaltyAddress, policy.FeeSpendKey.Concat(policy.FeeViewKey).ToArray() })
        {
            if (address.Length != 64) throw new FormatException("expected standard address keys");
            MoneroProofCrypto.RequirePoint(address[..32]); MoneroProofCrypto.RequirePoint(address[32..]);
        }
        var royalty = (ulong)((UInt128)terms.Price * fees.RoyaltyBps / 10000);
        var platform = (ulong)((UInt128)terms.Price * fees.PlatformBps / 10000);
        _ = checked(terms.Price + platform);
        SecondaryPayment[] payments = [new(2, fees.RoyaltyAddress, royalty), new(3, [.. policy.FeeSpendKey, .. policy.FeeViewKey], platform),
            new(4, terms.SellerPayout, terms.Price - royalty)];
        return payments.Where(p => p.Amount != 0).ToArray();
    }
    public static int MessageLength(CollectionCreatePolicy policy, ListedTerms terms, SecondaryFeePolicy fees)
        => 445 + 98 * Payments(policy, terms, fees).Length;
    public static byte[] Context(MoneroProofTransaction tx, XtopMessage message, CollectionCreatePolicy policy, ListingState listing, SecondaryFeePolicy fees)
        => MoneroProofCrypto.Hash(PrimarySaleEncoding.Write(w =>
        {
            w.Write(listing.Terms.Mode == ListingModes.Client ? "XTOP:CLIENT:SALE:V15\0"u8 : "XTOP:CUSTODY:SALE:LAB:V14\0"u8);
            w.Write(ListingProofs.Context(tx, message, policy, listing.Seller, listing));
            w.Write(fees.RoyaltyBps); w.Write(fees.RoyaltyAddress); w.Write(fees.PlatformBps);
            w.Write(policy.FeeSpendKey); w.Write(policy.FeeViewKey);
        }));
    private static byte[] Derivation(byte[] d)
    {
        var eight = new byte[32]; eight[0] = 8;
        return MoneroProofCrypto.Multiply(d, eight);
    }
    private static CancelPayload Validate(MoneroProofTransaction tx, XtopMessage message, CollectionCreatePolicy policy, ListingState listing, SecondaryFeePolicy fees)
    {
        var payload = ListingProofs.ReadCancel(message); var next = payload.Successor;
        if (listing.Terms.Mode is not (ListingModes.Marketplace or ListingModes.Client) ||
            (listing.Terms.Mode == ListingModes.Client && message.Version != 15)) throw new FormatException("invalid purchase mode or wire version");
        var payments = Payments(policy, listing.Terms, fees);
        if (message.Version != policy.WireVersion || message.Operation != Operation || !Same(message.ConfigHash, policy.ConfigHash) ||
            !Same(payload.ItemId, ListingProofs.ItemId(listing.Seller)) || !Same(payload.ListingId, listing.TransactionId) ||
            !Same(payload.PreviousImage, listing.Binding.KeyImage) || policy.NftAmount == 0 ||
            next.NominalAmount != policy.NftAmount || listing.Binding.NominalAmount != policy.NftAmount)
            throw new FormatException("purchase identity or nominal mismatch");
        foreach (var point in new[] { listing.PublicKey, listing.Binding.OwnerKey, listing.Binding.KeyImage, next.KeyImage, next.OwnerKey })
            MoneroProofCrypto.RequirePoint(point);
        if (tx.InputKeyImages.Length != 2 || tx.InputKeyImages.Count(i => Same(i, listing.Binding.KeyImage)) != 1 ||
            tx.InputKeyImages.Select(Convert.ToHexString).Distinct().Count() != 2 || tx.InputKeyImages.Any(i => Same(i, next.KeyImage)) ||
            tx.Outputs.Length != payments.Length + 2 || next.OutputIndex >= tx.Outputs.Length)
            throw new FormatException("expected listing input, buyer input, item, payouts and change");
        if (next.OwnershipWitness != 0 || next.AmountWitness != 0 || message.Witnesses.Length != 1 ||
            message.Witnesses[0].Kind != 7 || message.Witnesses[0].Profile != (listing.Terms.Mode == ListingModes.Client ? ClientProfile : Profile) || message.Witnesses[0].Proof.Length != 225 + payments.Length * 98)
            throw new FormatException("unexpected secondary proof layout");
        return payload;
    }
    public static CancelPayload Verify(MoneroProofTransaction tx, CollectionCreatePolicy policy, ListingState listing, SecondaryFeePolicy fees)
    {
        var message = XtopMessageReader.ReadMessage(tx.Message, policy.Network);
        var payload = Validate(tx, message, policy, listing, fees); var next = payload.Successor;
        var proof = message.Witnesses[0].Proof; var context = Context(tx, message, policy, listing, fees);
        var output = tx.Outputs[next.OutputIndex];
        if (!MoneroProofCrypto.VerifyDleq(context, output.Key, MoneroProofCrypto.HashToPoint(output.Key), next.KeyImage, proof[..64]) ||
            !MoneroProofCrypto.VerifySignature(context, next.OwnerKey, proof[64..128]) ||
            !MoneroProofCrypto.VerifySignature(context, listing.Binding.OwnerKey, proof[160..224]))
            throw new CryptographicException("purchase binding or authorization failed");
        if (!Same(MoneroProofCrypto.Commitment(proof[128..160], next.NominalAmount), output.Commitment))
            throw new CryptographicException("purchase nominal commitment mismatch");
        var payments = Payments(policy, listing.Terms, fees);
        if (proof[224] != payments.Length) throw new FormatException("payment count mismatch");
        var used = new HashSet<byte> { next.OutputIndex };
        for (var n = 0; n < payments.Length; n++)
        {
            var p = payments[n]; var offset = 225 + n * 98;
            var role = proof[offset]; var index = proof[offset + 1]; var d = proof[(offset + 2)..(offset + 34)];
            if (role != p.Role || index >= tx.Outputs.Length || !used.Add(index)) throw new FormatException("payment role or output reuse");
            if (!MoneroProofCrypto.VerifyDleq(context, tx.TransactionKey, p.Address[32..], d, proof[(offset + 34)..(offset + 98)]))
                throw new CryptographicException("payment recipient proof failed");
            var derivation = Derivation(d); var paid = tx.Outputs[index];
            var (amount, mask) = MoneroProofCrypto.DecodeAmount(derivation, index, paid.EncryptedAmount);
            if (!Same(MoneroProofCrypto.OutputKey(derivation, index, p.Address[..32]), paid.Key) ||
                amount != p.Amount ||
                !Same(MoneroProofCrypto.Commitment(mask, p.Amount), paid.Commitment))
                throw new CryptographicException("payment output or amount mismatch");
        }
        return payload;
    }
}

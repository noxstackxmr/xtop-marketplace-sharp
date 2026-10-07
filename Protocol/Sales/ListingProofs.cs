using System.Security.Cryptography;
using MarketplaceCore.Protocol.Collections;
using MarketplaceCore.Protocol.Messages;
using MarketplaceCore.Monero;

namespace MarketplaceCore.Protocol.Sales;

public sealed record ListedTerms(ulong Price, byte[] SellerPayout, byte[] ReturnAddress, byte[] ServiceAddress, byte Mode = 1);
public sealed record ListingItem(byte[] CollectionId, uint Serial, NewBinding Binding, byte[] PublicKey);
public sealed record ListingState(ListingItem Seller, ListedTerms Terms, NewBinding Binding, byte[] PublicKey, byte[] TransactionId);
public sealed record ListingPayload(byte[] ItemId, byte[] PreviousImage, ListedTerms Terms, NewBinding Successor);
public sealed record CancelPayload(byte[] ItemId, byte[] ListingId, byte[] PreviousImage, NewBinding Successor);

public static class ListingProofs
{
    public const byte ListOperation = 0x14;
    public const byte CancelOperation = 0x15;
    public const ushort ListProfile = 0xFF09;
    public const ushort CancelProfile = 0xFF0A;
    public const byte ClientListOperation = 0x18;
    public const ushort ClientListProfile = 0xFF0D;
    public const ushort ClientCancelProfile = 0xFF0E;
    public const int ListLength = 708;
    public const int CancelLength = 540;

    private static bool Same(byte[] a, byte[] b) => a.AsSpan().SequenceEqual(b);
    public static byte[] ItemId(ListingItem item) => Items.ItemIdentity.Derive(item.CollectionId, item.Serial);
    private static void Binding(BinaryWriter w, NewBinding b)
    {
        w.Write(b.OutputIndex); w.Write(b.KeyImage); w.Write(b.OwnerKey); w.Write(b.NominalAmount);
        w.Write(b.OwnershipWitness); w.Write(b.AmountWitness);
    }
    private static NewBinding Binding(ref PayloadReader r)
        => new(r.ReadByte(), r.Take(32).ToArray(), r.Take(32).ToArray(), r.ReadUInt64(), r.ReadByte(), r.ReadByte());
    private static void Terms(BinaryWriter w, ListedTerms terms)
    {
        w.Write(terms.Price); w.Write(terms.SellerPayout); w.Write(terms.ReturnAddress); w.Write(terms.ServiceAddress);
    }
    public static byte[] ListPayload(ListingItem previous, ListedTerms terms, NewBinding successor)
        => PrimarySaleEncoding.Write(w => { w.Write(ItemId(previous)); w.Write(previous.Binding.KeyImage); Terms(w, terms); Binding(w, successor); });
    public static byte[] ReturnPayload(ListingState listing, NewBinding successor)
        => PrimarySaleEncoding.Write(w =>
        {
            w.Write(ItemId(listing.Seller)); w.Write(listing.TransactionId); w.Write(listing.Binding.KeyImage); Binding(w, successor);
        });
    public static ListingPayload ReadList(XtopMessage message)
    {
        var r = new PayloadReader(message.Payload);
        var id = r.Take(32).ToArray(); var previous = r.Take(32).ToArray();
        var terms = new ListedTerms(r.ReadUInt64(), r.Take(64).ToArray(), r.Take(64).ToArray(), r.Take(64).ToArray(),
            ListingModes.FromOperation(message.Operation));
        var binding = Binding(ref r);
        if (message.Version == 15) r.Take(Marketplaces.MarketplacePolicyReader.SecondaryLength);
        r.EnsureEnd();
        return new(id, previous, terms, binding);
    }
    public static CancelPayload ReadCancel(XtopMessage message)
    {
        var r = new PayloadReader(message.Payload);
        var id = r.Take(32).ToArray(); var listing = r.Take(32).ToArray(); var previous = r.Take(32).ToArray();
        var binding = Binding(ref r); r.EnsureEnd();
        return new(id, listing, previous, binding);
    }
    public static ListingPayload VerifyList(MoneroProofTransaction tx, CollectionCreatePolicy policy, ListingItem previous)
    {
        var message = XtopMessageReader.ReadMessage(tx.Message, policy.Network);
        var payload = ValidateList(tx, message, policy, previous);
        Verify(tx, message, payload.Successor, payload.Terms.ServiceAddress, previous.Binding.OwnerKey,
            Context(tx, message, policy, previous, null));
        return payload;
    }
    public static CancelPayload VerifyCancel(MoneroProofTransaction tx, CollectionCreatePolicy policy, ListingState listing)
    {
        var message = XtopMessageReader.ReadMessage(tx.Message, policy.Network);
        var payload = ValidateCancel(tx, message, policy, listing);
        Verify(tx, message, payload.Successor, listing.Terms.ReturnAddress, listing.Binding.OwnerKey,
            Context(tx, message, policy, listing.Seller, listing));
        return payload;
    }
    private static void Verify(MoneroProofTransaction tx, XtopMessage message, NewBinding next, byte[] recipient,
        byte[] previousOwner, byte[] context)
    {
        var proof = message.Witnesses[0].Proof;
        var output = tx.Outputs[next.OutputIndex];
        if (!MoneroProofCrypto.VerifyDleq(context, output.Key, MoneroProofCrypto.HashToPoint(output.Key), next.KeyImage, proof[..64]) ||
            !MoneroProofCrypto.VerifySignature(context, next.OwnerKey, proof[64..128]) ||
            !MoneroProofCrypto.VerifySignature(context, previousOwner, proof[160..224]))
            throw new CryptographicException("listing binding or authorization failed");
        if (!MoneroProofCrypto.Commitment(proof[128..160], next.NominalAmount).AsSpan().SequenceEqual(output.Commitment))
            throw new CryptographicException("listing nominal commitment mismatch");
        var d = proof[224..256];
        if (!MoneroProofCrypto.VerifyDleq(context, tx.TransactionKey, recipient[32..], d, proof[256..320]))
            throw new CryptographicException("listing recipient proof failed");
        var cofactor = new byte[32]; cofactor[0] = 8;
        var derivation = MoneroProofCrypto.Multiply(d, cofactor);
        if (!Same(MoneroProofCrypto.OutputKey(derivation, next.OutputIndex, recipient[..32]), output.Key))
            throw new CryptographicException("listing output does not belong to its recipient");
        var (amount, mask) = MoneroProofCrypto.DecodeAmount(derivation, next.OutputIndex, output.EncryptedAmount);
        if (amount != next.NominalAmount || !Same(mask, proof[128..160]))
            throw new CryptographicException("listing recipient amount mismatch");
    }
    private static ListingPayload ValidateList(MoneroProofTransaction tx, XtopMessage message, CollectionCreatePolicy policy, ListingItem previous)
    {
        if (previous.CollectionId.Length != 32) throw new FormatException("invalid collection id");
        var payload = ReadList(message);
        if (!Same(payload.ItemId, ItemId(previous)) || !Same(payload.PreviousImage, previous.Binding.KeyImage))
            throw new FormatException("listing item mismatch");
        ValidateTerms(payload.Terms);
        if (message.Version == 15)
        {
            var marketplace = Marketplaces.MarketplacePolicyReader.ReadListing(message, policy.Network);
            Marketplaces.MarketplacePolicyReader.RequireMatch(marketplace, policy);
            if ((marketplace.Modes & payload.Terms.Mode) == 0) throw new FormatException("marketplace does not support the listing mode");
            if (payload.Terms.Mode == ListingModes.Marketplace && !Same(payload.Terms.ServiceAddress, marketplace.CustodyAddress!))
                throw new FormatException("marketplace custody address mismatch");
        }
        if (payload.Terms.Mode == ListingModes.Client)
        {
            if (message.Version != 15) throw new FormatException("client listing requires wire 15");
            if (!Same(payload.Terms.ServiceAddress, payload.Terms.ReturnAddress) || !Same(payload.Successor.OwnerKey, previous.Binding.OwnerKey))
                throw new FormatException("client listing must preserve seller control");
        }
        Validate(tx, message, policy, previous.Binding, previous.PublicKey, payload.Successor,
            payload.Terms.Mode == ListingModes.Client ? ClientListOperation : ListOperation,
            payload.Terms.Mode == ListingModes.Client ? ClientListProfile : ListProfile,
            ListLength + (message.Version == 15 ? Marketplaces.MarketplacePolicyReader.SecondaryLength : 0));
        return payload;
    }
    private static CancelPayload ValidateCancel(MoneroProofTransaction tx, XtopMessage message, CollectionCreatePolicy policy, ListingState listing)
    {
        var payload = ReadCancel(message);
        if (listing.TransactionId.Length != 32 || !Same(payload.ItemId, ItemId(listing.Seller)) ||
            !Same(payload.ListingId, listing.TransactionId) || !Same(payload.PreviousImage, listing.Binding.KeyImage))
            throw new FormatException("cancel listing mismatch");
        if (!Same(payload.Successor.OwnerKey, listing.Seller.Binding.OwnerKey))
            throw new FormatException("cancel must restore the seller owner key");
        ValidateTerms(listing.Terms);
        if (listing.Terms.Mode == ListingModes.Client && message.Version != 15) throw new FormatException("client cancellation requires wire 15");
        Validate(tx, message, policy, listing.Binding, listing.PublicKey, payload.Successor, CancelOperation,
            listing.Terms.Mode == ListingModes.Client ? ClientCancelProfile : CancelProfile, CancelLength);
        return payload;
    }
    private static void ValidateTerms(ListedTerms terms)
    {
        if (terms.Price == 0 || terms.Mode is not (ListingModes.Marketplace or ListingModes.Client)) throw new FormatException("invalid listing price or mode");
        foreach (var address in new[] { terms.SellerPayout, terms.ReturnAddress, terms.ServiceAddress })
        {
            if (address.Length != 64) throw new FormatException("expected standard address keys");
            MoneroProofCrypto.RequirePoint(address[..32]); MoneroProofCrypto.RequirePoint(address[32..]);
        }
    }
    private static void Validate(MoneroProofTransaction tx, XtopMessage message, CollectionCreatePolicy policy,
        NewBinding previous, byte[] previousKey, NewBinding next, byte operation, ushort profile, int length)
    {
        if (message.Version != policy.WireVersion || message.Operation != operation || !Same(message.ConfigHash, policy.ConfigHash) ||
            policy.NftAmount == 0 || previous.NominalAmount != policy.NftAmount || next.NominalAmount != policy.NftAmount)
            throw new FormatException("listing profile or nominal mismatch");
        foreach (var point in new[] { previousKey, previous.KeyImage, previous.OwnerKey, next.KeyImage, next.OwnerKey })
            MoneroProofCrypto.RequirePoint(point);
        if (tx.InputKeyImages.Length != 2 || tx.Outputs.Length != 2 ||
            tx.InputKeyImages.Count(i => Same(i, previous.KeyImage)) != 1 ||
            tx.InputKeyImages.Select(Convert.ToHexString).Distinct().Count() != 2 ||
            tx.InputKeyImages.Any(i => Same(i, next.KeyImage)) || next.OutputIndex >= tx.Outputs.Length)
            throw new FormatException("expected item input, money input, item output and change");
        if (next.OwnershipWitness != 0 || next.AmountWitness != 0 || message.Witnesses.Length != 1 ||
            message.Witnesses[0] is not { Kind: 7, Proof.Length: 320 } || message.Witnesses[0].Profile != profile ||
            (44 + message.Payload.Length + 5 + 320) != length)
            throw new FormatException("unexpected listing proof layout");
    }
    public static byte[] Context(MoneroProofTransaction tx, XtopMessage message, CollectionCreatePolicy policy,
        ListingItem previous, ListingState? listing)
        => MoneroProofCrypto.Hash(PrimarySaleEncoding.Write(w =>
        {
            w.Write(message.Operation == ClientListOperation || listing?.Terms.Mode == ListingModes.Client ? "XTOP:CLIENT:V15\0"u8 : "XTOP:CUSTODY:LAB:V14\0"u8);
            w.Write("XTOP"u8); w.Write(message.Version); w.Write(policy.Network);
            w.Write(message.ConfigHash); w.Write(message.Operation); w.Write(message.Witnesses[0].Profile); w.Write(policy.NftAmount);
            w.Write(previous.CollectionId); w.Write(previous.Serial); Binding(w, previous.Binding); w.Write(previous.PublicKey);
            if (listing != null)
            {
                w.Write(listing.TransactionId); Terms(w, listing.Terms); Binding(w, listing.Binding); w.Write(listing.PublicKey);
            }
            w.Write((uint)message.Payload.Length); w.Write(message.Payload); w.Write((byte)message.Witnesses.Length);
            foreach (var witness in message.Witnesses) { w.Write(witness.Kind); w.Write(witness.Profile); w.Write((ushort)witness.Proof.Length); }
            w.Write((uint)tx.PrefixWithoutCarrier.Length); w.Write(tx.PrefixWithoutCarrier);
            w.Write((uint)tx.RingCtBase.Length); w.Write(tx.RingCtBase);
        }));
}

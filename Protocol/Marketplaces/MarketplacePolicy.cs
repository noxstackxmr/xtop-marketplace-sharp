using MarketplaceCore.Monero;
using MarketplaceCore.Protocol.Collections;
using MarketplaceCore.Protocol.Messages;
using MarketplaceCore.Protocol.Sales;

namespace MarketplaceCore.Protocol.Marketplaces;

public sealed record MarketplacePolicy(byte[] ManagementKey, byte[] ConfigHash, byte[] FeeAddress, ulong CreationFee,
    ushort FeeBps, byte[]? CustodyAddress, byte Modes, byte[] Bytes)
{
    public byte[] Identity(byte network) => MarketplaceFormat.Identity(network, ManagementKey);
    public CollectionCreatePolicy BuildPolicy(byte network) => new(network, ConfigHash, FeeAddress[..32], FeeAddress[32..],
        CreationFee, MarketplaceFormat.ControlAmount, MarketplaceFormat.ItemAmount) { WireVersion = MarketplaceFormat.WireVersion };
}

public static class MarketplacePolicyReader
{
    public const int CreationLength = 234;
    public const int SecondaryLength = 291;

    public static void RequireMatch(MarketplacePolicy marketplace, CollectionCreatePolicy policy)
    {
        if (policy.WireVersion != MarketplaceFormat.WireVersion || !policy.ConfigHash.AsSpan().SequenceEqual(marketplace.ConfigHash) ||
            !policy.FeeSpendKey.AsSpan().SequenceEqual(marketplace.FeeAddress.AsSpan(0, 32)) ||
            !policy.FeeViewKey.AsSpan().SequenceEqual(marketplace.FeeAddress.AsSpan(32)) || policy.CreationFee != marketplace.CreationFee ||
            policy.ControlAmount != MarketplaceFormat.ControlAmount || policy.NftAmount != MarketplaceFormat.ItemAmount)
            throw new FormatException("marketplace policy mismatch");
    }

    public static byte[] Encode(MarketplaceConfiguration c, byte[] signature, bool secondary)
    {
        MarketplaceFormat.Validate(c);
        MarketplaceFormat.VerifySignature(c.Network, c.ManagementKey, MarketplaceFormat.Hash(c), signature);
        return PrimarySaleEncoding.Write(w =>
        {
            w.Write(c.ManagementKey);
            w.Write(secondary ? MarketplaceFormat.SecondaryBytes(c) : MarketplaceFormat.CreationBytes(c));
            w.Write(secondary ? MarketplaceFormat.Leaf(1, MarketplaceFormat.CreationBytes(c)) : MarketplaceFormat.Leaf(2, MarketplaceFormat.SecondaryBytes(c)));
            w.Write(MarketplaceFormat.Leaf(3, MarketplaceFormat.MetadataBytes(c))); w.Write(signature);
        });
    }

    public static MarketplacePolicy ReadCreation(XtopMessage message, byte network)
    {
        if (message.Version != MarketplaceFormat.WireVersion || message.Operation != 2 || message.Payload.Length != 220 + CreationLength)
            throw new FormatException("expected marketplace collection creation policy");
        return Read(message.Payload.AsSpan(220).ToArray(), network, message.ConfigHash, false);
    }

    public static MarketplacePolicy ReadListing(XtopMessage message, byte network)
    {
        if (message.Version != MarketplaceFormat.WireVersion || !ListingModes.IsListing(message.Operation) ||
            message.Payload.Length != 339 + SecondaryLength)
            throw new FormatException("expected marketplace listing policy");
        return Read(message.Payload.AsSpan(339).ToArray(), network, message.ConfigHash, true);
    }

    public static MarketplacePolicy Read(byte[] bytes, byte network, byte[] configHash, bool secondary)
    {
        if (bytes.Length != (secondary ? SecondaryLength : CreationLength)) throw new FormatException("invalid marketplace policy length");
        var r = new PayloadReader(bytes);
        var key = r.Take(32).ToArray();
        var terms = r.Take(secondary ? 131 : 74).ToArray(); var t = new PayloadReader(terms);
        var creation = secondary ? 0UL : t.ReadUInt64(); var rate = t.ReadUInt16(); var address = t.Take(64).ToArray();
        var custody = secondary ? t.Take(64).ToArray() : null; var modes = secondary ? t.ReadByte() : (byte)0;
        var otherHash = r.Take(32).ToArray(); var metadataHash = r.Take(32).ToArray(); var signature = r.Take(64).ToArray(); r.EnsureEnd();
        if (rate > 10000) throw new FormatException("marketplace rate exceeds 10000 bps");
        MarketplaceFormat.Address(address);
        if (secondary)
        {
            if (modes is < 1 or > 3) throw new FormatException("invalid marketplace sale modes");
            if ((modes & MarketplaceFormat.CustodyMode) != 0)
            {
                MarketplaceFormat.Address(custody!);
                if (address.AsSpan().SequenceEqual(custody)) throw new FormatException("fee and custody addresses must differ");
            }
            else if (custody!.Any(b => b != 0)) throw new FormatException("unexpected custody address");
        }
        var ownHash = MarketplaceFormat.Leaf(secondary ? (byte)2 : (byte)1, terms);
        var hash = MarketplaceFormat.Root(network, key, secondary ? otherHash : ownHash, secondary ? ownHash : otherHash, metadataHash);
        if (!hash.AsSpan().SequenceEqual(configHash)) throw new FormatException("marketplace policy commitment mismatch");
        MarketplaceFormat.VerifySignature(network, key, hash, signature);
        return new(key, hash, address, creation, rate, custody, modes, bytes.ToArray());
    }
}

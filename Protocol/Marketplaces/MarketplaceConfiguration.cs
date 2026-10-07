using System.Security.Cryptography;
using System.Text;
using MarketplaceCore.Monero;
using MarketplaceCore.Protocol.Messages;
using MarketplaceCore.Protocol.Sales;

namespace MarketplaceCore.Protocol.Marketplaces;

public sealed record MarketplaceConfiguration(byte Network, byte[] ManagementKey, uint Revision, byte[] PreviousHash,
    string Name, string WebsiteUrl, string CommunicationUrl, ushort ApiVersion, byte Modes,
    ulong CreationFee, ushort PrimaryFeeBps, ushort SecondaryFeeBps, byte[] FeeAddress, byte[] CustodyAddress);

public static class MarketplaceFormat
{
    public const byte Operation = 0x17;
    public const ushort Profile = 0xFF0C;
    public const byte WireVersion = 15;
    public const ulong ControlAmount = 1000;
    public const ulong ItemAmount = 1000;
    public const byte CustodyMode = 1;
    public const byte ClientMode = 2;

    public static byte[] Identity(byte network, byte[] key)
        => MoneroProofCrypto.Hash([.. "XTOP:MARKETPLACE:ID:V1\0"u8, network, .. key]);

    public static byte[] CreationBytes(MarketplaceConfiguration c)
        => PrimarySaleEncoding.Write(w => { w.Write(c.CreationFee); w.Write(c.PrimaryFeeBps); w.Write(c.FeeAddress); });

    public static byte[] SecondaryBytes(MarketplaceConfiguration c)
        => PrimarySaleEncoding.Write(w => { w.Write(c.SecondaryFeeBps); w.Write(c.FeeAddress); w.Write(c.CustodyAddress); w.Write(c.Modes); });

    public static byte[] MetadataBytes(MarketplaceConfiguration c)
        => PrimarySaleEncoding.Write(w =>
        {
            w.Write(c.Revision); w.Write(c.PreviousHash); WriteString(w, c.Name, true);
            WriteString(w, c.WebsiteUrl); WriteString(w, c.CommunicationUrl); w.Write(c.ApiVersion);
        });

    public static byte[] Leaf(byte type, byte[] bytes)
        => MoneroProofCrypto.Hash([.. "XTOP:MARKETPLACE:LEAF:V1\0"u8, type, .. bytes]);

    public static byte[] Root(byte network, byte[] key, byte[] creation, byte[] secondary, byte[] metadata)
        => MoneroProofCrypto.Hash([.. "XTOP:MARKETPLACE:CONFIG:V1\0"u8, network, .. key, .. creation, .. secondary, .. metadata]);

    public static byte[] Hash(MarketplaceConfiguration c)
        => Root(c.Network, c.ManagementKey, Leaf(1, CreationBytes(c)), Leaf(2, SecondaryBytes(c)), Leaf(3, MetadataBytes(c)));

    public static byte[] SignatureContext(byte[] hash)
        => MoneroProofCrypto.Hash([.. "XTOP:MARKETPLACE:SIGN:V1\0"u8, .. hash]);

    public static void VerifySignature(byte network, byte[] key, byte[] hash, byte[] signature)
    {
        if (network is not (0 or 1 or 2 or 255) || hash.Length != 32) throw new FormatException("invalid marketplace network or hash");
        MoneroProofCrypto.RequirePoint(key);
        if (!MoneroProofCrypto.VerifySignature(SignatureContext(hash), key, signature))
            throw new CryptographicException("marketplace signature failed");
    }

    public static byte[] Encode(MarketplaceConfiguration c)
    {
        Validate(c);
        return PrimarySaleEncoding.Write(w =>
        {
            w.Write((byte)1); w.Write(c.Network); w.Write(c.ManagementKey);
            w.Write(CreationBytes(c)); w.Write(c.SecondaryFeeBps); w.Write(c.CustodyAddress); w.Write(c.Modes);
            w.Write(MetadataBytes(c));
        });
    }

    public static MarketplaceConfiguration Read(XtopMessage message, byte network)
    {
        if (message.Version != WireVersion || message.Operation != Operation || message.Witnesses.Length != 1 ||
            message.Witnesses[0] is not { Kind: 3, Profile: Profile, Proof.Length: 64 })
            throw new FormatException("expected signed marketplace configuration");
        var r = new PayloadReader(message.Payload);
        if (r.ReadByte() != 1 || r.ReadByte() != network) throw new FormatException("unsupported marketplace format or network");
        var key = r.Take(32).ToArray(); var creation = r.ReadUInt64(); var primary = r.ReadUInt16();
        var feeAddress = r.Take(64).ToArray(); var secondary = r.ReadUInt16(); var custody = r.Take(64).ToArray(); var modes = r.ReadByte();
        var revision = r.ReadUInt32(); var previous = r.Take(32).ToArray();
        var name = ReadString(ref r, true); var website = ReadString(ref r); var communication = ReadString(ref r); var api = r.ReadUInt16();
        r.EnsureEnd();
        var c = new MarketplaceConfiguration(network, key, revision, previous, name, website, communication, api, modes,
            creation, primary, secondary, feeAddress, custody);
        Validate(c);
        if (!Hash(c).AsSpan().SequenceEqual(message.ConfigHash)) throw new FormatException("marketplace configuration hash mismatch");
        VerifySignature(network, key, message.ConfigHash, message.Witnesses[0].Proof);
        return c;
    }

    public static void Validate(MarketplaceConfiguration c)
    {
        if (c.Network is not (0 or 1 or 2 or 255) || c.PreviousHash.Length != 32 || c.ApiVersion == 0 ||
            c.PrimaryFeeBps > 10000 || c.SecondaryFeeBps > 10000 || c.Modes is < 1 or > 3)
            throw new FormatException("invalid marketplace configuration");
        if ((c.Revision == 0) != c.PreviousHash.All(b => b == 0)) throw new FormatException("invalid previous marketplace configuration");
        MoneroProofCrypto.RequirePoint(c.ManagementKey); Address(c.FeeAddress);
        if ((c.Modes & CustodyMode) != 0)
        {
            Address(c.CustodyAddress);
            if (c.FeeAddress.AsSpan().SequenceEqual(c.CustodyAddress)) throw new FormatException("fee and custody addresses must differ");
        }
        else if (c.CustodyAddress.Length != 64 || c.CustodyAddress.Any(b => b != 0)) throw new FormatException("unexpected custody address");
        Text(c.Name, 64);
        if (c.Name[0] == ' ' || c.Name[^1] == ' ') throw new FormatException("invalid marketplace name spacing");
        Url(c.WebsiteUrl, c.Network); Url(c.CommunicationUrl, c.Network);
    }

    public static void Address(byte[] address)
    {
        if (address.Length != 64) throw new FormatException("expected standard address keys");
        MoneroProofCrypto.RequirePoint(address[..32]); MoneroProofCrypto.RequirePoint(address[32..]);
    }

    private static void Text(string value, int maximum)
    {
        if (value.Length < 1 || value.Length > maximum || value.Any(c => c is < ' ' or > '~'))
            throw new FormatException("expected bounded printable ASCII");
    }

    private static void Url(string value, byte network)
    {
        Text(value, 256);
        if (value.Any(char.IsWhiteSpace) || !Uri.TryCreate(value, UriKind.Absolute, out var uri) ||
            (uri.Scheme != "https" && !(network == 255 && uri.Scheme == "http")) ||
            string.IsNullOrEmpty(uri.Host) || uri.UserInfo.Length != 0 || uri.Query.Length != 0 || uri.Fragment.Length != 0)
            throw new FormatException("expected an absolute HTTPS URL without credentials, query or fragment");
    }

    private static void WriteString(BinaryWriter w, string value, bool name = false)
    {
        var bytes = Encoding.ASCII.GetBytes(value);
        if (name) w.Write(checked((byte)bytes.Length)); else w.Write(checked((ushort)bytes.Length));
        w.Write(bytes);
    }

    private static string ReadString(ref PayloadReader r, bool name = false)
    {
        var size = name ? r.ReadByte() : r.ReadUInt16();
        if (size < 1 || size > (name ? 64 : 256)) throw new FormatException("invalid marketplace string length");
        var bytes = r.Take(size);
        foreach (var value in bytes) if (value is < 0x20 or > 0x7E) throw new FormatException("marketplace strings must be printable ASCII");
        return Encoding.ASCII.GetString(bytes);
    }
}

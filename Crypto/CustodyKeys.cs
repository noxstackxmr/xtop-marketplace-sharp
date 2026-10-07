using System.Runtime.InteropServices;
using System.Security.Cryptography;
using MarketplaceCore.Monero;
using MarketplaceCore.Options;
using Microsoft.Extensions.Options;

namespace MarketplaceCore.Crypto;

public sealed class CustodyKeys : IDisposable
{
    private readonly byte[] spend;
    private readonly byte[] view;
    private readonly byte[] owner;
    public bool Enabled { get; }
    public byte[] Address { get; }
    public byte[] Owner { get; }
    internal string SpendSecret => Convert.ToHexStringLower(spend);
    internal string ViewSecret => Convert.ToHexStringLower(view);

    public CustodyKeys(IOptions<CustodyOptions> config, IOptions<MarketplaceOptions> market)
    {
        var o = config.Value;
        Enabled = o.Enabled;
        if (!Enabled) { spend = view = owner = Address = Owner = []; return; }
        if (o.TestKeys && market.Value.Network != "fakechain") throw new InvalidOperationException("test custody keys require fakechain");
        spend = OwnerSignature.Hex(o.SpendSecret, 32);
        view = OwnerSignature.Hex(o.ViewSecret, 32);
        owner = OwnerSignature.Hex(o.OwnerSecret, 32);
        Address = [.. Public(spend), .. Public(view)];
        Owner = Public(owner);
        if (spend.SequenceEqual(owner)) throw new InvalidOperationException("custody spend and owner keys must differ");
        OwnerSignature.Hex(o.GenesisHash, 32);
        if (!Uri.TryCreate(o.RpcUrl, UriKind.Absolute, out var rpc) || rpc.Scheme is not ("http" or "https") ||
            rpc.UserInfo != "" || rpc.Query != "" || rpc.Fragment != "") throw new InvalidOperationException("invalid custody RPC URL");
    }

    public byte[] Sign(byte[] context) => Sign(context, owner);
    internal byte[] JournalKey() => HKDF.DeriveKey(HashAlgorithmName.SHA256, spend, 32, info: "XTOP:CUSTODY:JOURNAL:V1"u8.ToArray());
    public static byte[] Public(byte[] secret)
    {
        var result = new byte[32];
        if (secret.Length != 32 || Native.xtop_secret_to_public(secret, result) != 1) throw new CryptographicException("invalid secret scalar");
        return result;
    }
    public static byte[] NewSecret()
    {
        var value = new byte[32];
        do { RandomNumberGenerator.Fill(value); } while (!MoneroProofCrypto.IsScalar(value) || value.All(b => b == 0));
        return value;
    }
    public static byte[] Sign(byte[] context, byte[] secret)
    {
        var nonce = NewSecret();
        try
        {
            var result = new byte[64];
            if (context.Length != 32 || Native.xtop_signature_create(context, Public(secret), secret, nonce, result) != 1)
                throw new CryptographicException("signature failed");
            return result;
        }
        finally { CryptographicOperations.ZeroMemory(nonce); }
    }
    public static byte[] Dleq(byte[] context, byte[] point, byte[] basePoint, byte[] image, byte[] secret)
    {
        var nonce = NewSecret();
        try
        {
            var result = new byte[64];
            if (Native.xtop_dleq_create(context, point, basePoint, image, secret, nonce, result) != 1)
                throw new CryptographicException("binding proof failed");
            return result;
        }
        finally { CryptographicOperations.ZeroMemory(nonce); }
    }
    public byte[] Derivation(byte[] transactionKey)
    {
        var eight = new byte[32]; eight[0] = 8;
        return MoneroProofCrypto.Multiply(MoneroProofCrypto.Multiply(transactionKey, view), eight);
    }
    public byte[] OutputSecret(byte[] derivation, byte index)
    {
        var result = new byte[32];
        if (Native.xtop_derive_secret(derivation, index, spend, result) != 1) throw new CryptographicException("output derivation failed");
        return result;
    }
    public void Dispose()
    {
        CryptographicOperations.ZeroMemory(spend); CryptographicOperations.ZeroMemory(view); CryptographicOperations.ZeroMemory(owner);
    }
    private static class Native
    {
        [DllImport("xtop_monero", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int xtop_secret_to_public(byte[] secret, [Out] byte[] result);
        [DllImport("xtop_monero", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int xtop_signature_create(byte[] context, byte[] owner, byte[] secret, byte[] nonce, [Out] byte[] result);
        [DllImport("xtop_monero", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int xtop_dleq_create(byte[] context, byte[] r, byte[] a, byte[] d, byte[] secret, byte[] nonce, [Out] byte[] result);
        [DllImport("xtop_monero", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int xtop_derive_secret(byte[] derivation, ulong index, byte[] secret, [Out] byte[] result);
    }
}

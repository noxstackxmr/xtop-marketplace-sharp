using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace MarketplaceCore.Crypto;

public static class OwnerSignature
{
    public static byte[] Hex(string? value, int size)
    {
        if (value == null || value.Length != size * 2 || value.Any(c => !char.IsAsciiHexDigitLower(c)))
            throw new FormatException("invalid hex value");
        return Convert.FromHexString(value);
    }

    public static bool IsOwner(string? key)
    {
        try { return Native.xtop_point_is_valid(Hex(key, 32)) == 1; }
        catch (FormatException) { return false; }
    }

    public static bool Verify(string hash, string owner, string? signature)
    {
        try { return Native.xtop_signature_verify(Hex(hash, 32), Hex(owner, 32), Hex(signature, 64)) == 1; }
        catch (FormatException) { return false; }
    }

    public static void RequireEncryptionKey(string key)
    {
        var bytes = Hex(key, 65);
        if (bytes[0] != 4) throw new FormatException("invalid encryption key");
        try
        {
            using var parsed = ECDiffieHellman.Create(new ECParameters
            {
                Curve = ECCurve.NamedCurves.nistP256,
                Q = new ECPoint { X = bytes[1..33], Y = bytes[33..65] }
            });
        }
        catch (Exception exception) when (exception is CryptographicException or ArgumentException or PlatformNotSupportedException)
        { throw new FormatException("invalid encryption key"); }
    }

    private static class Native
    {
        [DllImport("xtop_monero", CallingConvention = CallingConvention.Cdecl)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.AssemblyDirectory | DllImportSearchPath.SafeDirectories)]
        internal static extern int xtop_point_is_valid(byte[] point);

        [DllImport("xtop_monero", CallingConvention = CallingConvention.Cdecl)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.AssemblyDirectory | DllImportSearchPath.SafeDirectories)]
        internal static extern int xtop_signature_verify(byte[] message, byte[] owner, byte[] signature);
    }
}

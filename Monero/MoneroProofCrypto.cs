using System.Buffers.Binary;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace MarketplaceCore.Monero;

public static class MoneroProofCrypto
{
    public static byte[] Hash(byte[] bytes)
    {
        var result = new byte[32];
        Native.xtop_fast_hash(bytes, (nuint)bytes.Length, result);
        return result;
    }

    public static bool IsPoint(byte[] value) => value.Length == 32 && Native.xtop_point_is_valid(value) == 1;
    public static bool IsScalar(byte[] value) => value.Length == 32 && Native.xtop_scalar_is_canonical(value) == 1;
    public static void RequirePoint(byte[] value)
    {
        if (!IsPoint(value)) throw new FormatException("invalid canonical prime-order point");
    }

    public static byte[] HashToPoint(byte[] point)
    {
        RequirePoint(point);
        var result = new byte[32];
        Native.xtop_hash_to_point(point, result);
        return result;
    }

    public static byte[] Multiply(byte[] point, byte[] scalar)
    {
        RequirePoint(point);
        RequireScalar(scalar);
        var result = new byte[32];
        Check(Native.xtop_point_multiply(point, scalar, result));
        return result;
    }

    public static byte[] Commitment(byte[] mask, ulong amount)
    {
        RequireScalar(mask);
        var result = new byte[32];
        Check(Native.xtop_commitment(mask, amount, result));
        return result;
    }

    public static bool VerifyDleq(byte[] context, byte[] r, byte[] a, byte[] d, byte[] proof)
        => context.Length == 32 && r.Length == 32 && a.Length == 32 && d.Length == 32 && proof.Length == 64 &&
           Native.xtop_dleq_verify(context, r, a, d, proof) == 1;

    public static bool VerifySignature(byte[] context, byte[] owner, byte[] proof)
        => context.Length == 32 && owner.Length == 32 && proof.Length == 64 &&
           Native.xtop_signature_verify(context, owner, proof) == 1;

    public static byte[] OutputKey(byte[] derivation, ulong index, byte[] spendKey)
    {
        RequirePoint(derivation);
        RequirePoint(spendKey);
        var result = new byte[32];
        Check(Native.xtop_derive_public(derivation, index, spendKey, result));
        return result;
    }

    public static (ulong Amount, byte[] Mask) DecodeAmount(byte[] derivation, ulong index, byte[] encrypted)
    {
        RequirePoint(derivation);
        if (encrypted.Length != 8) throw new FormatException("invalid encrypted amount length");
        var key = HashToScalar([.. derivation, .. NativeVarInt.Encode(index)]);
        var pad = Hash([.. "amount"u8, .. key]);
        var amount = BinaryPrimitives.ReadUInt64LittleEndian(encrypted) ^ BinaryPrimitives.ReadUInt64LittleEndian(pad);
        return (amount, HashToScalar([.. "commitment_mask"u8, .. key]));
    }

    private static byte[] HashToScalar(byte[] bytes)
    {
        var result = new byte[32];
        Native.xtop_hash_to_scalar(bytes, (nuint)bytes.Length, result);
        return result;
    }

    private static void RequireScalar(byte[] value)
    {
        if (!IsScalar(value)) throw new FormatException("noncanonical scalar");
    }

    private static void Check(int result)
    {
        if (result != 1) throw new CryptographicException("invalid native proof input");
    }

    private static class Native
    {
        private const string Library = "xtop_monero";

        [DllImport(Library, CallingConvention = CallingConvention.Cdecl)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.AssemblyDirectory | DllImportSearchPath.SafeDirectories)]
        internal static extern void xtop_fast_hash(byte[] data, nuint length, [Out] byte[] result);
        [DllImport(Library, CallingConvention = CallingConvention.Cdecl)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.AssemblyDirectory | DllImportSearchPath.SafeDirectories)]
        internal static extern void xtop_hash_to_scalar(byte[] data, nuint length, [Out] byte[] result);
        [DllImport(Library, CallingConvention = CallingConvention.Cdecl)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.AssemblyDirectory | DllImportSearchPath.SafeDirectories)]
        internal static extern int xtop_point_is_valid(byte[] point);
        [DllImport(Library, CallingConvention = CallingConvention.Cdecl)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.AssemblyDirectory | DllImportSearchPath.SafeDirectories)]
        internal static extern int xtop_scalar_is_canonical(byte[] scalar);
        [DllImport(Library, CallingConvention = CallingConvention.Cdecl)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.AssemblyDirectory | DllImportSearchPath.SafeDirectories)]
        internal static extern void xtop_hash_to_point(byte[] point, [Out] byte[] result);
        [DllImport(Library, CallingConvention = CallingConvention.Cdecl)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.AssemblyDirectory | DllImportSearchPath.SafeDirectories)]
        internal static extern int xtop_point_multiply(byte[] point, byte[] scalar, [Out] byte[] result);
        [DllImport(Library, CallingConvention = CallingConvention.Cdecl)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.AssemblyDirectory | DllImportSearchPath.SafeDirectories)]
        internal static extern int xtop_commitment(byte[] mask, ulong amount, [Out] byte[] result);
        [DllImport(Library, CallingConvention = CallingConvention.Cdecl)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.AssemblyDirectory | DllImportSearchPath.SafeDirectories)]
        internal static extern int xtop_dleq_verify(byte[] context, byte[] r, byte[] a, byte[] d, byte[] proof);
        [DllImport(Library, CallingConvention = CallingConvention.Cdecl)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.AssemblyDirectory | DllImportSearchPath.SafeDirectories)]
        internal static extern int xtop_signature_verify(byte[] context, byte[] owner, byte[] proof);
        [DllImport(Library, CallingConvention = CallingConvention.Cdecl)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.AssemblyDirectory | DllImportSearchPath.SafeDirectories)]
        internal static extern int xtop_derive_public(byte[] derivation, ulong index, byte[] spend, [Out] byte[] result);
    }
}

internal static class NativeVarInt
{
    public static byte[] Encode(ulong value)
    {
        var bytes = new List<byte>();
        do
        {
            var next = (byte)(value & 127);
            value >>= 7;
            bytes.Add(value == 0 ? next : (byte)(next | 128));
        } while (value != 0);
        return bytes.ToArray();
    }
}

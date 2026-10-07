using System.Security.Cryptography;
using System.Text.Json;
using MarketplaceCore.Crypto;
using MarketplaceCore.Options;
using Microsoft.Extensions.Options;

namespace MarketplaceCore.Services.Custody;

public sealed record CustodyReceipt(string Reference, string ConfigHash, string Operation, string OwnerKey,
    string KeyImage, string SignatureHash, JsonElement Transaction);

public sealed class CustodyJournal : IDisposable
{
    private readonly string directory;
    private readonly byte[] key;
    private readonly FileStream? instanceLock;
    public CustodyJournal(CustodyKeys keys, IOptions<CustodyOptions> options, IHostEnvironment environment)
    {
        directory = Path.GetFullPath(options.Value.JournalDirectory, environment.ContentRootPath);
        key = keys.Enabled ? keys.JournalKey() : [];
        if (!keys.Enabled) return;
        Directory.CreateDirectory(directory);
        instanceLock = new FileStream(Path.Combine(directory, "instance.lock"), FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
    }
    public CustodyReceipt? Read(string image)
    {
        var path = FileName(image);
        if (!File.Exists(path)) return null;
        var bytes = File.ReadAllBytes(path);
        if (bytes.Length is < 28 or > 262144) throw new InvalidDataException("invalid_custody_journal");
        var plain = new byte[bytes.Length - 28];
        try
        {
            using var cipher = new AesGcm(key, 16);
            cipher.Decrypt(bytes.AsSpan(0, 12), bytes.AsSpan(28), bytes.AsSpan(12, 16), plain, OwnerSignature.Hex(image, 32));
            var result = JsonSerializer.Deserialize<CustodyReceipt>(plain) ?? throw new InvalidDataException("invalid_custody_journal");
            if (result.KeyImage != image) throw new InvalidDataException("invalid_custody_journal");
            return result;
        }
        finally { CryptographicOperations.ZeroMemory(plain); }
    }
    public void Save(CustodyReceipt receipt)
    {
        var existing = Read(receipt.KeyImage);
        if (existing != null) throw new InvalidOperationException("output_already_signed");
        var plain = JsonSerializer.SerializeToUtf8Bytes(receipt);
        var bytes = new byte[plain.Length + 28];
        RandomNumberGenerator.Fill(bytes.AsSpan(0, 12));
        var temporary = FileName(receipt.KeyImage) + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            using var cipher = new AesGcm(key, 16);
            cipher.Encrypt(bytes.AsSpan(0, 12), plain, bytes.AsSpan(28), bytes.AsSpan(12, 16), OwnerSignature.Hex(receipt.KeyImage, 32));
            using (var file = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough))
            { file.Write(bytes); file.Flush(true); }
            File.Move(temporary, FileName(receipt.KeyImage), false);
        }
        finally { CryptographicOperations.ZeroMemory(plain); if (File.Exists(temporary)) File.Delete(temporary); }
    }
    private string FileName(string image)
    {
        OwnerSignature.Hex(image, 32);
        return Path.Combine(directory, image + ".bin");
    }
    public void Dispose() { instanceLock?.Dispose(); CryptographicOperations.ZeroMemory(key); }
}

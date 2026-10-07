using System.Security.Cryptography;
using System.Text.Json;
using MarketplaceCore.Crypto;
using MarketplaceCore.Options;
using Microsoft.Extensions.Options;

namespace MarketplaceCore.Services.Custody;

public sealed record CustodyReceipt(string Reference, string ConfigHash, string Operation, string OwnerKey,
    string KeyImage, string SignatureHash, JsonElement Transaction, long Sequence = 0);

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
        => ReadAll(image).LastOrDefault();

    public IReadOnlyList<CustodyReceipt> ReadAll(string image)
    {
        var path = FileName(image);
        var paths = Directory.GetFiles(directory, image + ".*.bin").AsEnumerable();
        if (File.Exists(path)) paths = paths.Prepend(path);
        return paths.Select(p => ReadFile(image, p)).OrderBy(r => r.Sequence).ToArray();
    }
    private CustodyReceipt ReadFile(string image, string path)
    {
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
        var existing = ReadAll(receipt.KeyImage);
        if (existing.Count != 0 && receipt.Operation != "cancel") throw new InvalidOperationException("output_already_signed");
        if (receipt.Operation == "cancel" && existing.Any(r => r.Operation == "cancel" && r.OwnerKey != receipt.OwnerKey))
            throw new InvalidOperationException("wrong_cancellation_owner");
        OwnerSignature.Hex(receipt.SignatureHash, 32);
        var destination = existing.Count == 0 ? FileName(receipt.KeyImage) :
            Path.Combine(directory, receipt.KeyImage + "." + receipt.SignatureHash + ".bin");
        receipt = receipt with { Sequence = existing.Count == 0 ? 0 : checked(existing.Max(r => r.Sequence) + 1) };
        var plain = JsonSerializer.SerializeToUtf8Bytes(receipt);
        var bytes = new byte[plain.Length + 28];
        RandomNumberGenerator.Fill(bytes.AsSpan(0, 12));
        var temporary = destination + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            using var cipher = new AesGcm(key, 16);
            cipher.Encrypt(bytes.AsSpan(0, 12), plain, bytes.AsSpan(28), bytes.AsSpan(12, 16), OwnerSignature.Hex(receipt.KeyImage, 32));
            using (var file = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough))
            { file.Write(bytes); file.Flush(true); }
            File.Move(temporary, destination, false);
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

using System.Diagnostics;
using System.Text.Json;
using MarketplaceCore.Options;
using Microsoft.Extensions.Options;

namespace MarketplaceCore.Services.Custody;

public interface ICustodySigner : IDisposable
{
    Task<JsonElement> CallAsync(object command, CancellationToken cancellationToken);
}
public interface ICustodySignerFactory { ICustodySigner Create(); }

public sealed class CustodySignerFactory(IOptions<CustodyOptions> options, IHostEnvironment environment) : ICustodySignerFactory
{
    public ICustodySigner Create()
    {
        var path = Path.GetFullPath(options.Value.SignerPath, environment.ContentRootPath);
        return new CustodySigner(path, options.Value.SignerTimeoutSeconds);
    }
}

internal sealed class CustodySigner : ICustodySigner
{
    private readonly Process process;
    private readonly int timeout;
    private readonly Task drain;
    private bool disposed;
    public CustodySigner(string path, int timeoutSeconds)
    {
        timeout = timeoutSeconds;
        process = Process.Start(new ProcessStartInfo(path)
        {
            UseShellExecute = false, CreateNoWindow = true,
            RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true
        }) ?? throw new InvalidOperationException("signer_unavailable");
        drain = process.StandardError.BaseStream.CopyToAsync(Stream.Null);
    }
    public async Task<JsonElement> CallAsync(object command, CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(TimeSpan.FromSeconds(timeout));
        try
        {
            var encoded = JsonSerializer.Serialize(command);
            if (encoded.Length > 250000) throw new FormatException("signer_request_too_large");
            await process.StandardInput.WriteLineAsync(encoded.AsMemory(), deadline.Token);
            await process.StandardInput.FlushAsync(deadline.Token);
            var line = await process.StandardOutput.ReadLineAsync(deadline.Token);
            if (line == null || line.Length > 250000) throw new InvalidOperationException("signer_unavailable");
            using var document = JsonDocument.Parse(line);
            if (!document.RootElement.TryGetProperty("ok", out var result)) throw new InvalidOperationException("signer_rejected");
            return result.Clone();
        }
        catch { Dispose(); throw; }
    }
    public void Dispose()
    {
        if (disposed) return;
        disposed = true;
        try { if (!process.HasExited) process.Kill(true); }
        finally { process.Dispose(); }
    }
}

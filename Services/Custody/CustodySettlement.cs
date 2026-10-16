using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text.Json;
using MarketplaceCore.Options;
using Microsoft.Extensions.Options;

namespace MarketplaceCore.Services.Custody;

public sealed class CustodySettlement(CustodyJournal journal, ICustodySubmissionNode node, CustodyResources resources,
    IOptions<CustodyOptions> options, TimeProvider clock, ILogger<CustodySettlement> logger) : BackgroundService
{
    private sealed class Pending
    {
        public readonly SemaphoreSlim Gate = new(1, 1);
        public long Due;
        public string Status = "pending";
    }
    private readonly ConcurrentDictionary<string, Pending> pending = new();
    private readonly SemaphoreSlim wake = new(0, 1);
    private readonly CustodyWorkQueue work = new(options.Value.MaximumQueuedRequests, options.Value.ParallelSubmissions);
    public string State(string image) => pending.TryGetValue(image, out var state) ? Volatile.Read(ref state.Status) : "pending";
    public void Notify(string image)
    {
        var state = pending.GetOrAdd(image, _ => new());
        Interlocked.Exchange(ref state.Due, -1);
        try { wake.Release(); } catch (SemaphoreFullException) { }
    }
    public async Task ReconcileAsync(string image, CancellationToken token)
    {
        var state = pending.GetOrAdd(image, _ => new());
        await state.Gate.WaitAsync(token);
        try
        {
            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(token);
            deadline.CancelAfter(TimeSpan.FromSeconds(options.Value.SubmissionTimeoutSeconds));
            using var item = await resources.Items.EnterAsync(image, deadline.Token);
            using var lease = await work.EnterAsync(true, deadline.Token);
            var receipt = journal.Read(image);
            if (receipt == null) return;
            var status = await node.ReconcileAsync(receipt, deadline.Token);
            Volatile.Write(ref state.Status, status);
            var delay = status == "confirmed" ? options.Value.ConfirmedRecheckSeconds : options.Value.SubmissionRetrySeconds;
            Interlocked.Exchange(ref state.Due, clock.GetUtcNow().ToUnixTimeMilliseconds() + delay * 1000L);
        }
        catch (Exception e) when (e is HttpRequestException or IOException or InvalidOperationException or JsonException or
            KeyNotFoundException or OperationCanceledException or CryptographicException or FormatException or OverflowException)
        {
            Volatile.Write(ref state.Status, "pending");
            Interlocked.Exchange(ref state.Due, clock.GetUtcNow().ToUnixTimeMilliseconds() + options.Value.SubmissionRetrySeconds * 1000L);
            logger.LogWarning("Custody submission deferred: {Reason}", e.GetType().Name);
            if (token.IsCancellationRequested) throw;
        }
        finally { state.Gate.Release(); }
    }
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!options.Value.Enabled) return;
        foreach (var image in journal.LatestImages()) pending.TryAdd(image, new());
        try
        {
            while (!stoppingToken.IsCancellationRequested)
            {
                var now = clock.GetUtcNow().ToUnixTimeMilliseconds();
                var due = pending.Where(p => Interlocked.Read(ref p.Value.Due) <= now)
                    .OrderBy(p => Interlocked.Read(ref p.Value.Due)).Take(options.Value.SubmissionBatchSize).Select(p => p.Key).ToArray();
                await Parallel.ForEachAsync(due, new ParallelOptions { MaxDegreeOfParallelism = options.Value.ParallelSubmissions, CancellationToken = stoppingToken },
                    async (image, token) => await ReconcileAsync(image, token));
                if (due.Length == options.Value.SubmissionBatchSize) continue;
                await wake.WaitAsync(TimeSpan.FromSeconds(1), stoppingToken);
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { }
    }
}

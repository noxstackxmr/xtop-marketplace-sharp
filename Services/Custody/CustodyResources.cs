using Microsoft.Extensions.Options;
using MarketplaceCore.Options;

namespace MarketplaceCore.Services.Custody;

public sealed class CustodyCapacityException : Exception;

public sealed class CustodyResources(IOptions<CustodyOptions> options)
{
    public CustodyWorkQueue Work { get; } = new(options.Value.MaximumQueuedRequests, options.Value.ParallelTrades);
    public CustodyItemLocks Items { get; } = new();
    public CustodySignerBudget Signers { get; } = new(options.Value.MaximumSignerProcesses,
        options.Value.MaximumQueuedRequests, () => MemoryAvailable(options.Value));

    private static bool MemoryAvailable(CustodyOptions options)
    {
        if (options.SignerMemorySoftLimitBytes == 0) return true;
        try
        {
            var usage = long.Parse(File.ReadAllText(options.MemoryUsageFile).Trim());
            return usage >= 0 && usage < options.SignerMemorySoftLimitBytes;
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or FormatException or OverflowException)
        { return false; }
    }
}

public sealed class CustodySignerBudget(int maximum, int maximumWaiting, Func<bool>? memoryAvailable = null)
{
    private readonly object gate = new();
    private readonly LinkedList<object> waiting = [];
    private int used;
    public (int Active, int Waiting) Snapshot() { lock (gate) return (used, waiting.Count); }
    public async Task<IDisposable> EnterAsync(CancellationToken token)
    {
        LinkedListNode<object> ticket;
        lock (gate)
        {
            if (waiting.Count >= maximumWaiting) throw new InvalidOperationException("custody_busy");
            ticket = waiting.AddLast(new object());
        }
        try
        {
            while (true)
            {
                token.ThrowIfCancellationRequested();
                lock (gate)
                    if (waiting.First == ticket && used < maximum && (memoryAvailable?.Invoke() ?? true))
                    { used++; waiting.Remove(ticket); return new Lease(this); }
                await Task.Delay(250, token);
            }
        }
        finally { lock (gate) if (ticket.List != null) waiting.Remove(ticket); }
    }
    private sealed class Lease(CustodySignerBudget owner) : IDisposable
    {
        private int disposed;
        public void Dispose() { if (Interlocked.Exchange(ref disposed, 1) == 0) lock (owner.gate) owner.used--; }
    }
}

public sealed class CustodyItemLocks
{
    private sealed class Entry { public readonly SemaphoreSlim Gate = new(1, 1); public int Users; }
    private readonly object gate = new();
    private readonly Dictionary<string, Entry> entries = [];
    public async Task<IDisposable> EnterAsync(string item, CancellationToken token)
    {
        Entry entry;
        lock (gate)
        { if (!entries.TryGetValue(item, out entry!)) entries[item] = entry = new(); entry.Users++; }
        try { await entry.Gate.WaitAsync(token); return new Lease(this, item, entry); }
        catch { Release(item, entry, false); throw; }
    }
    private void Release(string item, Entry entry, bool held)
    {
        lock (gate)
        {
            if (held) entry.Gate.Release();
            if (--entry.Users == 0) { entries.Remove(item); entry.Gate.Dispose(); }
        }
    }
    private sealed class Lease(CustodyItemLocks owner, string item, Entry entry) : IDisposable
    {
        private int disposed;
        public void Dispose() { if (Interlocked.Exchange(ref disposed, 1) == 0) owner.Release(item, entry, true); }
    }
}

namespace MarketplaceCore.Services.Custody;

public sealed class CustodyWorkQueue(int maximumWaiting = 1024, int parallelism = 1)
{
    private readonly object gate = new();
    private readonly LinkedList<TaskCompletionSource<IDisposable>> continuing = new();
    private readonly LinkedList<TaskCompletionSource<IDisposable>> opening = new();
    private int active;
    public (int Active, int Waiting) Snapshot() { lock (gate) return (active, continuing.Count + opening.Count); }
    public async Task<IDisposable> EnterAsync(bool continuation, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        TaskCompletionSource<IDisposable> source;
        LinkedList<TaskCompletionSource<IDisposable>> list;
        LinkedListNode<TaskCompletionSource<IDisposable>> node;
        lock (gate)
        {
            if (active < parallelism) { active++; return new Lease(this); }
            if (continuing.Count + opening.Count >= maximumWaiting) throw new InvalidOperationException("custody_busy");
            source = new(TaskCreationOptions.RunContinuationsAsynchronously);
            list = continuation ? continuing : opening;
            node = list.AddLast(source);
        }
        using var cancelled = token.Register(() =>
        {
            lock (gate)
                if (node.List != null) { list.Remove(node); source.TrySetCanceled(token); }
        });
        return await source.Task;
    }
    private void Exit()
    {
        lock (gate)
        {
            var list = continuing.Count > 0 ? continuing : opening;
            if (list.First is not { } node) { active--; return; }
            list.RemoveFirst(); node.Value.SetResult(new Lease(this));
        }
    }
    private sealed class Lease(CustodyWorkQueue owner) : IDisposable
    {
        private CustodyWorkQueue? held = owner;
        public void Dispose() => Interlocked.Exchange(ref held, null)?.Exit();
    }
}


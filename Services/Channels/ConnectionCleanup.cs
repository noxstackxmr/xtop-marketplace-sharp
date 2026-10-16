using MarketplaceCore.Hubs;
using MarketplaceCore.Services.Indexer;
using Microsoft.AspNetCore.SignalR;

namespace MarketplaceCore.Services.Channels;

public sealed class ConnectionCleanup(RelayState state, IHubContext<CommunicationHub> hub,
    TimeProvider clock, ILogger<ConnectionCleanup> logger, IListingDirectory listings) : BackgroundService
{
    protected override Task ExecuteAsync(CancellationToken stoppingToken)
        => Task.WhenAll(Cleanup(stoppingToken), CheckSellers(stoppingToken));

    private async Task CheckSellers(CancellationToken token)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(30), clock);
        while (await timer.WaitForNextTickAsync(token))
            await Parallel.ForEachAsync(state.Sellers(), new ParallelOptions { MaxDegreeOfParallelism = 8, CancellationToken = token }, async (seller, ct) =>
            {
                try
                {
                    if (await listings.SellerAsync(seller.Owner, ct) == null) state.RevokeSeller(seller.Id);
                }
                catch (Exception e) when (!ct.IsCancellationRequested)
                {
                    // An unavailable indexer is not proof that a seller lost their listings.
                    logger.LogDebug(e, "seller eligibility check unavailable");
                }
            });
    }

    private async Task Cleanup(CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(5), clock);
        while (await timer.WaitForNextTickAsync(stoppingToken))
        {
            var expired = state.Sweep();
            foreach (var abort in expired.Aborts) abort();
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken);
            timeout.CancelAfter(TimeSpan.FromSeconds(5));
            try
            {
                await Task.WhenAll(expired.Notifications.Select(d =>
                    hub.Clients.Client(d.ConnectionId).SendAsync("ChannelClosed", d.Payload, timeout.Token)));
            }
            catch (OperationCanceledException) when (!stoppingToken.IsCancellationRequested)
            {
                logger.LogWarning("channel close notification timed out");
            }
        }
    }
}

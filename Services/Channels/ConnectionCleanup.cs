using MarketplaceCore.Hubs;
using Microsoft.AspNetCore.SignalR;

namespace MarketplaceCore.Services.Channels;

public sealed class ConnectionCleanup(RelayState state, IHubContext<CommunicationHub> hub,
    TimeProvider clock, ILogger<ConnectionCleanup> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
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

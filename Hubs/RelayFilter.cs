using System.Text.Json;
using MarketplaceCore.Services.Channels;
using Microsoft.AspNetCore.SignalR;

namespace MarketplaceCore.Hubs;

public sealed class RelayFilter(RelayState state) : IHubFilter
{
    public async ValueTask<object?> InvokeMethodAsync(HubInvocationContext context,
        Func<HubInvocationContext, ValueTask<object?>> next)
    {
        try
        {
            state.CheckRate(context.Context.ConnectionId);
            return await next(context);
        }
        catch (RelayException exception)
        {
            if (exception.Message == "connection_expired") context.Context.Abort();
            throw new HubException(exception.Message);
        }
        catch (FormatException) { throw new HubException("invalid_input"); }
        catch (Exception exception) when (exception is HttpRequestException or JsonException or InvalidDataException)
        {
            throw new HubException("indexer_unavailable");
        }
        catch (OperationCanceledException) { throw new HubException("request_timeout"); }
    }
}

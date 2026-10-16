using System.Threading.RateLimiting;
using System.Net;
using MarketplaceCore.Crypto;
using MarketplaceCore.Hubs;
using MarketplaceCore.Options;
using MarketplaceCore.Services.Channels;
using MarketplaceCore.Services.Indexer;
using MarketplaceCore.Services.Custody;
using Microsoft.AspNetCore.Http.Connections;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.AspNetCore.SignalR;
using Microsoft.Extensions.Options;

namespace MarketplaceCore;

public static class MarketplaceApplication
{
    public static WebApplication Build(string[] args, Action<WebApplicationBuilder>? configure = null)
    {
        var builder = WebApplication.CreateBuilder(args);
        builder.Services.AddControllers().AddApplicationPart(typeof(MarketplaceApplication).Assembly);
        builder.Services.AddProblemDetails();
        builder.Services.AddOptions<MarketplaceOptions>().BindConfiguration("Marketplace")
            .ValidateDataAnnotations()
            .Validate(o => o.Network is "mainnet" or "testnet" or "stagenet" or "fakechain", "invalid network")
            .Validate(o => IsOrigin(o.PublicOrigin), "invalid public origin")
            .Validate(o => Uri.TryCreate(o.IndexerUrl, UriKind.Absolute, out var uri) && uri.Scheme is "http" or "https" &&
                uri.UserInfo == "" && uri.Query == "" && uri.Fragment == "", "invalid indexer URL")
            .Validate(o => o.AllowedOrigins.All(IsOrigin), "invalid allowed origin")
            .ValidateOnStart();
        builder.Services.AddOptions<ChannelOptions>().BindConfiguration("Channels").ValidateDataAnnotations().ValidateOnStart();
        builder.Services.AddOptions<CustodyOptions>().BindConfiguration("Custody").ValidateDataAnnotations()
            .Validate(o => o.MaximumRetainedSessions > o.MaximumSessions + o.ParallelTrades, "retain extra capacity for cancellation and receipt recovery")
            .Validate(o => o.SignerMemorySoftLimitBytes == 0 || !string.IsNullOrWhiteSpace(o.MemoryUsageFile), "memory limit requires service memory usage file")
            .Validate(o => !o.Enabled || o.SignerMemorySoftLimitBytes == 0 || ReadableMemoryUsage(o.MemoryUsageFile), "memory usage file must be readable and contain a non-negative byte count")
            .ValidateOnStart();
        builder.Services.AddSingleton(TimeProvider.System);
        builder.Services.AddSingleton<CustodyKeys>();
        builder.Services.AddSingleton<CustodyProofs>();
        builder.Services.AddSingleton<CustodyJournal>();
        builder.Services.AddSingleton<CustodyResources>();
        builder.Services.AddSingleton<CustodySettlement>();
        builder.Services.AddHostedService(s => s.GetRequiredService<CustodySettlement>());
        builder.Services.AddSingleton<ICustodySignerFactory, CustodySignerFactory>();
        builder.Services.AddSingleton<CustodySessions>();
        builder.Services.AddHostedService(services => services.GetRequiredService<CustodySessions>());
        builder.Services.AddHttpClient<ICustodyDirectory, CustodyDirectory>((services, http) =>
        {
            var options = services.GetRequiredService<IOptions<MarketplaceOptions>>().Value;
            http.BaseAddress = new Uri(options.IndexerUrl.TrimEnd('/') + "/");
            http.Timeout = TimeSpan.FromSeconds(options.RequestTimeoutSeconds);
            http.MaxResponseContentBufferSize = 131072;
        }).ConfigurePrimaryHttpMessageHandler(() => new HttpClientHandler { AllowAutoRedirect = false });
        builder.Services.AddHttpClient<ICustodySubmissionNode, CustodySubmissionNode>((services, http) =>
        {
            var options = services.GetRequiredService<IOptions<CustodyOptions>>().Value;
            http.BaseAddress = new Uri(options.RpcUrl.TrimEnd('/') + "/");
            http.Timeout = TimeSpan.FromSeconds(options.SubmissionTimeoutSeconds);
            http.MaxResponseContentBufferSize = 262144;
        }).ConfigurePrimaryHttpMessageHandler(() => new HttpClientHandler { AllowAutoRedirect = false });
        builder.Services.AddHttpClient<ICustodyNode, CustodyNode>((services, http) =>
        {
            var options = services.GetRequiredService<IOptions<CustodyOptions>>().Value;
            http.BaseAddress = new Uri(options.RpcUrl.TrimEnd('/') + "/");
            http.Timeout = TimeSpan.FromSeconds(15);
            http.MaxResponseContentBufferSize = 131072;
        }).ConfigurePrimaryHttpMessageHandler(() => new HttpClientHandler { AllowAutoRedirect = false });
        builder.Services.AddSingleton<RelayState>();
        builder.Services.AddSingleton<RelayAdmission>();
        builder.Services.AddHostedService<ConnectionCleanup>();
        builder.Services.AddHttpClient<IListingDirectory, ListingDirectory>((services, http) =>
        {
            var options = services.GetRequiredService<IOptions<MarketplaceOptions>>().Value;
            http.BaseAddress = new Uri(options.IndexerUrl.TrimEnd('/') + "/");
            http.Timeout = TimeSpan.FromSeconds(options.RequestTimeoutSeconds);
            http.MaxResponseContentBufferSize = 65536;
        }).ConfigurePrimaryHttpMessageHandler(() => new HttpClientHandler { AllowAutoRedirect = false });
        builder.Services.AddSignalR(options =>
        {
            options.EnableDetailedErrors = false;
            options.MaximumParallelInvocationsPerClient = 1;
            options.KeepAliveInterval = TimeSpan.FromSeconds(10);
            options.ClientTimeoutInterval = TimeSpan.FromSeconds(30);
            options.AddFilter<RelayFilter>();
        });
        builder.Services.AddOptions<HubOptions>().Configure<IOptions<ChannelOptions>>((hub, options) =>
            hub.MaximumReceiveMessageSize = options.Value.MaximumMessageBytes * 2 + 4096);
        builder.Services.AddCors();
        builder.Services.AddRateLimiter(options =>
        {
            options.RejectionStatusCode = 429;
            options.OnRejected = async (context, token) =>
            {
                context.HttpContext.Response.Headers.RetryAfter = "2";
                await context.HttpContext.Response.WriteAsJsonAsync(new { error = "service_busy" }, token);
            };
            options.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(context =>
            {
                var custody = context.RequestServices.GetRequiredService<IOptions<CustodyOptions>>().Value;
                var channels = context.RequestServices.GetRequiredService<IOptions<ChannelOptions>>().Value;
                var path = context.Request.Path;
                var bucket = path.StartsWithSegments("/hubs") ? "relay" : path.Value?.EndsWith("/messages", StringComparison.Ordinal) == true
                    ? "transactions" : path.StartsWithSegments("/api/custody/sessions") ? "opening" : "reads";
                return RateLimitPartition.GetConcurrencyLimiter(bucket, _ => new ConcurrencyLimiterOptions
                {
                    PermitLimit = bucket == "relay" ? channels.MaximumConnections : custody.MaximumHttpRequests,
                    QueueLimit = bucket == "relay" ? 0 : custody.MaximumQueuedRequests, QueueProcessingOrder = QueueProcessingOrder.OldestFirst
                });
            });
            options.AddPolicy("http", context => RateLimitPartition.GetFixedWindowLimiter(
                (context.Connection.RemoteIpAddress?.ToString() ?? "unknown") + (context.Request.Path.StartsWithSegments("/api/custody/sessions") ? ":trade" : ":read"),
                _ => new FixedWindowRateLimiterOptions
                { PermitLimit = context.RequestServices.GetRequiredService<IOptions<CustodyOptions>>().Value.HttpRequestsPerMinutePerIp, Window = TimeSpan.FromMinutes(1), QueueLimit = 0 }));
            options.AddPolicy("admission", context => RateLimitPartition.GetFixedWindowLimiter(
                context.Connection.RemoteIpAddress?.ToString() ?? "unknown",
                _ => new FixedWindowRateLimiterOptions { PermitLimit = 30, Window = TimeSpan.FromMinutes(1), QueueLimit = 0 }));
        });
        configure?.Invoke(builder);
        var app = builder.Build();
        var marketplace = app.Services.GetRequiredService<IOptions<MarketplaceOptions>>().Value;
        var channels = app.Services.GetRequiredService<IOptions<ChannelOptions>>().Value;
        _ = app.Services.GetRequiredService<CustodyKeys>();
        if (!OwnerSignature.IsOwner("5866666666666666666666666666666666666666666666666666666666666666"))
            throw new InvalidOperationException("native signature verification unavailable");
        app.UseExceptionHandler();
        if (marketplace.TrustLoopbackProxy)
        {
            var forwarding = new ForwardedHeadersOptions
            {
                ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto,
                ForwardLimit = 1
            };
            forwarding.KnownIPNetworks.Clear();
            forwarding.KnownProxies.Clear();
            forwarding.KnownProxies.Add(IPAddress.Loopback);
            forwarding.KnownProxies.Add(IPAddress.IPv6Loopback);
            app.UseForwardedHeaders(forwarding);
        }
        app.Use(async (context, next) =>
        {
            if (!context.Request.IsHttps && !app.Environment.IsDevelopment())
            {
                context.Response.StatusCode = 400;
                await context.Response.WriteAsJsonAsync(new { error = "https_required" });
                return;
            }
            if (context.Request.Headers.TryGetValue("Origin", out var origin) &&
                !marketplace.AllowedOrigins.Contains(origin.ToString(), StringComparer.Ordinal))
            {
                context.Response.StatusCode = 403;
                return;
            }
            await next(context);
        });
        app.UseCors(policy =>
        {
            if (marketplace.AllowedOrigins.Length > 0)
                policy.WithOrigins(marketplace.AllowedOrigins).WithMethods("GET", "POST").AllowAnyHeader();
        });
        app.UseRateLimiter();
        app.Use(async (context, next) =>
        {
            if (context.Request.Path.StartsWithSegments("/hubs/communication"))
            {
                var grant = context.RequestServices.GetRequiredService<RelayAdmission>().Consume(context.Request.Query["ticket"].ToString());
                if (grant == null)
                {
                    context.Response.StatusCode = 403;
                    await context.Response.WriteAsJsonAsync(new { error = "admission_required" });
                    return;
                }
                context.Items[RelayAdmission.ContextKey] = grant;
            }
            await next(context);
        });
        app.MapControllers();
        app.MapHub<CommunicationHub>("/hubs/communication", options =>
        {
            options.Transports = HttpTransportType.WebSockets;
            options.ApplicationMaxBufferSize = channels.MaximumMessageBytes * 2 + 4096;
            options.TransportMaxBufferSize = channels.MaximumMessageBytes * 2 + 4096;
        }).RequireRateLimiting("http");
        return app;
    }

    private static bool ReadableMemoryUsage(string path)
    {
        try { return Path.IsPathFullyQualified(path) && long.TryParse(File.ReadAllText(path).Trim(), out var bytes) && bytes >= 0; }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or ArgumentException) { return false; }
    }

    private static bool IsOrigin(string value)
        => Uri.TryCreate(value, UriKind.Absolute, out var uri) &&
            (uri.Scheme == "https" || (uri.Scheme == "http" && uri.IsLoopback)) &&
            uri.UserInfo == "" && uri.AbsolutePath == "/" && uri.Query == "" && uri.Fragment == "" &&
            value == uri.GetLeftPart(UriPartial.Authority);
}

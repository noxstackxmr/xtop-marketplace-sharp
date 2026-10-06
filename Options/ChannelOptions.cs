using System.ComponentModel.DataAnnotations;

namespace MarketplaceCore.Options;

public sealed class ChannelOptions
{
    [Range(1, 120)] public int LifetimeMinutes { get; set; } = 30;
    [Range(1, 512)] public int MaximumMessages { get; set; } = 128;
    [Range(1024, 262144)] public int MaximumMessageBytes { get; set; } = 65536;
    [Range(1, 32)] public int MaximumOpenChannelsPerBuyer { get; set; } = 8;
    [Range(15, 120)] public int PresenceTimeoutSeconds { get; set; } = 45;
    [Range(10, 120)] public int AcceptTimeoutSeconds { get; set; } = 30;
    [Range(1, 8)] public int MaximumConnectionsPerOwner { get; set; } = 3;
    [Range(8, 4096)] public int MaximumConnections { get; set; } = 512;
    [Range(1, 64)] public int MaximumConnectionsPerIp { get; set; } = 16;
    [Range(8, 4096)] public int MaximumChannels { get; set; } = 512;
}

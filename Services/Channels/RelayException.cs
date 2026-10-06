namespace MarketplaceCore.Services.Channels;

public sealed class RelayException(string code) : Exception(code);

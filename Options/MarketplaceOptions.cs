using System.ComponentModel.DataAnnotations;

namespace MarketplaceCore.Options;

public sealed class MarketplaceOptions
{
    [Required] public string Network { get; set; } = "fakechain";
    [Required, RegularExpression("^[0-9a-f]{64}$")] public string Id { get; set; } = "";
    [Required] public string PublicOrigin { get; set; } = "";
    [Required] public string IndexerUrl { get; set; } = "";
    public string[] AllowedOrigins { get; set; } = [];
    public bool TrustLoopbackProxy { get; set; }
    [Range(1, 60)] public int RequestTimeoutSeconds { get; set; } = 15;
    public byte NetworkId => Network switch
    {
        "mainnet" => 0, "testnet" => 1, "stagenet" => 2, "fakechain" => 255,
        _ => throw new InvalidOperationException("unsupported network")
    };
}

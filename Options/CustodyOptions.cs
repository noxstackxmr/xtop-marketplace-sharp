using System.ComponentModel.DataAnnotations;

namespace MarketplaceCore.Options;

public sealed class CustodyOptions
{
    public bool Enabled { get; set; }
    public bool TestKeys { get; set; }
    public string SpendSecret { get; set; } = "";
    public string ViewSecret { get; set; } = "";
    public string OwnerSecret { get; set; } = "";
    public string RpcUrl { get; set; } = "http://127.0.0.1:18081/";
    public string GenesisHash { get; set; } = "";
    public string SignerPath { get; set; } = "";
    public string JournalDirectory { get; set; } = "data/custody";
    [Range(1, 128)] public int MaximumSessions { get; set; } = 16;
    [Range(1, 30)] public int SessionMinutes { get; set; } = 5;
    [Range(5, 120)] public int SignerTimeoutSeconds { get; set; } = 60;
}

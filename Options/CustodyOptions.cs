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
    [Range(1, 4096)] public int MaximumSessions { get; set; } = 128;
    [Range(1, 64)] public int MaximumSessionsPerOwner { get; set; } = 4;
    [Range(1, 16384)] public int MaximumRetainedSessions { get; set; } = 512;
    [Range(1, 256)] public int ParallelTrades { get; set; } = 8;
    [Range(1, 10000)] public int MaximumQueuedRequests { get; set; } = 512;
    [Range(1, 4096)] public int MaximumHttpRequests { get; set; } = 128;
    [Range(30, 60000)] public int HttpRequestsPerMinutePerIp { get; set; } = 600;
    [Range(1, 4096)] public int MaximumSignerProcesses { get; set; } = 32;
    public string MemoryUsageFile { get; set; } = "";
    [Range(0, long.MaxValue)] public long SignerMemorySoftLimitBytes { get; set; }
    [Range(1, 32)] public int ParallelSubmissions { get; set; } = 2;
    [Range(1, 256)] public int SubmissionBatchSize { get; set; } = 16;
    [Range(1, 60)] public int SubmissionRetrySeconds { get; set; } = 5;
    [Range(15, 3600)] public int ConfirmedRecheckSeconds { get; set; } = 300;
    [Range(5, 60)] public int SubmissionTimeoutSeconds { get; set; } = 10;
    [Range(1, 30)] public int SessionMinutes { get; set; } = 5;
    [Range(5, 120)] public int SignerTimeoutSeconds { get; set; } = 60;
}

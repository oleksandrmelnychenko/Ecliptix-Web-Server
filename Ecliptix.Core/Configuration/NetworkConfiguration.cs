namespace Ecliptix.Core.Configuration;

public sealed class NetworkConfiguration
{
    public const string SectionName = "Network";

    public PortsConfiguration Ports { get; set; } = new();

    public LimitsConfiguration Limits { get; set; } = new();

    public RateLimitConfiguration RateLimit { get; set; } = new();

    public CompressionConfiguration Compression { get; set; } = new();
}

public sealed class PortsConfiguration
{
    public int Grpc { get; set; } = 5051;

    public int Http { get; set; } = 8080;
}

public sealed class LimitsConfiguration
{
    public int MaxConcurrentConnections { get; set; } = 1000;

    public int MaxConcurrentUpgradedConnections { get; set; } = 1000;

    public long MaxRequestBodySizeBytes { get; set; } = 10 * 1024 * 1024;
}

public sealed class RateLimitConfiguration
{
    public int PermitLimit { get; set; } = 100;

    public int WindowMinutes { get; set; } = 1;

    public int SegmentsPerWindow { get; set; } = 4;

    public int QueueLimit { get; set; } = 10;
}

public sealed class CompressionConfiguration
{
    public string Algorithm { get; set; } = "gzip";
}

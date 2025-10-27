namespace Ecliptix.Utilities.Configuration;

public sealed class CryptographicParameters
{
    public int Argon2MemorySize { get; set; } = 262144;

    public int Argon2Iterations { get; set; } = 4;

    public int Argon2DegreeOfParallelism { get; set; } = 4;

    public int EnhancedKeyOutputLength { get; set; } = 64;

    public int MasterKeySize { get; set; } = 32;

    public int DefaultThreshold { get; set; } = 3;

    public int DefaultTotalShares { get; set; } = 5;

    public int AskTimeoutSeconds { get; set; } = 30;


    public TimeSpan AskTimeout => TimeSpan.FromSeconds(AskTimeoutSeconds);
}

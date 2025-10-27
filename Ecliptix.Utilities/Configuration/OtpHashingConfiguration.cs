namespace Ecliptix.Utilities.Configuration;

public sealed class OtpHashingConfiguration
{
    public int SaltSize { get; set; } = 32;

    public int Pbkdf2Iterations { get; set; } = 100000;

    public int HashOutputLength { get; set; } = 32;
}

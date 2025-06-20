namespace Ecliptix.Core.AuthenticationSystem;

public class AkeServerState
{
    public byte[] ServerEphemeralPrivateKeyBytes { get; set; }
    public byte[] ServerEphemeralPublicKey { get; set; }
    public byte[] ClientStaticPublicKey { get; set; }
    public byte[] OprfResponse { get; set; }
    public string Username { get; set; }
    public byte[] RegistrationRecord { get; set; }
    public DateTimeOffset Expiration { get; set; }
}

public class AkePasswordResetState
{
    public string Username { get; set; }
    public string ResetToken { get; set; }
    public DateTimeOffset Expiration { get; set; }
}
namespace Ecliptix.Core.Infrastructure.Grpc.Routing.Providers;

/// <summary>
/// Constants for device provisioning cryptographic operations and validation.
/// </summary>
public static class DeviceProvisioningConstants
{
    public static class Proof
    {
        /// <summary>Required length for HMAC proof in bytes (SHA-256 output).</summary>
        public const int Length = 32;
    }

    public static class Nonce
    {
        /// <summary>Minimum allowed nonce length in bytes.</summary>
        public const int MinLength = 16;

        /// <summary>Maximum allowed nonce length in bytes.</summary>
        public const int MaxLength = 64;

        /// <summary>Server nonce length in bytes.</summary>
        public const int ServerLength = 32;
    }

    public static class ReplayProtection
    {
        /// <summary>Scope identifier for authenticated establish replay protection.</summary>
        public const string AuthenticatedEstablishScope = "device_provisioning.auth_establish";

        /// <summary>Time-to-live for authenticated establish replay entries.</summary>
        public static readonly TimeSpan AuthenticatedEstablishTtl = TimeSpan.FromMinutes(5);

        /// <summary>Time-to-live for server nonce entries.</summary>
        public static readonly TimeSpan ServerNonceTtl = TimeSpan.FromMinutes(5);
    }

    public static class Identity
    {
        /// <summary>Required length for membership and account identifiers in bytes (GUID size).</summary>
        public const int IdentifierLength = 16;
    }
}

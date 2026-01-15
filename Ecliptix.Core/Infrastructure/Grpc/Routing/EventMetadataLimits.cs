namespace Ecliptix.Core.Infrastructure.Grpc.Routing;

/// <summary>
/// Maximum length limits for event metadata fields in gRPC requests.
/// Used for validation to prevent oversized payloads.
/// </summary>
public static class EventMetadataLimits
{
    /// <summary>Maximum length for event ID field.</summary>
    public const int MaxEventIdLength = 128;

    /// <summary>Maximum length for request ID field.</summary>
    public const int MaxRequestIdLength = 128;

    /// <summary>Maximum length for platform identifier.</summary>
    public const int MaxPlatformLength = 64;

    /// <summary>Maximum length for version string.</summary>
    public const int MaxVersionLength = 32;

    /// <summary>Maximum length for device ID (app device identifier).</summary>
    public const int MaxAppDeviceLength = 128;

    /// <summary>Maximum length for application instance identifier.</summary>
    public const int MaxApplicationInstanceLength = 128;

    /// <summary>Maximum length for locale string.</summary>
    public const int MaxLocaleLength = 16;

    /// <summary>Maximum length for tenant identifier.</summary>
    public const int MaxTenantLength = 64;

    /// <summary>Maximum length for idempotency key pattern.</summary>
    public const int MaxIdempotencyKeyLength = 128;
}

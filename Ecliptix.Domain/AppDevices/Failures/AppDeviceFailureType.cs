namespace Ecliptix.Domain.AppDevices.Failures;

/// <summary>
///     Defines the specific types of failures that can occur within the AppDevice domain.
///     Each member represents a distinct, actionable problem category.
/// </summary>
public enum AppDeviceFailureType
{
    /// <summary>
    ///     Indicates a failure in a downstream service or infrastructure component, such as the database,
    ///     a message queue, or a network call. These are often transient and may be recoverable.
    ///     Corresponds to a 503 Service Unavailable or Unavailable.
    /// </summary>
    InfrastructureFailure,

    /// <summary>
    ///     An unexpected and unhandled error occurred within the application logic.
    ///     This represents a potential bug that should be logged with high severity and investigated.
    ///     Corresponds to a 500 Internal Server Error or Internal.
    /// </summary>
    InternalError
}
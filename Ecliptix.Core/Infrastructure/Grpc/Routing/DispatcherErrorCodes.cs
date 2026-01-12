namespace Ecliptix.Core.Infrastructure.Grpc.Routing;

internal static class DispatcherErrorCodes
{
    public const string StatusOk = "OK";
    public const string StatusError = "ERR";

    public const string RouteNotFound = "route_not_found";
    public const string RouteMissingEventType = "route_missing_event_type";

    public const string DeserializeFailed = "deserialize_failed";
    public const string SerializeFailed = "serialize_failed";
    public const string HandlerFailed = "handler_failed";

    public const string DeliveryKindRequired = "delivery_kind_required";
    public const string ContextRequired = "context_required";
    public const string ContextMismatch = "context_mismatch";
    public const string ConnectIdRequired = "connect_id_required";

    public const string EventIdTooLong = "event_id_too_long";
    public const string RequestIdTooLong = "request_id_too_long";
    public const string PlatformTooLong = "platform_too_long";
    public const string VersionTooLong = "version_too_long";
    public const string AppDeviceIdTooLong = "app_device_id_too_long";
    public const string ApplicationInstanceIdTooLong = "application_instance_id_too_long";
    public const string LocaleTooLong = "locale_too_long";
    public const string TenantTooLong = "tenant_too_long";

    public const string IdempotencyRequired = "idempotency_required";
    public const string IdempotencyInvalid = "idempotency_invalid";
}

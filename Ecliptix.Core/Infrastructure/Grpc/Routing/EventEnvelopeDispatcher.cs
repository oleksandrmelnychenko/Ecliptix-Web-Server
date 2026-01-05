using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using Ecliptix.Protobuf.Transport.Common;
using Ecliptix.SharedKernel;
using Google.Protobuf;
using Microsoft.Extensions.Logging;

namespace Ecliptix.Core.Infrastructure.Grpc.Routing;

/// <summary>
/// Centralizes envelope routing: resolve route, deserialize payload, invoke handler, serialize response.
/// </summary>
public sealed class EventEnvelopeDispatcher
{
    private readonly IEventRouteResolver _resolver;
    private readonly ILogger<EventEnvelopeDispatcher> _logger;
    private static readonly HashSet<string> IdempotencyRequiredEvents = new(StringComparer.OrdinalIgnoreCase)
    {
        "IdentityAccessRegistrationInit",
        "IdentityAccessRegistrationComplete",
        "IdentityAccessRecoveryInit",
        "IdentityAccessRecoveryComplete",
        "IdentityAccessSignInInit",
        "IdentityAccessSignInComplete",
        "IdentityAccessLogout",
        "IdentityAccessLogoutAnonymous",
        "DeviceProvisioningRegisterDevice",
        "DeviceProvisioningSecureChannelEstablish",
        "DeviceProvisioningSecureChannelRestore",
        "DeviceProvisioningSecureChannelAuthEstablish"
    };
    private static readonly Regex IdempotencyPattern = new("^[A-Za-z0-9._:-]{1,128}$", RegexOptions.Compiled);
    private const int MaxEventIdLength = 128;
    private const int MaxEventTypeLength = 128;
    private const int MaxContextLength = 64;
    private const int MaxRequestIdLength = 128;
    private const int MaxPlatformLength = 64;
    private const int MaxVersionLength = 32;
    private const int MaxAppDeviceLength = 128;
    private const int MaxApplicationInstanceLength = 128;
    private const int MaxLocaleLength = 16;
    private const int MaxTenantLength = 64;

    public EventEnvelopeDispatcher(IEventRouteResolver resolver, ILogger<EventEnvelopeDispatcher> logger)
    {
        _resolver = resolver;
        _logger = logger;
    }

    public async Task<EventEnvelope> DispatchAsync(EventEnvelope envelope, CancellationToken cancellationToken)
    {
        EventMetadata metadata = EnsureMetadata(envelope.Metadata);

        EventEnvelope? validationError = ValidateMetadata(metadata);
        if (validationError is not null)
        {
            return validationError;
        }

        if (!_resolver.TryGetRoute(metadata.EventType, out EventRoute route))
        {
            return BuildErrorEnvelope(metadata, "route_not_found", $"No route registered for eventType '{metadata.EventType}'");
        }

        if (string.IsNullOrWhiteSpace(metadata.Context))
        {
            metadata.Context = route.Context;
        }

        EventEnvelope? missingRequired = EnsureRequiredTransportMetadata(metadata, route);
        if (missingRequired is not null)
        {
            return missingRequired;
        }

        EventEnvelope? idempotencyError = EnsureIdempotency(metadata);
        if (idempotencyError is not null)
        {
            return idempotencyError;
        }

        LogIdempotencyIfMissing(metadata);

        object message;
        try
        {
            message = route.Deserialize(envelope.Payload.Memory);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to deserialize payload for eventType {EventType}", metadata.EventType);
            return BuildErrorEnvelope(metadata, "deserialize_failed", "Could not deserialize payload");
        }

        Result<object, FailureBase> result;
        try
        {
            result = await route.HandleAsync(message, metadata, cancellationToken);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unhandled exception in handler for eventType {EventType}", metadata.EventType);
            return BuildErrorEnvelope(metadata, "handler_failed", "An error occurred while handling the request");
        }

        if (result.IsOk)
        {
            object response = result.Unwrap();

            try
            {
                ReadOnlyMemory<byte> serialized = route.Serialize(response);
                return new EventEnvelope
                {
                    Metadata = BuildResponseMetadata(metadata, status: "OK", errorCode: string.Empty, userMessage: string.Empty),
                    Payload = ByteString.CopyFrom(serialized.Span)
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to serialize response for eventType {EventType}", metadata.EventType);
                return BuildErrorEnvelope(metadata, "serialize_failed", "Could not serialize response payload");
            }
        }

        FailureBase failure = result.UnwrapErr();
        GrpcErrorDescriptor descriptor = failure.ToGrpcDescriptor();
        _logger.LogWarning("Route failed for eventType {EventType}: {ErrorCode} - {Message}", metadata.EventType,
            descriptor.ErrorCode, failure.Message);

        return new EventEnvelope
        {
            Metadata = BuildResponseMetadata(metadata, status: "ERR", errorCode: descriptor.ErrorCode.ToString(),
                userMessage: failure.Message),
            Payload = ByteString.Empty
        };
    }

    private static EventMetadata EnsureMetadata(EventMetadata? incoming)
    {
        EventMetadata metadata = incoming ?? new EventMetadata();
        if (string.IsNullOrWhiteSpace(metadata.EventId))
        {
            metadata.EventId = Guid.NewGuid().ToString("N");
        }

        return metadata;
    }

    private EventEnvelope? ValidateMetadata(EventMetadata metadata)
    {
        if (string.IsNullOrWhiteSpace(metadata.EventType))
        {
            return BuildErrorEnvelope(metadata, "route_missing_event_type", "EventType is required");
        }

        if (metadata.EventId?.Length > MaxEventIdLength)
        {
            return BuildErrorEnvelope(metadata, "event_id_too_long", $"event_id must be <= {MaxEventIdLength} chars");
        }

        if (metadata.EventType?.Length > MaxEventTypeLength)
        {
            return BuildErrorEnvelope(metadata, "event_type_too_long", $"event_type must be <= {MaxEventTypeLength} chars");
        }

        if (!string.IsNullOrWhiteSpace(metadata.Context) && metadata.Context.Length > MaxContextLength)
        {
            return BuildErrorEnvelope(metadata, "context_too_long", $"context must be <= {MaxContextLength} chars");
        }

        if (!string.IsNullOrWhiteSpace(metadata.RequestId) && metadata.RequestId.Length > MaxRequestIdLength)
        {
            return BuildErrorEnvelope(metadata, "request_id_too_long", $"request_id must be <= {MaxRequestIdLength} chars");
        }

        if (!string.IsNullOrWhiteSpace(metadata.Platform) && metadata.Platform.Length > MaxPlatformLength)
        {
            return BuildErrorEnvelope(metadata, "platform_too_long", $"platform must be <= {MaxPlatformLength} chars");
        }

        if (!string.IsNullOrWhiteSpace(metadata.Version) && metadata.Version.Length > MaxVersionLength)
        {
            return BuildErrorEnvelope(metadata, "version_too_long", $"version must be <= {MaxVersionLength} chars");
        }

        if (!string.IsNullOrWhiteSpace(metadata.AppDeviceId) && metadata.AppDeviceId.Length > MaxAppDeviceLength)
        {
            return BuildErrorEnvelope(metadata, "app_device_id_too_long", $"app_device_id must be <= {MaxAppDeviceLength} chars");
        }

        if (!string.IsNullOrWhiteSpace(metadata.ApplicationInstanceId) && metadata.ApplicationInstanceId.Length > MaxApplicationInstanceLength)
        {
            return BuildErrorEnvelope(metadata, "application_instance_id_too_long", $"application_instance_id must be <= {MaxApplicationInstanceLength} chars");
        }

        if (!string.IsNullOrWhiteSpace(metadata.Locale) && metadata.Locale.Length > MaxLocaleLength)
        {
            return BuildErrorEnvelope(metadata, "locale_too_long", $"locale must be <= {MaxLocaleLength} chars");
        }

        if (!string.IsNullOrWhiteSpace(metadata.Tenant) && metadata.Tenant.Length > MaxTenantLength)
        {
            return BuildErrorEnvelope(metadata, "tenant_too_long", $"tenant must be <= {MaxTenantLength} chars");
        }

        return null;
    }

    private EventEnvelope? EnsureRequiredTransportMetadata(EventMetadata metadata, EventRoute route)
    {
        if (RequiresConnectId(route.Context))
        {
            // Prefer explicit connect_id, fallback to partition_key if present.
            if (metadata.ConnectId == 0 && uint.TryParse(metadata.PartitionKey, out uint parsed))
            {
                metadata.ConnectId = parsed;
            }

            if (metadata.ConnectId == 0)
            {
                return BuildErrorEnvelope(metadata, "connect_id_required",
                    $"connect_id is required for context '{route.Context}'");
            }

            if (string.IsNullOrWhiteSpace(metadata.PartitionKey))
            {
                metadata.PartitionKey = metadata.ConnectId.ToString();
            }
        }

        return null;
    }

    private static bool RequiresConnectId(string context) =>
        !string.IsNullOrWhiteSpace(context) &&
        (context.Equals("identity_access", StringComparison.OrdinalIgnoreCase) ||
         context.Equals("device_provisioning", StringComparison.OrdinalIgnoreCase));

    private EventEnvelope? EnsureIdempotency(EventMetadata metadata)
    {
        if (RequiresIdempotency(metadata.EventType) && string.IsNullOrWhiteSpace(metadata.IdempotencyKey))
        {
            return BuildErrorEnvelope(metadata, "idempotency_required",
                $"idempotency_key is required for eventType '{metadata.EventType}'");
        }

        if (!string.IsNullOrWhiteSpace(metadata.IdempotencyKey) && !IdempotencyPattern.IsMatch(metadata.IdempotencyKey))
        {
            return BuildErrorEnvelope(metadata, "idempotency_invalid",
                "idempotency_key must be 1-128 chars of [A-Za-z0-9._:-]");
        }

        return null;
    }

    private static bool RequiresIdempotency(string? eventType)
    {
        return !string.IsNullOrWhiteSpace(eventType) && IdempotencyRequiredEvents.Contains(eventType);
    }

    private void LogIdempotencyIfMissing(EventMetadata metadata)
    {
        if (string.IsNullOrWhiteSpace(metadata.IdempotencyKey))
        {
            _logger.LogDebug("No idempotency key provided for eventType {EventType} in context {Context}", metadata.EventType, metadata.Context);
        }
    }

    private static EventMetadata BuildResponseMetadata(EventMetadata requestMetadata, string status, string errorCode,
        string userMessage)
    {
        return new EventMetadata
        {
            EventId = requestMetadata.EventId ?? Guid.NewGuid().ToString("N"),
            EventType = !string.IsNullOrWhiteSpace(requestMetadata.ResponseType)
                ? requestMetadata.ResponseType
                : requestMetadata.EventType,
            EventVersion = requestMetadata.ResponseVersion != 0
                ? requestMetadata.ResponseVersion
                : requestMetadata.EventVersion,
            Context = requestMetadata.Context,
            CorrelationId = string.IsNullOrWhiteSpace(requestMetadata.CorrelationId)
                ? requestMetadata.EventId
                : requestMetadata.CorrelationId,
            CausationId = requestMetadata.EventId,
            PartitionKey = requestMetadata.PartitionKey,
            Locale = requestMetadata.Locale,
            Tenant = requestMetadata.Tenant,
            TypeUrl = requestMetadata.TypeUrl,
            RoutingHint = requestMetadata.RoutingHint ?? ByteString.Empty,
            ResponseType = requestMetadata.ResponseType,
            ResponseVersion = requestMetadata.ResponseVersion,
            Status = status,
            ErrorCode = errorCode,
            UserMessage = userMessage,
            ConnectId = requestMetadata.ConnectId,
            AppDeviceId = requestMetadata.AppDeviceId,
            ApplicationInstanceId = requestMetadata.ApplicationInstanceId,
            RequestId = requestMetadata.RequestId,
            IdempotencyKey = requestMetadata.IdempotencyKey,
            Platform = requestMetadata.Platform,
            Version = requestMetadata.Version,
            KeyExchangeContext = requestMetadata.KeyExchangeContext,
            DeliveryKind = requestMetadata.DeliveryKind
        };
    }

    private EventEnvelope BuildErrorEnvelope(EventMetadata metadata, string errorCode, string userMessage)
    {
        return new EventEnvelope
        {
            Metadata = BuildResponseMetadata(metadata, status: "ERR", errorCode: errorCode, userMessage: userMessage),
            Payload = ByteString.Empty
        };
    }
}

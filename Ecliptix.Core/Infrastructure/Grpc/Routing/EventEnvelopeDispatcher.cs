using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using Ecliptix.Protobuf.Transport.Common;
using Ecliptix.SharedKernel;
using Google.Protobuf;

namespace Ecliptix.Core.Infrastructure.Grpc.Routing;

public sealed class EventEnvelopeDispatcher
{
    private readonly IEventRouteResolver _resolver;
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

    public EventEnvelopeDispatcher(IEventRouteResolver resolver)
    {
        _resolver = resolver;
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
            return BuildErrorEnvelope(metadata, "route_not_found");
        }

        EventEnvelope? missingRequired = EnsureRequiredTransportMetadata(metadata, route);
        if (missingRequired is not null)
        {
            return missingRequired;
        }

        EventEnvelope? idempotencyError = EnsureIdempotency(metadata, route);
        if (idempotencyError is not null)
        {
            return idempotencyError;
        }

        object message;
        try
        {
            message = route.Deserialize(envelope.Payload.Memory);
        }
        catch
        {
            return BuildErrorEnvelope(metadata, "deserialize_failed");
        }

        Result<object, FailureBase> result;
        try
        {
            result = await route.HandleAsync(message, metadata, cancellationToken);
        }
        catch
        {
            return BuildErrorEnvelope(metadata, "handler_failed");
        }

        if (result.IsOk)
        {
            object response = result.Unwrap();

            try
            {
                ReadOnlyMemory<byte> serialized = route.Serialize(response);
                return new EventEnvelope
                {
                    Metadata = BuildResponseMetadata(metadata, status: "OK", errorCode: string.Empty),
                    Payload = ByteString.CopyFrom(serialized.Span)
                };
            }
            catch
            {
                return BuildErrorEnvelope(metadata, "serialize_failed");
            }
        }

        FailureBase failure = result.UnwrapErr();
        GrpcErrorDescriptor descriptor = failure.ToGrpcDescriptor();

        return new EventEnvelope
        {
            Metadata = BuildResponseMetadata(metadata, status: "ERR", errorCode: descriptor.ErrorCode.ToString()),
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
            return BuildErrorEnvelope(metadata, "route_missing_event_type");
        }

        if (metadata.DeliveryKind == DeliveryKind.Unspecified)
        {
            return BuildErrorEnvelope(metadata, "delivery_kind_required");
        }

        if (metadata.EventId?.Length > MaxEventIdLength)
        {
            return BuildErrorEnvelope(metadata, "event_id_too_long");
        }

        if (metadata.EventType?.Length > MaxEventTypeLength)
        {
            return BuildErrorEnvelope(metadata, "event_type_too_long");
        }

        if (!string.IsNullOrWhiteSpace(metadata.Context) && metadata.Context.Length > MaxContextLength)
        {
            return BuildErrorEnvelope(metadata, "context_too_long");
        }

        if (!string.IsNullOrWhiteSpace(metadata.RequestId) && metadata.RequestId.Length > MaxRequestIdLength)
        {
            return BuildErrorEnvelope(metadata, "request_id_too_long");
        }

        if (!string.IsNullOrWhiteSpace(metadata.Platform) && metadata.Platform.Length > MaxPlatformLength)
        {
            return BuildErrorEnvelope(metadata, "platform_too_long");
        }

        if (!string.IsNullOrWhiteSpace(metadata.Version) && metadata.Version.Length > MaxVersionLength)
        {
            return BuildErrorEnvelope(metadata, "version_too_long");
        }

        if (!string.IsNullOrWhiteSpace(metadata.AppDeviceId) && metadata.AppDeviceId.Length > MaxAppDeviceLength)
        {
            return BuildErrorEnvelope(metadata, "app_device_id_too_long");
        }

        if (!string.IsNullOrWhiteSpace(metadata.ApplicationInstanceId) &&
            metadata.ApplicationInstanceId.Length > MaxApplicationInstanceLength)
        {
            return BuildErrorEnvelope(metadata, "application_instance_id_too_long");
        }

        if (!string.IsNullOrWhiteSpace(metadata.Locale) && metadata.Locale.Length > MaxLocaleLength)
        {
            return BuildErrorEnvelope(metadata, "locale_too_long");
        }

        if (!string.IsNullOrWhiteSpace(metadata.Tenant) && metadata.Tenant.Length > MaxTenantLength)
        {
            return BuildErrorEnvelope(metadata, "tenant_too_long");
        }

        return null;
    }

    private EventEnvelope? EnsureRequiredTransportMetadata(EventMetadata metadata, EventRoute route)
    {
        if (string.IsNullOrWhiteSpace(metadata.Context))
        {
            return BuildErrorEnvelope(metadata, "context_required");
        }

        if (!metadata.Context.Equals(route.Context, StringComparison.OrdinalIgnoreCase))
        {
            return BuildErrorEnvelope(metadata, "context_mismatch");
        }

        if (RequiresConnectId(route.Context))
        {
            if (metadata.ConnectId == 0 && uint.TryParse(metadata.PartitionKey, out uint parsed))
            {
                metadata.ConnectId = parsed;
            }

            if (metadata.ConnectId == 0)
            {
                return BuildErrorEnvelope(metadata, "connect_id_required");
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

    private EventEnvelope? EnsureIdempotency(EventMetadata metadata, EventRoute route)
    {
        if (route.IdempotencyRequired && string.IsNullOrWhiteSpace(metadata.IdempotencyKey))
        {
            return BuildErrorEnvelope(metadata, "idempotency_required");
        }

        if (!string.IsNullOrWhiteSpace(metadata.IdempotencyKey) && !IdempotencyPattern.IsMatch(metadata.IdempotencyKey))
        {
            return BuildErrorEnvelope(metadata, "idempotency_invalid");
        }

        return null;
    }


    private static EventMetadata BuildResponseMetadata(EventMetadata requestMetadata, string status, string errorCode)
    {
        return new EventMetadata
        {
            EventId = requestMetadata.EventId,
            EventType = requestMetadata.EventType,
            Context = requestMetadata.Context,
            CorrelationId = string.IsNullOrWhiteSpace(requestMetadata.CorrelationId)
                ? requestMetadata.EventId
                : requestMetadata.CorrelationId,
            CausationId = requestMetadata.EventId,
            PartitionKey = requestMetadata.PartitionKey,
            Locale = requestMetadata.Locale,
            Tenant = requestMetadata.Tenant,
            Status = status,
            ErrorCode = errorCode,
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

    private EventEnvelope BuildErrorEnvelope(EventMetadata metadata, string errorCode)
    {
        return new EventEnvelope
        {
            Metadata = BuildResponseMetadata(metadata, status: "ERR", errorCode: errorCode),
            Payload = ByteString.Empty
        };
    }
}

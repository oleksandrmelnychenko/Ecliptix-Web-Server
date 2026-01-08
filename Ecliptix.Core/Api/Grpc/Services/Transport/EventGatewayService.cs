using Ecliptix.Core.Infrastructure.Grpc.Routing;
using Ecliptix.Protobuf.Transport.Common;
using Ecliptix.Protobuf.Transport.Gateway;
using Ecliptix.SharedKernel.Grpc.Utilities;
using Google.Protobuf;
using Grpc.Core;

namespace Ecliptix.Core.Api.Grpc.Services.Transport;

public sealed class EventGatewayService(EventEnvelopeDispatcher dispatcher) : EventGateway.EventGatewayBase
{
    public override Task<EventEnvelope> Unary(EventEnvelope request, ServerCallContext context)
    {
        if (request.Metadata is null || request.Metadata.EventType == TransportEventType.Unspecified)
        {
            return Task.FromResult(BuildMissingEventTypeEnvelope(DeliveryKind.Unary));
        }

        EventEnvelope normalized = NormalizeMetadata(request, DeliveryKind.Unary, context);
        return dispatcher.DispatchAsync(normalized, context.CancellationToken);
    }

    public override async Task ServerStream(
        EventEnvelope request,
        IServerStreamWriter<EventEnvelope> responseStream,
        ServerCallContext context)
    {
        if (request.Metadata is null || request.Metadata.EventType == TransportEventType.Unspecified)
        {
            await responseStream.WriteAsync(BuildMissingEventTypeEnvelope(DeliveryKind.ServerStream));
            return;
        }

        EventEnvelope normalized = NormalizeMetadata(request, DeliveryKind.ServerStream, context);
        EventEnvelope response = await dispatcher.DispatchAsync(normalized, context.CancellationToken);
        await responseStream.WriteAsync(response);
    }

    public override async Task<EventEnvelope> ClientStream(
        IAsyncStreamReader<EventEnvelope> requestStream,
        ServerCallContext context)
    {
        EventEnvelope? lastResponse = null;

        await foreach (EventEnvelope request in requestStream.ReadAllAsync(context.CancellationToken))
        {
            if (request.Metadata is null || request.Metadata.EventType == TransportEventType.Unspecified)
            {
                return BuildMissingEventTypeEnvelope(DeliveryKind.ClientStream);
            }

            EventEnvelope normalized = NormalizeMetadata(request, DeliveryKind.ClientStream, context);
            lastResponse = await dispatcher.DispatchAsync(normalized, context.CancellationToken);
        }

        return lastResponse ?? new EventEnvelope
        {
            Metadata = new EventMetadata
            {
                Status = "ERR",
                ErrorCode = "empty_stream",
                DeliveryKind = DeliveryKind.ClientStream
            }
        };
    }

    public override async Task BidiStream(
        IAsyncStreamReader<EventEnvelope> requestStream,
        IServerStreamWriter<EventEnvelope> responseStream,
        ServerCallContext context)
    {
        await foreach (EventEnvelope request in requestStream.ReadAllAsync(context.CancellationToken))
        {
            if (request.Metadata is null || request.Metadata.EventType == TransportEventType.Unspecified)
            {
                await responseStream.WriteAsync(BuildMissingEventTypeEnvelope(DeliveryKind.BidiStream));
                continue;
            }

            EventEnvelope normalized = NormalizeMetadata(request, DeliveryKind.BidiStream, context);
            EventEnvelope response = await dispatcher.DispatchAsync(normalized, context.CancellationToken);
            await responseStream.WriteAsync(response);
        }
    }

    private static EventEnvelope NormalizeMetadata(
        EventEnvelope request,
        DeliveryKind deliveryKind,
        ServerCallContext context)
    {
        EventMetadata metadata = request.Metadata ?? new EventMetadata();
        metadata.EventId = string.IsNullOrWhiteSpace(metadata.EventId)
            ? Guid.NewGuid().ToString("N")
            : metadata.EventId;

        metadata.DeliveryKind = metadata.DeliveryKind == DeliveryKind.Unspecified
            ? deliveryKind
            : metadata.DeliveryKind;

        if (metadata.ConnectId == 0)
        {
            try
            {
                metadata.ConnectId = ServiceUtilities.ExtractConnectId(context);
            }
            catch
            {
                // ignored
            }
        }

        if (string.IsNullOrWhiteSpace(metadata.PartitionKey) && metadata.ConnectId != 0)
        {
            metadata.PartitionKey = metadata.ConnectId.ToString();
        }

        string? idempotency = context.RequestHeaders.FirstOrDefault(h =>
            h.Key == MetadataConstants.Keys.IdempotencyKey)?.Value;
        if (!string.IsNullOrWhiteSpace(idempotency) && string.IsNullOrWhiteSpace(metadata.IdempotencyKey))
        {
            metadata.IdempotencyKey = idempotency;
        }

        string? requestId = context.RequestHeaders.FirstOrDefault(h =>
            h.Key == MetadataConstants.Keys.RequestId)?.Value;
        if (!string.IsNullOrWhiteSpace(requestId) && string.IsNullOrWhiteSpace(metadata.RequestId))
        {
            metadata.RequestId = requestId;
        }

        string? correlationId = context.RequestHeaders.FirstOrDefault(h =>
            h.Key == MetadataConstants.Keys.CorrelationId)?.Value;
        if (!string.IsNullOrWhiteSpace(correlationId) && string.IsNullOrWhiteSpace(metadata.CorrelationId))
        {
            metadata.CorrelationId = correlationId;
        }

        string? platform = context.RequestHeaders.FirstOrDefault(h =>
            h.Key == MetadataConstants.Keys.Platform)?.Value;
        if (!string.IsNullOrWhiteSpace(platform) && string.IsNullOrWhiteSpace(metadata.Platform))
        {
            metadata.Platform = platform;
        }

        string? locale = context.RequestHeaders.FirstOrDefault(h =>
            h.Key == MetadataConstants.Keys.Locale)?.Value;
        if (!string.IsNullOrWhiteSpace(locale) && string.IsNullOrWhiteSpace(metadata.Locale))
        {
            metadata.Locale = locale;
        }

        string? version = context.RequestHeaders.FirstOrDefault(h =>
            h.Key == MetadataConstants.Keys.Version)?.Value;
        if (!string.IsNullOrWhiteSpace(version) && string.IsNullOrWhiteSpace(metadata.Version))
        {
            metadata.Version = version;
        }

        string? appDeviceId = context.RequestHeaders.FirstOrDefault(h =>
            h.Key == MetadataConstants.Keys.AppDeviceId)?.Value;
        if (!string.IsNullOrWhiteSpace(appDeviceId) && string.IsNullOrWhiteSpace(metadata.AppDeviceId))
        {
            metadata.AppDeviceId = appDeviceId;
        }

        string? appInstanceId = context.RequestHeaders.FirstOrDefault(h =>
            h.Key == MetadataConstants.Keys.ApplicationInstanceId)?.Value;
        if (!string.IsNullOrWhiteSpace(appInstanceId) && string.IsNullOrWhiteSpace(metadata.ApplicationInstanceId))
        {
            metadata.ApplicationInstanceId = appInstanceId;
        }

        string? tenant = context.RequestHeaders.FirstOrDefault(h =>
            h.Key == MetadataConstants.Keys.Tenant)?.Value;
        if (!string.IsNullOrWhiteSpace(tenant) && string.IsNullOrWhiteSpace(metadata.Tenant))
        {
            metadata.Tenant = tenant;
        }

        request.Metadata = metadata;
        return request;
    }

    private static EventEnvelope BuildMissingEventTypeEnvelope(DeliveryKind deliveryKind) => new()
    {
        Metadata = new EventMetadata
        {
            Status = "ERR",
            ErrorCode = "missing_event_type",
            DeliveryKind = deliveryKind
        },
        Payload = ByteString.Empty
    };
}

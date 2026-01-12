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
        if (request.Metadata?.Identity?.EventType is null or TransportEventType.Unspecified)
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
        if (request.Metadata?.Identity?.EventType is null or TransportEventType.Unspecified)
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
            if (request.Metadata?.Identity?.EventType is null or TransportEventType.Unspecified)
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
                Identity = new EventIdentity { DeliveryKind = DeliveryKind.ClientStream },
                Outcome = new EventOutcome { Status = "ERR", ErrorCode = "empty_stream" }
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
            if (request.Metadata?.Identity?.EventType is null or TransportEventType.Unspecified)
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
        metadata.Identity ??= new EventIdentity();
        metadata.Client ??= new ClientContext();
        metadata.Security ??= new SecurityContext();

        string? GetHeader(string key) =>
            context.RequestHeaders.FirstOrDefault(h => h.Key == key)?.Value;

        void ApplyIfEmpty(ref string target, string? value)
        {
            if (!string.IsNullOrWhiteSpace(value) && string.IsNullOrWhiteSpace(target))
            {
                target = value;
            }
        }

        metadata.Identity.EventId = string.IsNullOrWhiteSpace(metadata.Identity.EventId)
            ? Guid.NewGuid().ToString("N")
            : metadata.Identity.EventId;

        metadata.Identity.DeliveryKind = metadata.Identity.DeliveryKind == DeliveryKind.Unspecified
            ? deliveryKind
            : metadata.Identity.DeliveryKind;

        metadata.Security.ConnectId = ServiceUtilities.ExtractConnectId(context);

        if (string.IsNullOrWhiteSpace(metadata.Identity.PartitionKey) && metadata.Security.ConnectId != 0)
        {
            metadata.Identity.PartitionKey = metadata.Security.ConnectId.ToString();
        }

        string idempotencyKey = metadata.Client.IdempotencyKey;
        string requestId = metadata.Client.RequestId;
        string correlationId = metadata.Identity.CorrelationId;
        string platform = metadata.Client.Platform;
        string locale = metadata.Client.Locale;
        string version = metadata.Client.Version;
        string appDeviceId = metadata.Client.DeviceId?.ToBase64() ?? string.Empty;
        string applicationInstanceId = metadata.Client.ApplicationInstanceId?.ToBase64() ?? string.Empty;
        string tenant = metadata.Client.Tenant;

        ApplyIfEmpty(ref idempotencyKey, GetHeader(MetadataConstants.Keys.IdempotencyKey));
        ApplyIfEmpty(ref requestId, GetHeader(MetadataConstants.Keys.RequestId));
        ApplyIfEmpty(ref correlationId, GetHeader(MetadataConstants.Keys.CorrelationId));
        ApplyIfEmpty(ref platform, GetHeader(MetadataConstants.Keys.Platform));
        ApplyIfEmpty(ref locale, GetHeader(MetadataConstants.Keys.Locale));
        ApplyIfEmpty(ref version, GetHeader(MetadataConstants.Keys.Version));
        ApplyIfEmpty(ref appDeviceId, GetHeader(MetadataConstants.Keys.DeviceId));
        ApplyIfEmpty(ref applicationInstanceId, GetHeader(MetadataConstants.Keys.ApplicationInstanceId));
        ApplyIfEmpty(ref tenant, GetHeader(MetadataConstants.Keys.Tenant));

        metadata.Client.IdempotencyKey = idempotencyKey;
        metadata.Client.RequestId = requestId;
        metadata.Identity.CorrelationId = correlationId;
        metadata.Client.Platform = platform;
        metadata.Client.Locale = locale;
        metadata.Client.Version = version;
        metadata.Client.DeviceId = ByteString.FromBase64(appDeviceId);
        metadata.Client.ApplicationInstanceId = ByteString.FromBase64(applicationInstanceId);
        metadata.Client.Tenant = tenant;

        request.Metadata = metadata;
        return request;
    }

    private static EventEnvelope BuildMissingEventTypeEnvelope(DeliveryKind deliveryKind) => new()
    {
        Metadata = new EventMetadata
        {
            Identity = new EventIdentity { DeliveryKind = deliveryKind },
            Outcome = new EventOutcome { Status = "ERR", ErrorCode = "missing_event_type" }
        },
        Payload = ByteString.Empty
    };
}

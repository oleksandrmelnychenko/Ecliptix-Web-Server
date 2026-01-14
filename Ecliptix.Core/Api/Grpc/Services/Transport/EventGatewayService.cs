using System.Runtime.CompilerServices;
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
        await dispatcher.DispatchServerStreamAsync(normalized, responseStream, context.CancellationToken);
    }

    public override async Task<EventEnvelope> ClientStream(
        IAsyncStreamReader<EventEnvelope> requestStream,
        ServerCallContext context)
    {
        IAsyncEnumerable<EventEnvelope> normalizedStream =
            NormalizeStreamAsync(requestStream, DeliveryKind.ClientStream, context);

        return await dispatcher.DispatchClientStreamAsync(normalizedStream, context.CancellationToken);
    }

    public override async Task BidiStream(
        IAsyncStreamReader<EventEnvelope> requestStream,
        IServerStreamWriter<EventEnvelope> responseStream,
        ServerCallContext context)
    {
        IAsyncEnumerable<EventEnvelope> normalizedStream =
            NormalizeStreamAsync(requestStream, DeliveryKind.BidiStream, context);

        await dispatcher.DispatchBidiStreamAsync(normalizedStream, responseStream, context.CancellationToken);
    }

    private async IAsyncEnumerable<EventEnvelope> NormalizeStreamAsync(
        IAsyncStreamReader<EventEnvelope> requestStream,
        DeliveryKind deliveryKind,
        ServerCallContext context,
        [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        CancellationToken effectiveToken = cancellationToken == default
            ? context.CancellationToken
            : cancellationToken;

        await foreach (EventEnvelope envelope in requestStream.ReadAllAsync(effectiveToken))
        {
            yield return NormalizeMetadata(envelope, deliveryKind, context);
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

        Metadata headers = context.RequestHeaders;

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

        metadata.Client.IdempotencyKey = ApplyHeaderIfEmpty(metadata.Client.IdempotencyKey, headers, MetadataConstants.Keys.IdempotencyKey);
        metadata.Client.RequestId = ApplyHeaderIfEmpty(metadata.Client.RequestId, headers, MetadataConstants.Keys.RequestId);
        metadata.Identity.CorrelationId = ApplyHeaderIfEmpty(metadata.Identity.CorrelationId, headers, MetadataConstants.Keys.CorrelationId);
        metadata.Client.Platform = ApplyHeaderIfEmpty(metadata.Client.Platform, headers, MetadataConstants.Keys.Platform);
        metadata.Client.Locale = ApplyHeaderIfEmpty(metadata.Client.Locale, headers, MetadataConstants.Keys.Locale);
        metadata.Client.Version = ApplyHeaderIfEmpty(metadata.Client.Version, headers, MetadataConstants.Keys.Version);
        metadata.Client.Tenant = ApplyHeaderIfEmpty(metadata.Client.Tenant, headers, MetadataConstants.Keys.Tenant);

        metadata.Client.DeviceId = ApplyByteStringHeaderIfEmpty(metadata.Client.DeviceId, headers, MetadataConstants.Keys.DeviceId);
        metadata.Client.ApplicationInstanceId = ApplyByteStringHeaderIfEmpty(metadata.Client.ApplicationInstanceId, headers, MetadataConstants.Keys.ApplicationInstanceId);

        request.Metadata = metadata;
        return request;
    }

    private static string ApplyHeaderIfEmpty(string current, Metadata headers, string key)
    {
        if (!string.IsNullOrWhiteSpace(current))
        {
            return current;
        }

        string? value = GetHeaderValue(headers, key);
        return !string.IsNullOrWhiteSpace(value) ? value : current;
    }

    private static ByteString ApplyByteStringHeaderIfEmpty(ByteString current, Metadata headers, string key)
    {
        if (!current.IsEmpty)
        {
            return current;
        }

        string? value = GetHeaderValue(headers, key);
        return !string.IsNullOrWhiteSpace(value) ? ByteString.FromBase64(value) : current;
    }

    private static string? GetHeaderValue(Metadata headers, string key) =>
        headers.FirstOrDefault(h => h.Key == key)?.Value;

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

using Ecliptix.Protobuf.Common;
using Ecliptix.Protobuf.Transport.Common;
using Google.Protobuf;
using Grpc.Core;

namespace Ecliptix.Core.Infrastructure.Grpc.Routing;

internal sealed class SecureEnvelopeStreamAdapter(
    IServerStreamWriter<EventEnvelope> innerStream,
    EventMetadata requestMetadata) : IServerStreamWriter<SecureEnvelope>
{
    public WriteOptions? WriteOptions
    {
        get => innerStream.WriteOptions;
        set => innerStream.WriteOptions = value;
    }

    public Task WriteAsync(SecureEnvelope message)
    {
        EventEnvelope envelope = new()
        {
            Metadata = BuildResponseMetadata(requestMetadata),
            Payload = message.ToByteString()
        };

        return innerStream.WriteAsync(envelope);
    }

    private static EventMetadata BuildResponseMetadata(EventMetadata requestMetadata)
    {
        return new EventMetadata
        {
            Identity = new EventIdentity
            {
                EventId = requestMetadata.Identity?.EventId ?? string.Empty,
                EventType = requestMetadata.Identity?.EventType ?? TransportEventType.Unspecified,
                Context = requestMetadata.Identity?.Context ?? EventContext.Unspecified,
                CorrelationId = string.IsNullOrWhiteSpace(requestMetadata.Identity?.CorrelationId)
                    ? requestMetadata.Identity?.EventId ?? string.Empty
                    : requestMetadata.Identity.CorrelationId,
                CausationId = requestMetadata.Identity?.EventId ?? string.Empty,
                PartitionKey = requestMetadata.Identity?.PartitionKey ?? string.Empty,
                DeliveryKind = requestMetadata.Identity?.DeliveryKind ?? DeliveryKind.ServerStream
            },
            Client = new ClientContext
            {
                Locale = requestMetadata.Client?.Locale ?? string.Empty,
                Tenant = requestMetadata.Client?.Tenant ?? string.Empty,
                RequestId = requestMetadata.Client?.RequestId ?? string.Empty,
                IdempotencyKey = requestMetadata.Client?.IdempotencyKey ?? string.Empty,
                Platform = requestMetadata.Client?.Platform ?? string.Empty,
                Version = requestMetadata.Client?.Version ?? string.Empty,
                DeviceId = requestMetadata.Client?.DeviceId ?? ByteString.Empty,
                ApplicationInstanceId = requestMetadata.Client?.ApplicationInstanceId ?? ByteString.Empty
            },
            Security = new SecurityContext
            {
                ConnectId = requestMetadata.Security?.ConnectId ?? 0,
                KeyExchangeContext = requestMetadata.Security?.KeyExchangeContext ?? string.Empty
            },
            Outcome = new EventOutcome
            {
                Status = "OK",
                ErrorCode = string.Empty,
                MessageKey = string.Empty,
                Retryable = false,
                LocalizedMessage = string.Empty
            }
        };
    }
}

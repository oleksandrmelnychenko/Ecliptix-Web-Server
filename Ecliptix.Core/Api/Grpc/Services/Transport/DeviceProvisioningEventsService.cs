using Ecliptix.Core.Infrastructure.Grpc.Routing;
using Ecliptix.SharedKernel.Grpc.Utilities;
using Ecliptix.Protobuf.Common;
using Ecliptix.Protobuf.Device;
using Ecliptix.Protobuf.Transport.Common;
using Ecliptix.Protobuf.Transport.DeviceProvisioning;
using Google.Protobuf;
using Grpc.Core;

namespace Ecliptix.Core.Api.Grpc.Services.Transport;

/// <summary>
/// Context-specific transport entry point for DeviceProvisioning events.
/// Normalizes metadata and delegates to the event dispatcher.
/// </summary>
public sealed class DeviceProvisioningEventsService : DeviceProvisioningEvents.DeviceProvisioningEventsBase
{
    private readonly EventEnvelopeDispatcher _dispatcher;

    public DeviceProvisioningEventsService(EventEnvelopeDispatcher dispatcher)
    {
        _dispatcher = dispatcher;
    }

    public override Task<EventEnvelope> RegisterDevice(EventEnvelope request, ServerCallContext context) =>
        DispatchAsync(request, DeviceProvisioningEventType.DeviceProvisioningRegisterDevice.ToString(), context, "device_provisioning");

    public override Task<EventEnvelope> EstablishSecureChannel(EventEnvelope request, ServerCallContext context) =>
        DispatchAsync(request, DeviceProvisioningEventType.DeviceProvisioningSecureChannelEstablish.ToString(), context, "device_provisioning");

    public override Task<EventEnvelope> RestoreSecureChannel(EventEnvelope request, ServerCallContext context) =>
        DispatchAsync(request, DeviceProvisioningEventType.DeviceProvisioningSecureChannelRestore.ToString(), context, "device_provisioning");

    public override Task<EventEnvelope> AuthenticatedEstablish(AuthenticatedEstablishRequest request, ServerCallContext context) =>
        DispatchAuthEstablishAsync(request, context);

    public override async Task<EventEnvelope> EventClientStream(
        IAsyncStreamReader<EventEnvelope> requestStream,
        ServerCallContext context)
    {
        EventEnvelope? lastResponse = null;
        await foreach (EventEnvelope request in requestStream.ReadAllAsync(context.CancellationToken))
        {
            if (string.IsNullOrWhiteSpace(request.Metadata?.EventType))
            {
                return BuildMissingEventTypeEnvelope("device_provisioning", DeliveryKind.ClientStream);
            }

            EventEnvelope normalized = NormalizeMetadata(
                request,
                request.Metadata.EventType,
                context,
                "device_provisioning",
                DeliveryKind.ClientStream);
            lastResponse = await _dispatcher.DispatchAsync(normalized, context.CancellationToken);
        }

        return lastResponse ?? new EventEnvelope
        {
            Metadata = new EventMetadata
            {
                Status = "ERR",
                ErrorCode = "empty_stream",
                UserMessage = "No messages received",
                Context = "device_provisioning",
                DeliveryKind = DeliveryKind.ClientStream
            }
        };
    }

    public override async Task EventServerStream(
        EventEnvelope request,
        IServerStreamWriter<EventEnvelope> responseStream,
        ServerCallContext context)
    {
        if (string.IsNullOrWhiteSpace(request.Metadata?.EventType))
        {
            await responseStream.WriteAsync(BuildMissingEventTypeEnvelope("device_provisioning", DeliveryKind.ServerStream));
            return;
        }

        EventEnvelope normalized = NormalizeMetadata(
            request,
            request.Metadata.EventType,
            context,
            "device_provisioning",
            DeliveryKind.ServerStream);

        EventEnvelope response = await _dispatcher.DispatchAsync(normalized, context.CancellationToken);
        await responseStream.WriteAsync(response);
    }

    public override async Task EventBidiStream(
        IAsyncStreamReader<EventEnvelope> requestStream,
        IServerStreamWriter<EventEnvelope> responseStream,
        ServerCallContext context)
    {
        await foreach (EventEnvelope request in requestStream.ReadAllAsync(context.CancellationToken))
        {
            if (string.IsNullOrWhiteSpace(request.Metadata?.EventType))
            {
                await responseStream.WriteAsync(BuildMissingEventTypeEnvelope("device_provisioning", DeliveryKind.BidiStream));
                continue;
            }

            EventEnvelope normalized = NormalizeMetadata(
                request,
                request.Metadata.EventType,
                context,
                "device_provisioning",
                DeliveryKind.BidiStream);

            EventEnvelope response = await _dispatcher.DispatchAsync(normalized, context.CancellationToken);
            await responseStream.WriteAsync(response);
        }
    }

    private async Task<EventEnvelope> DispatchAsync(
        EventEnvelope request,
        string eventType,
        ServerCallContext context,
        string contextName)
    {
        EventEnvelope normalized = NormalizeMetadata(request, eventType, context, contextName);
        return await _dispatcher.DispatchAsync(normalized, context.CancellationToken);
    }

    private async Task<EventEnvelope> DispatchAuthEstablishAsync(
        AuthenticatedEstablishRequest request,
        ServerCallContext context)
    {
        EventMetadata metadata = new EventMetadata
        {
            EventId = Guid.NewGuid().ToString("N"),
            EventType = DeviceProvisioningEventType.DeviceProvisioningSecureChannelAuthEstablish.ToString(),
            Context = "device_provisioning",
            DeliveryKind = DeliveryKind.Unary
        };

        try
        {
            metadata.ConnectId = ServiceUtilities.ExtractConnectId(context);
            metadata.PartitionKey = metadata.ConnectId.ToString();
        }
        catch
        {
            // leave default if not available
        }

        string? idempotency = context.RequestHeaders.FirstOrDefault(h => h.Key == Ecliptix.SharedKernel.Grpc.Utilities.MetadataConstants.Keys.IdempotencyKey)?.Value;
        if (!string.IsNullOrWhiteSpace(idempotency))
        {
            metadata.IdempotencyKey = idempotency;
        }

        EventEnvelope envelope = new()
        {
            Metadata = metadata,
            Payload = ByteString.CopyFrom(request.ToByteArray())
        };

        return await _dispatcher.DispatchAsync(envelope, context.CancellationToken);
    }

    private static EventEnvelope NormalizeMetadata(
        EventEnvelope request,
        string eventType,
        ServerCallContext context,
        string contextName,
        DeliveryKind deliveryKind = DeliveryKind.Unspecified)
    {
        EventMetadata metadata = request.Metadata ?? new EventMetadata();
        metadata.EventId = string.IsNullOrWhiteSpace(metadata.EventId) ? Guid.NewGuid().ToString("N") : metadata.EventId;
        metadata.EventType = string.IsNullOrWhiteSpace(metadata.EventType) ? eventType : metadata.EventType;
        metadata.Context = string.IsNullOrWhiteSpace(metadata.Context) ? contextName : metadata.Context;
        metadata.DeliveryKind = metadata.DeliveryKind == DeliveryKind.Unspecified
            ? (deliveryKind == DeliveryKind.Unspecified ? DeliveryKind.Unary : deliveryKind)
            : metadata.DeliveryKind;

        if (metadata.ConnectId == 0)
        {
            try
            {
                metadata.ConnectId = ServiceUtilities.ExtractConnectId(context);
            }
            catch
            {
                // leave as 0 if not available
            }
        }

        if (string.IsNullOrWhiteSpace(metadata.PartitionKey) && metadata.ConnectId != 0)
        {
            metadata.PartitionKey = metadata.ConnectId.ToString();
        }

        string? idempotency = context.RequestHeaders.FirstOrDefault(h => h.Key == Ecliptix.SharedKernel.Grpc.Utilities.MetadataConstants.Keys.IdempotencyKey)?.Value;
        if (string.IsNullOrWhiteSpace(metadata.IdempotencyKey) && !string.IsNullOrWhiteSpace(idempotency))
        {
            metadata.IdempotencyKey = idempotency;
        }

        request.Metadata = metadata;
        return request;
    }

    private static EventEnvelope BuildMissingEventTypeEnvelope(string contextName, DeliveryKind deliveryKind) =>
        new()
        {
            Metadata = new EventMetadata
            {
                Status = "ERR",
                ErrorCode = "missing_event_type",
                UserMessage = "metadata.event_type is required",
                Context = contextName,
                DeliveryKind = deliveryKind
            },
            Payload = ByteString.Empty
        };
}

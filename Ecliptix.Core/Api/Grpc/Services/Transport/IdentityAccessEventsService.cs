using Ecliptix.Core.Infrastructure.Grpc.Routing;
using Ecliptix.SharedKernel.Grpc.Utilities;
using Ecliptix.Protobuf.Transport.Common;
using Ecliptix.Protobuf.Transport.Identity;
using Google.Protobuf;
using Grpc.Core;

namespace Ecliptix.Core.Api.Grpc.Services.Transport;

/// <summary>
/// Context-specific transport entry point for IdentityAccess events.
/// Normalizes metadata and delegates to the event dispatcher.
/// </summary>
public sealed class IdentityAccessEventsService : IdentityAccessEvents.IdentityAccessEventsBase
{
    private readonly EventEnvelopeDispatcher _dispatcher;

    public IdentityAccessEventsService(EventEnvelopeDispatcher dispatcher)
    {
        _dispatcher = dispatcher;
    }

    public override Task<EventEnvelope> RegistrationInit(EventEnvelope request, ServerCallContext context) =>
        DispatchAsync(request, IdentityAccessEventType.IdentityAccessRegistrationInit.ToString(), context, "identity_access");

    public override Task<EventEnvelope> RegistrationComplete(EventEnvelope request, ServerCallContext context) =>
        DispatchAsync(request, IdentityAccessEventType.IdentityAccessRegistrationComplete.ToString(), context, "identity_access");

    public override Task<EventEnvelope> RecoveryInit(EventEnvelope request, ServerCallContext context) =>
        DispatchAsync(request, IdentityAccessEventType.IdentityAccessRecoveryInit.ToString(), context, "identity_access");

    public override Task<EventEnvelope> RecoveryComplete(EventEnvelope request, ServerCallContext context) =>
        DispatchAsync(request, IdentityAccessEventType.IdentityAccessRecoveryComplete.ToString(), context, "identity_access");

    public override Task<EventEnvelope> SignInInit(EventEnvelope request, ServerCallContext context) =>
        DispatchAsync(request, IdentityAccessEventType.IdentityAccessSignInInit.ToString(), context, "identity_access");

    public override Task<EventEnvelope> SignInComplete(EventEnvelope request, ServerCallContext context) =>
        DispatchAsync(request, IdentityAccessEventType.IdentityAccessSignInComplete.ToString(), context, "identity_access");

    public override Task<EventEnvelope> Logout(EventEnvelope request, ServerCallContext context) =>
        DispatchAsync(request, IdentityAccessEventType.IdentityAccessLogout.ToString(), context, "identity_access");

    public override Task<EventEnvelope> LogoutAnonymous(EventEnvelope request, ServerCallContext context) =>
        DispatchAsync(request, IdentityAccessEventType.IdentityAccessLogoutAnonymous.ToString(), context, "identity_access");

    public override Task<EventEnvelope> GetMasterKeyShares(EventEnvelope request, ServerCallContext context) =>
        DispatchAsync(request, IdentityAccessEventType.IdentityAccessGetMasterKeyShares.ToString(), context, "identity_access");

    public override Task<EventEnvelope> VerifyOtp(EventEnvelope request, ServerCallContext context) =>
        DispatchAsync(request, IdentityAccessEventType.IdentityAccessVerifyOtp.ToString(), context, "identity_access");

    public override Task<EventEnvelope> ValidateMobileNumber(EventEnvelope request, ServerCallContext context) =>
        DispatchAsync(request, IdentityAccessEventType.IdentityAccessValidateMobileNumber.ToString(), context, "identity_access");

    public override Task<EventEnvelope> CheckMobileAvailability(EventEnvelope request, ServerCallContext context) =>
        DispatchAsync(request, IdentityAccessEventType.IdentityAccessCheckMobileAvailability.ToString(), context, "identity_access");

    public override Task<EventEnvelope> RecoveryMobileVerification(EventEnvelope request, ServerCallContext context) =>
        DispatchAsync(request, IdentityAccessEventType.IdentityAccessRecoveryMobileVerification.ToString(), context, "identity_access");

    public override async Task<EventEnvelope> EventClientStream(
        IAsyncStreamReader<EventEnvelope> requestStream,
        ServerCallContext context)
    {
        EventEnvelope? lastResponse = null;
        await foreach (EventEnvelope request in requestStream.ReadAllAsync(context.CancellationToken))
        {
            if (string.IsNullOrWhiteSpace(request.Metadata?.EventType))
            {
                return BuildMissingEventTypeEnvelope("identity_access", DeliveryKind.ClientStream);
            }

            EventEnvelope normalized = NormalizeMetadata(
                request,
                request.Metadata.EventType,
                context,
                "identity_access",
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
                Context = "identity_access",
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
            await responseStream.WriteAsync(BuildMissingEventTypeEnvelope("identity_access", DeliveryKind.ServerStream));
            return;
        }

        EventEnvelope normalized = NormalizeMetadata(
            request,
            request.Metadata.EventType,
            context,
            "identity_access",
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
                await responseStream.WriteAsync(BuildMissingEventTypeEnvelope("identity_access", DeliveryKind.BidiStream));
                continue;
            }

            EventEnvelope normalized = NormalizeMetadata(
                request,
                request.Metadata.EventType,
                context,
                "identity_access",
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

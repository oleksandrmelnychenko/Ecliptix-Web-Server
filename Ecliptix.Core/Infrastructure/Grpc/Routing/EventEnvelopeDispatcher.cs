using System.Text.RegularExpressions;
using Ecliptix.IdentityAccess.Domain;
using Ecliptix.IdentityAccess.Domain.Services;
using Ecliptix.Protobuf.Transport.Common;
using Ecliptix.SharedKernel;
using Google.Protobuf;
using Grpc.Core;

namespace Ecliptix.Core.Infrastructure.Grpc.Routing;

public sealed class EventEnvelopeDispatcher(
    IEventRouteResolver resolver,
    ILocalizationService localizationService)
{
    private static readonly Regex IdempotencyPattern = new($"^[A-Za-z0-9._:-]{{1,{EventMetadataLimits.MaxIdempotencyKeyLength}}}$", RegexOptions.Compiled);

    public Task<EventEnvelope> DispatchAsync(EventEnvelope envelope, CancellationToken cancellationToken)
    {
        return CreateContext(envelope)
            .Bind(ValidateEventType)
            .Bind(ValidateDeliveryKind)
            .Bind(ValidateFieldLengths)
            .Bind(ResolveRoute)
            .Bind(dispatchContext => ValidateDeliveryKindMatch(dispatchContext, DeliveryKind.Unary))
            .Bind(ValidateRouteContext)
            .Bind(EnsureConnectId)
            .Bind(ValidateIdempotency)
            .Bind(ValidateDeviceIdentifiers)
            .Bind(DeserializePayload)
            .BindAsync(dispatchContext => ExecuteUnaryHandler(dispatchContext, cancellationToken))
            .Bind(SerializeResponse)
            .MatchAsync(BuildSuccessEnvelope, BuildErrorEnvelope);
    }

    public async Task DispatchServerStreamAsync(
        EventEnvelope envelope,
        IServerStreamWriter<EventEnvelope> responseStream,
        CancellationToken cancellationToken)
    {
        Result<DispatchContext, DispatchFailure> result = CreateContext(envelope)
            .Bind(ValidateEventType)
            .Bind(ValidateDeliveryKind)
            .Bind(ValidateFieldLengths)
            .Bind(ResolveRoute)
            .Bind(dispatchContext => ValidateDeliveryKindMatch(dispatchContext, DeliveryKind.ServerStream))
            .Bind(ValidateRouteContext)
            .Bind(EnsureConnectId)
            .Bind(ValidateIdempotency)
            .Bind(ValidateDeviceIdentifiers)
            .Bind(DeserializePayload);

        if (result.IsErr)
        {
            await responseStream.WriteAsync(BuildErrorEnvelope(result.UnwrapErr()));
            return;
        }

        DispatchContext dispatchContext = result.Unwrap();
        await ExecuteServerStreamHandler(dispatchContext, responseStream, cancellationToken);
    }

    public async Task<EventEnvelope> DispatchClientStreamAsync(
        IAsyncEnumerable<EventEnvelope> envelopes,
        CancellationToken cancellationToken)
    {
        await using IAsyncEnumerator<EventEnvelope> enumerator = envelopes.GetAsyncEnumerator(cancellationToken);

        if (!await enumerator.MoveNextAsync())
        {
            return BuildErrorEnvelope(new DispatchFailure(
                DispatcherErrorCodes.DeserializeFailed,
                string.Empty,
                string.Empty,
                false,
                new EventMetadata()));
        }

        EventEnvelope firstEnvelope = enumerator.Current;

        Result<DispatchContext, DispatchFailure> result = CreateContext(firstEnvelope)
            .Bind(ValidateEventType)
            .Bind(ValidateDeliveryKind)
            .Bind(ValidateFieldLengths)
            .Bind(ResolveRoute)
            .Bind(dispatchContext => ValidateDeliveryKindMatch(dispatchContext, DeliveryKind.ClientStream))
            .Bind(ValidateRouteContext)
            .Bind(EnsureConnectId)
            .Bind(ValidateIdempotency)
            .Bind(ValidateDeviceIdentifiers);

        if (result.IsErr)
        {
            return BuildErrorEnvelope(result.UnwrapErr());
        }

        DispatchContext dispatchContext = result.Unwrap();
        IAsyncEnumerable<IMessage> messageStream = DeserializeEnumeratedStream(firstEnvelope, enumerator, dispatchContext.Route!, cancellationToken);

        return await ExecuteClientStreamHandler(dispatchContext, messageStream, cancellationToken)
            .Bind(SerializeResponse)
            .MatchAsync(BuildSuccessEnvelope, BuildErrorEnvelope);
    }

    public async Task DispatchBidiStreamAsync(
        IAsyncEnumerable<EventEnvelope> envelopes,
        IServerStreamWriter<EventEnvelope> responseStream,
        CancellationToken cancellationToken)
    {
        await using IAsyncEnumerator<EventEnvelope> enumerator = envelopes.GetAsyncEnumerator(cancellationToken);

        if (!await enumerator.MoveNextAsync())
        {
            await responseStream.WriteAsync(BuildErrorEnvelope(new DispatchFailure(
                DispatcherErrorCodes.DeserializeFailed,
                string.Empty,
                string.Empty,
                false,
                new EventMetadata())));
            return;
        }

        EventEnvelope firstEnvelope = enumerator.Current;

        Result<DispatchContext, DispatchFailure> result = CreateContext(firstEnvelope)
            .Bind(ValidateEventType)
            .Bind(ValidateDeliveryKind)
            .Bind(ValidateFieldLengths)
            .Bind(ResolveRoute)
            .Bind(dispatchContext => ValidateDeliveryKindMatch(dispatchContext, DeliveryKind.BidiStream))
            .Bind(ValidateRouteContext)
            .Bind(EnsureConnectId)
            .Bind(ValidateIdempotency)
            .Bind(ValidateDeviceIdentifiers);

        if (result.IsErr)
        {
            await responseStream.WriteAsync(BuildErrorEnvelope(result.UnwrapErr()));
            return;
        }

        DispatchContext dispatchContext = result.Unwrap();
        IAsyncEnumerable<IMessage> messageStream = DeserializeEnumeratedStream(firstEnvelope, enumerator, dispatchContext.Route!, cancellationToken);

        await ExecuteBidiStreamHandler(dispatchContext, messageStream, responseStream, cancellationToken);
    }

    private static Result<DispatchContext, DispatchFailure> CreateContext(EventEnvelope envelope)
    {
        EventMetadata metadata = envelope.Metadata ?? new EventMetadata();
        metadata.Identity ??= new EventIdentity();

        if (string.IsNullOrWhiteSpace(metadata.Identity.EventId))
        {
            metadata.Identity.EventId = Guid.NewGuid().ToString("N");
        }

        return Ok(new DispatchContext { Envelope = envelope, Metadata = metadata });
    }

    private static Result<DispatchContext, DispatchFailure> ValidateEventType(DispatchContext dispatchContext)
    {
        return dispatchContext.Metadata.Identity?.EventType is null or TransportEventType.Unspecified
            ? Fail(dispatchContext, DispatcherErrorCodes.RouteMissingEventType)
            : Ok(dispatchContext);
    }

    private static Result<DispatchContext, DispatchFailure> ValidateDeliveryKind(DispatchContext dispatchContext)
    {
        return dispatchContext.Metadata.Identity?.DeliveryKind is null or DeliveryKind.Unspecified
            ? Fail(dispatchContext, DispatcherErrorCodes.DeliveryKindRequired)
            : Ok(dispatchContext);
    }

    private static Result<DispatchContext, DispatchFailure> ValidateFieldLengths(DispatchContext dispatchContext)
    {
        return Ok(dispatchContext)
            .Bind(c => ValidateLength(c, c.Metadata.Identity?.EventId, EventMetadataLimits.MaxEventIdLength, DispatcherErrorCodes.EventIdTooLong))
            .Bind(c => ValidateLength(c, c.Metadata.Client?.RequestId, EventMetadataLimits.MaxRequestIdLength, DispatcherErrorCodes.RequestIdTooLong))
            .Bind(c => ValidateLength(c, c.Metadata.Client?.Platform, EventMetadataLimits.MaxPlatformLength, DispatcherErrorCodes.PlatformTooLong))
            .Bind(c => ValidateLength(c, c.Metadata.Client?.Version, EventMetadataLimits.MaxVersionLength, DispatcherErrorCodes.VersionTooLong))
            .Bind(c => ValidateByteStringLength(c, c.Metadata.Client?.DeviceId, EventMetadataLimits.MaxAppDeviceLength, DispatcherErrorCodes.AppDeviceIdTooLong))
            .Bind(c => ValidateByteStringLength(c, c.Metadata.Client?.ApplicationInstanceId, EventMetadataLimits.MaxApplicationInstanceLength, DispatcherErrorCodes.ApplicationInstanceIdTooLong))
            .Bind(c => ValidateLength(c, c.Metadata.Client?.Locale, EventMetadataLimits.MaxLocaleLength, DispatcherErrorCodes.LocaleTooLong))
            .Bind(c => ValidateLength(c, c.Metadata.Client?.Tenant, EventMetadataLimits.MaxTenantLength, DispatcherErrorCodes.TenantTooLong));
    }

    private static Result<DispatchContext, DispatchFailure> ValidateLength(
        DispatchContext dispatchContext, string? value, int maxLength, string errorCode)
    {
        return !string.IsNullOrWhiteSpace(value) && value.Length > maxLength
            ? Fail(dispatchContext, errorCode)
            : Ok(dispatchContext);
    }

    private static Result<DispatchContext, DispatchFailure> ValidateByteStringLength(
        DispatchContext dispatchContext, ByteString? value, int maxLength, string errorCode)
    {
        return value != null && !value.IsEmpty && value.Length > maxLength
            ? Fail(dispatchContext, errorCode)
            : Ok(dispatchContext);
    }

    private Result<DispatchContext, DispatchFailure> ResolveRoute(DispatchContext dispatchContext)
    {
        return resolver.TryGetRoute(dispatchContext.Metadata.Identity!.EventType, out EventRoute route)
            ? Ok(dispatchContext.WithRoute(route))
            : Fail(dispatchContext, DispatcherErrorCodes.RouteNotFound);
    }

    private static Result<DispatchContext, DispatchFailure> ValidateRouteContext(DispatchContext dispatchContext)
    {
        if (dispatchContext.Metadata.Identity?.Context is null or EventContext.Unspecified)
        {
            return Fail(dispatchContext, DispatcherErrorCodes.ContextRequired);
        }

        return dispatchContext.Metadata.Identity.Context != dispatchContext.Route!.Context
            ? Fail(dispatchContext, DispatcherErrorCodes.ContextMismatch)
            : Ok(dispatchContext);
    }

    private static Result<DispatchContext, DispatchFailure> ValidateDeliveryKindMatch(
        DispatchContext dispatchContext, DeliveryKind expectedKind)
    {
        return dispatchContext.Route!.DeliveryKind != expectedKind
            ? Fail(dispatchContext, DispatcherErrorCodes.DeliveryKindMismatch)
            : Ok(dispatchContext);
    }

    private static Result<DispatchContext, DispatchFailure> EnsureConnectId(DispatchContext dispatchContext)
    {
        if (!RequiresConnectId(dispatchContext.Route!.Context))
        {
            return Ok(dispatchContext);
        }

        dispatchContext.Metadata.Security ??= new SecurityContext();
        dispatchContext.Metadata.Identity ??= new EventIdentity();

        if (dispatchContext.Metadata.Security.ConnectId == 0 && uint.TryParse(dispatchContext.Metadata.Identity.PartitionKey, out uint parsed))
        {
            dispatchContext.Metadata.Security.ConnectId = parsed;
        }

        if (dispatchContext.Metadata.Security.ConnectId == 0)
        {
            return Fail(dispatchContext, DispatcherErrorCodes.ConnectIdRequired);
        }

        if (string.IsNullOrWhiteSpace(dispatchContext.Metadata.Identity.PartitionKey))
        {
            dispatchContext.Metadata.Identity.PartitionKey = dispatchContext.Metadata.Security.ConnectId.ToString();
        }

        return Ok(dispatchContext);
    }

    private static bool RequiresConnectId(EventContext context) =>
        context is EventContext.IdentityAccess or EventContext.DeviceProvisioning;

    private static Result<DispatchContext, DispatchFailure> ValidateIdempotency(DispatchContext dispatchContext)
    {
        string? idempotencyKey = dispatchContext.Metadata.Client?.IdempotencyKey;

        if (dispatchContext.Route!.IdempotencyRequired && string.IsNullOrWhiteSpace(idempotencyKey))
        {
            return Fail(dispatchContext, DispatcherErrorCodes.IdempotencyRequired);
        }

        return !string.IsNullOrWhiteSpace(idempotencyKey) && !IdempotencyPattern.IsMatch(idempotencyKey)
            ? Fail(dispatchContext, DispatcherErrorCodes.IdempotencyInvalid)
            : Ok(dispatchContext);
    }

    private static Result<DispatchContext, DispatchFailure> ValidateDeviceIdentifiers(DispatchContext dispatchContext)
    {
        if (dispatchContext.Route!.RequiresDeviceId &&
            (dispatchContext.Metadata.Client?.DeviceId == null || dispatchContext.Metadata.Client.DeviceId.IsEmpty))
        {
            return Fail(dispatchContext, DispatcherErrorCodes.DeviceIdRequired);
        }

        if (dispatchContext.Route.RequiresApplicationInstanceId &&
            (dispatchContext.Metadata.Client?.ApplicationInstanceId == null || dispatchContext.Metadata.Client.ApplicationInstanceId.IsEmpty))
        {
            return Fail(dispatchContext, DispatcherErrorCodes.ApplicationInstanceIdRequired);
        }

        return Ok(dispatchContext);
    }

    private static Result<DispatchContext, DispatchFailure> DeserializePayload(DispatchContext dispatchContext)
    {
        try
        {
            IMessage message = dispatchContext.Route!.Deserialize(dispatchContext.Envelope.Payload.Memory);
            return Ok(dispatchContext.WithMessage(message));
        }
        catch
        {
            return Fail(dispatchContext, DispatcherErrorCodes.DeserializeFailed);
        }
    }

    private async Task<Result<DispatchContext, DispatchFailure>> ExecuteUnaryHandler(
        DispatchContext dispatchContext, CancellationToken cancellationToken)
    {
        if (dispatchContext.Route!.HandleUnaryAsync is null)
        {
            return Fail(dispatchContext, DispatcherErrorCodes.HandlerNotConfigured);
        }

        try
        {
            Result<IMessage, FailureBase> result =
                await dispatchContext.Route.HandleUnaryAsync(dispatchContext.Message!, dispatchContext.Metadata, cancellationToken);

            return result.IsOk
                ? Ok(dispatchContext.WithResponse(result.Unwrap()))
                : FailWithDescriptor(dispatchContext, result.UnwrapErr());
        }
        catch
        {
            return Fail(dispatchContext, DispatcherErrorCodes.HandlerFailed, retryable: true);
        }
    }

    private async Task ExecuteServerStreamHandler(
        DispatchContext dispatchContext,
        IServerStreamWriter<EventEnvelope> responseStream,
        CancellationToken cancellationToken)
    {
        if (dispatchContext.Route!.HandleServerStreamAsync is null)
        {
            await responseStream.WriteAsync(BuildErrorEnvelope(new DispatchFailure(
                DispatcherErrorCodes.HandlerNotConfigured,
                string.Empty,
                string.Empty,
                false,
                dispatchContext.Metadata)));
            return;
        }

        try
        {
            await dispatchContext.Route.HandleServerStreamAsync(dispatchContext.Message!, dispatchContext.Metadata, responseStream, cancellationToken);
        }
        catch
        {
            await responseStream.WriteAsync(BuildErrorEnvelope(new DispatchFailure(
                DispatcherErrorCodes.HandlerFailed,
                string.Empty,
                string.Empty,
                true,
                dispatchContext.Metadata)));
        }
    }

    private async Task<Result<DispatchContext, DispatchFailure>> ExecuteClientStreamHandler(
        DispatchContext dispatchContext,
        IAsyncEnumerable<IMessage> messageStream,
        CancellationToken cancellationToken)
    {
        if (dispatchContext.Route!.HandleClientStreamAsync is null)
        {
            return Fail(dispatchContext, DispatcherErrorCodes.HandlerNotConfigured);
        }

        try
        {
            Result<IMessage, FailureBase> result =
                await dispatchContext.Route.HandleClientStreamAsync(messageStream, dispatchContext.Metadata, cancellationToken);

            return result.IsOk
                ? Ok(dispatchContext.WithResponse(result.Unwrap()))
                : FailWithDescriptor(dispatchContext, result.UnwrapErr());
        }
        catch
        {
            return Fail(dispatchContext, DispatcherErrorCodes.HandlerFailed, retryable: true);
        }
    }

    private async Task ExecuteBidiStreamHandler(
        DispatchContext dispatchContext,
        IAsyncEnumerable<IMessage> messageStream,
        IServerStreamWriter<EventEnvelope> responseStream,
        CancellationToken cancellationToken)
    {
        if (dispatchContext.Route!.HandleBidiStreamAsync is null)
        {
            await responseStream.WriteAsync(BuildErrorEnvelope(new DispatchFailure(
                DispatcherErrorCodes.HandlerNotConfigured,
                string.Empty,
                string.Empty,
                false,
                dispatchContext.Metadata)));
            return;
        }

        try
        {
            await dispatchContext.Route.HandleBidiStreamAsync(messageStream, dispatchContext.Metadata, responseStream, cancellationToken);
        }
        catch
        {
            await responseStream.WriteAsync(BuildErrorEnvelope(new DispatchFailure(
                DispatcherErrorCodes.HandlerFailed,
                string.Empty,
                string.Empty,
                true,
                dispatchContext.Metadata)));
        }
    }

    private static async IAsyncEnumerable<IMessage> DeserializeEnumeratedStream(
        EventEnvelope firstEnvelope,
        IAsyncEnumerator<EventEnvelope> enumerator,
        EventRoute route,
        [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken)
    {
        yield return route.Deserialize(firstEnvelope.Payload.Memory);

        while (await enumerator.MoveNextAsync().ConfigureAwait(false))
        {
            cancellationToken.ThrowIfCancellationRequested();
            yield return route.Deserialize(enumerator.Current.Payload.Memory);
        }
    }

    private static Result<DispatchContext, DispatchFailure> SerializeResponse(DispatchContext dispatchContext)
    {
        try
        {
            ReadOnlyMemory<byte> serialized = dispatchContext.Route!.Serialize(dispatchContext.Response!);
            return Ok(dispatchContext with { Envelope = new EventEnvelope { Payload = ByteString.CopyFrom(serialized.Span) } });
        }
        catch
        {
            return Fail(dispatchContext, DispatcherErrorCodes.SerializeFailed);
        }
    }

    private static EventEnvelope BuildSuccessEnvelope(DispatchContext dispatchContext)
    {
        return new EventEnvelope
        {
            Metadata = BuildResponseMetadata(dispatchContext.Metadata, DispatcherErrorCodes.StatusOk, string.Empty),
            Payload = dispatchContext.Envelope.Payload
        };
    }

    private static EventEnvelope BuildErrorEnvelope(DispatchFailure failure)
    {
        return new EventEnvelope
        {
            Metadata = BuildResponseMetadata(
                failure.Metadata,
                DispatcherErrorCodes.StatusError,
                failure.ErrorCode,
                failure.MessageKey,
                failure.LocalizedMessage,
                failure.Retryable),
            Payload = ByteString.Empty
        };
    }

    private static EventMetadata BuildResponseMetadata(
        EventMetadata requestMetadata,
        string status,
        string errorCode,
        string messageKey = "",
        string localizedMessage = "",
        bool retryable = false)
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
                DeliveryKind = requestMetadata.Identity?.DeliveryKind ?? DeliveryKind.Unspecified
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
                Status = status,
                ErrorCode = errorCode,
                MessageKey = messageKey,
                Retryable = retryable,
                LocalizedMessage = localizedMessage
            }
        };
    }

    private static Result<DispatchContext, DispatchFailure> Ok(DispatchContext dispatchContext)
        => Result<DispatchContext, DispatchFailure>.Ok(dispatchContext);

    private static Result<DispatchContext, DispatchFailure> Fail(DispatchContext dispatchContext, string errorCode, bool retryable = false)
        => Result<DispatchContext, DispatchFailure>.Err(
            new DispatchFailure(errorCode, string.Empty, string.Empty, retryable, dispatchContext.Metadata));

    private Result<DispatchContext, DispatchFailure> FailWithDescriptor(DispatchContext dispatchContext, FailureBase failure)
    {
        GrpcErrorDescriptor descriptor = failure.ToGrpcDescriptor();
        string locale = dispatchContext.Metadata.Client?.Locale ?? "en-US";
        string localizedMessage = localizationService.Localize(descriptor.I18nKey, locale);

        return Result<DispatchContext, DispatchFailure>.Err(
            new DispatchFailure(
                descriptor.ErrorCode.ToString(),
                descriptor.I18nKey,
                localizedMessage,
                descriptor.Retryable,
                dispatchContext.Metadata));
    }
}

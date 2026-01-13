using System.Text.RegularExpressions;
using Ecliptix.Protobuf.Transport.Common;
using Ecliptix.SharedKernel;
using Google.Protobuf;

namespace Ecliptix.Core.Infrastructure.Grpc.Routing;

public sealed class EventEnvelopeDispatcher(IEventRouteResolver resolver)
{
    private static readonly Regex IdempotencyPattern = new("^[A-Za-z0-9._:-]{1,128}$", RegexOptions.Compiled);
    private const int MaxEventIdLength = 128;
    private const int MaxRequestIdLength = 128;
    private const int MaxPlatformLength = 64;
    private const int MaxVersionLength = 32;
    private const int MaxAppDeviceLength = 128;
    private const int MaxApplicationInstanceLength = 128;
    private const int MaxLocaleLength = 16;
    private const int MaxTenantLength = 64;

    public Task<EventEnvelope> DispatchAsync(EventEnvelope envelope, CancellationToken cancellationToken)
    {
        return CreateContext(envelope)
            .Bind(ValidateEventType)
            .Bind(ValidateDeliveryKind)
            .Bind(ValidateFieldLengths)
            .Bind(ResolveRoute)
            .Bind(ValidateRouteContext)
            .Bind(EnsureConnectId)
            .Bind(ValidateIdempotency)
            .Bind(ValidateDeviceIdentifiers)
            .Bind(DeserializePayload)
            .BindAsync(ctx => ExecuteHandler(ctx, cancellationToken))
            .Bind(SerializeResponse)
            .MatchAsync(BuildSuccessEnvelope, BuildErrorEnvelope);
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

    private static Result<DispatchContext, DispatchFailure> ValidateEventType(DispatchContext ctx)
    {
        return ctx.Metadata.Identity?.EventType is null or TransportEventType.Unspecified
            ? Fail(ctx, DispatcherErrorCodes.RouteMissingEventType)
            : Ok(ctx);
    }

    private static Result<DispatchContext, DispatchFailure> ValidateDeliveryKind(DispatchContext ctx)
    {
        return ctx.Metadata.Identity?.DeliveryKind is null or DeliveryKind.Unspecified
            ? Fail(ctx, DispatcherErrorCodes.DeliveryKindRequired)
            : Ok(ctx);
    }

    private static Result<DispatchContext, DispatchFailure> ValidateFieldLengths(DispatchContext ctx)
    {
        return Ok(ctx)
            .Bind(c => ValidateLength(c, c.Metadata.Identity?.EventId, MaxEventIdLength, DispatcherErrorCodes.EventIdTooLong))
            .Bind(c => ValidateLength(c, c.Metadata.Client?.RequestId, MaxRequestIdLength, DispatcherErrorCodes.RequestIdTooLong))
            .Bind(c => ValidateLength(c, c.Metadata.Client?.Platform, MaxPlatformLength, DispatcherErrorCodes.PlatformTooLong))
            .Bind(c => ValidateLength(c, c.Metadata.Client?.Version, MaxVersionLength, DispatcherErrorCodes.VersionTooLong))
            .Bind(c => ValidateByteStringLength(c, c.Metadata.Client?.DeviceId, MaxAppDeviceLength, DispatcherErrorCodes.AppDeviceIdTooLong))
            .Bind(c => ValidateByteStringLength(c, c.Metadata.Client?.ApplicationInstanceId, MaxApplicationInstanceLength, DispatcherErrorCodes.ApplicationInstanceIdTooLong))
            .Bind(c => ValidateLength(c, c.Metadata.Client?.Locale, MaxLocaleLength, DispatcherErrorCodes.LocaleTooLong))
            .Bind(c => ValidateLength(c, c.Metadata.Client?.Tenant, MaxTenantLength, DispatcherErrorCodes.TenantTooLong));
    }

    private static Result<DispatchContext, DispatchFailure> ValidateLength(
        DispatchContext ctx, string? value, int maxLength, string errorCode)
    {
        return !string.IsNullOrWhiteSpace(value) && value.Length > maxLength
            ? Fail(ctx, errorCode)
            : Ok(ctx);
    }

    private static Result<DispatchContext, DispatchFailure> ValidateByteStringLength(
        DispatchContext ctx, ByteString? value, int maxLength, string errorCode)
    {
        return value != null && !value.IsEmpty && value.Length > maxLength
            ? Fail(ctx, errorCode)
            : Ok(ctx);
    }

    private Result<DispatchContext, DispatchFailure> ResolveRoute(DispatchContext ctx)
    {
        return resolver.TryGetRoute(ctx.Metadata.Identity!.EventType, out EventRoute route)
            ? Ok(ctx.WithRoute(route))
            : Fail(ctx, DispatcherErrorCodes.RouteNotFound);
    }

    private static Result<DispatchContext, DispatchFailure> ValidateRouteContext(DispatchContext ctx)
    {
        if (ctx.Metadata.Identity?.Context is null or EventContext.Unspecified)
        {
            return Fail(ctx, DispatcherErrorCodes.ContextRequired);
        }

        return ctx.Metadata.Identity.Context != ctx.Route!.Context
            ? Fail(ctx, DispatcherErrorCodes.ContextMismatch)
            : Ok(ctx);
    }

    private static Result<DispatchContext, DispatchFailure> EnsureConnectId(DispatchContext ctx)
    {
        if (!RequiresConnectId(ctx.Route!.Context))
        {
            return Ok(ctx);
        }

        ctx.Metadata.Security ??= new SecurityContext();
        ctx.Metadata.Identity ??= new EventIdentity();

        if (ctx.Metadata.Security.ConnectId == 0 && uint.TryParse(ctx.Metadata.Identity.PartitionKey, out uint parsed))
        {
            ctx.Metadata.Security.ConnectId = parsed;
        }

        if (ctx.Metadata.Security.ConnectId == 0)
        {
            return Fail(ctx, DispatcherErrorCodes.ConnectIdRequired);
        }

        if (string.IsNullOrWhiteSpace(ctx.Metadata.Identity.PartitionKey))
        {
            ctx.Metadata.Identity.PartitionKey = ctx.Metadata.Security.ConnectId.ToString();
        }

        return Ok(ctx);
    }

    private static bool RequiresConnectId(EventContext context) =>
        context is EventContext.IdentityAccess or EventContext.DeviceProvisioning;

    private static Result<DispatchContext, DispatchFailure> ValidateIdempotency(DispatchContext ctx)
    {
        string? idempotencyKey = ctx.Metadata.Client?.IdempotencyKey;

        if (ctx.Route!.IdempotencyRequired && string.IsNullOrWhiteSpace(idempotencyKey))
        {
            return Fail(ctx, DispatcherErrorCodes.IdempotencyRequired);
        }

        return !string.IsNullOrWhiteSpace(idempotencyKey) && !IdempotencyPattern.IsMatch(idempotencyKey)
            ? Fail(ctx, DispatcherErrorCodes.IdempotencyInvalid)
            : Ok(ctx);
    }

    private static Result<DispatchContext, DispatchFailure> ValidateDeviceIdentifiers(DispatchContext ctx)
    {
        if (ctx.Route!.RequiresDeviceId &&
            (ctx.Metadata.Client?.DeviceId == null || ctx.Metadata.Client.DeviceId.IsEmpty))
        {
            return Fail(ctx, DispatcherErrorCodes.DeviceIdRequired);
        }

        if (ctx.Route.RequiresApplicationInstanceId &&
            (ctx.Metadata.Client?.ApplicationInstanceId == null || ctx.Metadata.Client.ApplicationInstanceId.IsEmpty))
        {
            return Fail(ctx, DispatcherErrorCodes.ApplicationInstanceIdRequired);
        }

        return Ok(ctx);
    }

    private static Result<DispatchContext, DispatchFailure> DeserializePayload(DispatchContext ctx)
    {
        try
        {
            IMessage message = ctx.Route!.Deserialize(ctx.Envelope.Payload.Memory);
            return Ok(ctx.WithMessage(message));
        }
        catch
        {
            return Fail(ctx, DispatcherErrorCodes.DeserializeFailed);
        }
    }

    private static async Task<Result<DispatchContext, DispatchFailure>> ExecuteHandler(
        DispatchContext ctx, CancellationToken cancellationToken)
    {
        try
        {
            Result<IMessage, FailureBase> result =
                await ctx.Route!.HandleAsync(ctx.Message!, ctx.Metadata, cancellationToken);

            return result.IsOk
                ? Ok(ctx.WithResponse(result.Unwrap()))
                : FailWithDescriptor(ctx, result.UnwrapErr());
        }
        catch
        {
            return Fail(ctx, DispatcherErrorCodes.HandlerFailed, retryable: true);
        }
    }

    private static Result<DispatchContext, DispatchFailure> SerializeResponse(DispatchContext ctx)
    {
        try
        {
            ReadOnlyMemory<byte> serialized = ctx.Route!.Serialize(ctx.Response!);
            return Ok(ctx with { Envelope = new EventEnvelope { Payload = ByteString.CopyFrom(serialized.Span) } });
        }
        catch
        {
            return Fail(ctx, DispatcherErrorCodes.SerializeFailed);
        }
    }

    private static EventEnvelope BuildSuccessEnvelope(DispatchContext ctx)
    {
        return new EventEnvelope
        {
            Metadata = BuildResponseMetadata(ctx.Metadata, DispatcherErrorCodes.StatusOk, string.Empty),
            Payload = ctx.Envelope.Payload
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

    private static Result<DispatchContext, DispatchFailure> Ok(DispatchContext ctx)
        => Result<DispatchContext, DispatchFailure>.Ok(ctx);

    private static Result<DispatchContext, DispatchFailure> Fail(DispatchContext ctx, string errorCode, bool retryable = false)
        => Result<DispatchContext, DispatchFailure>.Err(
            new DispatchFailure(errorCode, string.Empty, string.Empty, retryable, ctx.Metadata));

    private static Result<DispatchContext, DispatchFailure> FailWithDescriptor(DispatchContext ctx, FailureBase failure)
    {
        GrpcErrorDescriptor descriptor = failure.ToGrpcDescriptor();
        string localizedMessage = failure.UserMessageKey ?? descriptor.I18nKey;

        return Result<DispatchContext, DispatchFailure>.Err(
            new DispatchFailure(
                descriptor.ErrorCode.ToString(),
                descriptor.I18nKey,
                localizedMessage,
                descriptor.Retryable,
                ctx.Metadata));
    }
}

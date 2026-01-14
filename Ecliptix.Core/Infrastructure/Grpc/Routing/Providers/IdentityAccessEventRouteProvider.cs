using Ecliptix.IdentityAccess.Infrastructure.EventHandling;
using Ecliptix.Protobuf.Common;
using Ecliptix.Protobuf.Transport.Common;
using Ecliptix.SharedKernel;
using Google.Protobuf;
using Grpc.Core;

namespace Ecliptix.Core.Infrastructure.Grpc.Routing.Providers;

public static class IdentityAccessEventRouteProvider
{
    private const EventContext IdentityAccessContext = EventContext.IdentityAccess;

    [EventRoute(TransportEventType.IdentityOpaqueRegistrationInit, IdentityAccessContext, IdempotencyRequired = true)]
    internal static Task<Result<IMessage, FailureBase>> HandleIdentityOpaqueRegistrationInit(
        IServiceProvider services,
        SecureEnvelope envelope,
        EventMetadata metadata,
        CancellationToken cancellationToken) =>
        WithMembership(services, envelope, metadata,
            static (handler, request, context, _) => handler.OpaqueRegistrationInitRequest(request, context),
            cancellationToken);

    [EventRoute(TransportEventType.IdentityOpaqueRegistrationComplete, IdentityAccessContext, IdempotencyRequired = true)]
    internal static Task<Result<IMessage, FailureBase>> HandleIdentityOpaqueRegistrationComplete(
        IServiceProvider services,
        SecureEnvelope envelope,
        EventMetadata metadata,
        CancellationToken cancellationToken) =>
        WithMembership(services, envelope, metadata,
            static (handler, request, context, _) => handler.OpaqueRegistrationCompleteRequest(request, context),
            cancellationToken);

    [EventRoute(TransportEventType.IdentityOpaqueRecoveryInit, IdentityAccessContext, IdempotencyRequired = true)]
    internal static Task<Result<IMessage, FailureBase>> HandleIdentityOpaqueRecoveryInit(
        IServiceProvider services,
        SecureEnvelope envelope,
        EventMetadata metadata,
        CancellationToken cancellationToken) =>
        WithMembership(services, envelope, metadata,
            static (handler, request, context, _) => handler.OpaqueRecoverySecretKeyInitRequest(request, context),
            cancellationToken);

    [EventRoute(TransportEventType.IdentityOpaqueRecoveryComplete, IdentityAccessContext, IdempotencyRequired = true)]
    internal static Task<Result<IMessage, FailureBase>> HandleIdentityOpaqueRecoveryComplete(
        IServiceProvider services,
        SecureEnvelope envelope,
        EventMetadata metadata,
        CancellationToken cancellationToken) =>
        WithMembership(services, envelope, metadata,
            static (handler, request, context, _) => handler.OpaqueRecoveryCompleteRequest(request, context),
            cancellationToken);

    [EventRoute(TransportEventType.IdentityOpaqueSigninInit, IdentityAccessContext, IdempotencyRequired = true)]
    internal static Task<Result<IMessage, FailureBase>> HandleIdentityOpaqueSigninInit(
        IServiceProvider services,
        SecureEnvelope envelope,
        EventMetadata metadata,
        CancellationToken cancellationToken) =>
        WithMembership(services, envelope, metadata,
            static (handler, request, context, _) => handler.OpaqueSignInInitRequest(request, context),
            cancellationToken);

    [EventRoute(TransportEventType.IdentityOpaqueSigninComplete, IdentityAccessContext, IdempotencyRequired = true)]
    internal static Task<Result<IMessage, FailureBase>> HandleIdentityOpaqueSigninComplete(
        IServiceProvider services,
        SecureEnvelope envelope,
        EventMetadata metadata,
        CancellationToken cancellationToken) =>
        WithMembership(services, envelope, metadata,
            static (handler, request, context, _) => handler.OpaqueSignInCompleteRequest(request, context),
            cancellationToken);

    [EventRoute(TransportEventType.IdentitySessionLogout, IdentityAccessContext, IdempotencyRequired = true)]
    internal static Task<Result<IMessage, FailureBase>> HandleIdentitySessionLogout(
        IServiceProvider services,
        SecureEnvelope envelope,
        EventMetadata metadata,
        CancellationToken cancellationToken) =>
        WithMembership(services, envelope, metadata,
            static (handler, request, context, _) => handler.Logout(request, context),
            cancellationToken);

    [EventRoute(TransportEventType.IdentitySessionLogoutAnonymous, IdentityAccessContext, IdempotencyRequired = true)]
    internal static Task<Result<IMessage, FailureBase>> HandleIdentitySessionLogoutAnonymous(
        IServiceProvider services,
        SecureEnvelope envelope,
        EventMetadata metadata,
        CancellationToken cancellationToken) =>
        WithMembership(services, envelope, metadata,
            static (handler, request, context, _) => handler.AnonymousLogout(request, context),
            cancellationToken);

    [EventRoute(TransportEventType.IdentityOtpVerify, IdentityAccessContext)]
    internal static Task<Result<IMessage, FailureBase>> HandleIdentityOtpVerify(
        IServiceProvider services,
        SecureEnvelope envelope,
        EventMetadata metadata,
        CancellationToken cancellationToken) =>
        WithVerification(services, envelope, metadata,
            static (handler, request, context) => handler.VerifyOtp(request, context),
            cancellationToken);

    [EventRoute(TransportEventType.IdentityMobileNumberValidate, IdentityAccessContext)]
    internal static Task<Result<IMessage, FailureBase>> HandleIdentityMobileNumberValidate(
        IServiceProvider services,
        SecureEnvelope envelope,
        EventMetadata metadata,
        CancellationToken cancellationToken) =>
        WithVerification(services, envelope, metadata,
            static (handler, request, context) => handler.ValidateMobileNumber(request, context),
            cancellationToken);

    [EventRoute(TransportEventType.IdentityMobileNumberAvailability, IdentityAccessContext)]
    internal static Task<Result<IMessage, FailureBase>> HandleIdentityMobileNumberAvailability(
        IServiceProvider services,
        SecureEnvelope envelope,
        EventMetadata metadata,
        CancellationToken cancellationToken) =>
        WithVerification(services, envelope, metadata,
            static (handler, request, context) => handler.CheckMobileNumberAvailability(request, context),
            cancellationToken);

    [EventRoute(TransportEventType.IdentityRecoveryMobileVerify, IdentityAccessContext)]
    internal static Task<Result<IMessage, FailureBase>> HandleIdentityRecoveryMobileVerify(
        IServiceProvider services,
        SecureEnvelope envelope,
        EventMetadata metadata,
        CancellationToken cancellationToken) =>
        WithVerification(services, envelope, metadata,
            static (handler, request, context) => handler.RecoverySecretKeyMobileVerification(request, context),
            cancellationToken);

    [EventRoute(TransportEventType.IdentityProfileNameAvailability, IdentityAccessContext, IdempotencyRequired = true)]
    internal static Task<Result<IMessage, FailureBase>> HandleIdentityProfileNameAvailability(
        IServiceProvider services,
        SecureEnvelope envelope,
        EventMetadata metadata,
        CancellationToken cancellationToken) =>
        WithAccountProfile(services, envelope, metadata,
            static (handler, request, context) => handler.CheckProfileNameAvailability(request, context),
            cancellationToken);

    [EventRoute(TransportEventType.IdentityProfileUpsert, IdentityAccessContext, IdempotencyRequired = true)]
    internal static Task<Result<IMessage, FailureBase>> HandleIdentityProfileUpsert(
        IServiceProvider services,
        SecureEnvelope envelope,
        EventMetadata metadata,
        CancellationToken cancellationToken) =>
        WithAccountProfile(services, envelope, metadata,
            static (handler, request, context) => handler.CreateOrUpdateProfile(request, context),
            cancellationToken);

    [EventRoute(TransportEventType.IdentityProfileLookup, IdentityAccessContext)]
    internal static Task<Result<IMessage, FailureBase>> HandleIdentityProfileLookup(
        IServiceProvider services,
        SecureEnvelope envelope,
        EventMetadata metadata,
        CancellationToken cancellationToken) =>
        WithAccountProfile(services, envelope, metadata,
            static (handler, request, context) => handler.GetAccountProfile(request, context),
            cancellationToken);

    [EventRoute(TransportEventType.IdentityOtpInitiate, IdentityAccessContext, DeliveryKind.ServerStream)]
    internal static async Task HandleIdentityOtpInitiate(
        IServiceProvider services,
        SecureEnvelope envelope,
        EventMetadata metadata,
        IServerStreamWriter<EventEnvelope> responseStream,
        CancellationToken cancellationToken)
    {
        uint connectId = GrpcCallContextFactory.ResolveConnectId(metadata);
        using IServiceScope scope = services.CreateScope();
        GrpcCallContext context = GrpcCallContextFactory.BuildContext(
            metadata, connectId, cancellationToken);

        VerificationFlowHandler handler =
            ActivatorUtilities.CreateInstance<VerificationFlowHandler>(scope.ServiceProvider);

        SecureEnvelopeStreamAdapter streamAdapter = new(responseStream, metadata);

        await handler.InitiateVerification(envelope, streamAdapter, context);
    }

    private static async Task<Result<IMessage, FailureBase>> WithMembership(
        IServiceProvider services,
        SecureEnvelope envelope,
        EventMetadata metadata,
        Func<MembershipEventHandler, SecureEnvelope, GrpcCallContext, CancellationToken, Task<SecureEnvelope>> invoke,
        CancellationToken cancellationToken)
    {
        uint connectId = GrpcCallContextFactory.ResolveConnectId(metadata);
        using IServiceScope scope = services.CreateScope();
        GrpcCallContext context = GrpcCallContextFactory.BuildContext(
            metadata, connectId, cancellationToken);
        MembershipEventHandler handler =
            ActivatorUtilities.CreateInstance<MembershipEventHandler>(scope.ServiceProvider);

        SecureEnvelope response = await invoke(handler, envelope, context, cancellationToken);
        return Result<IMessage, FailureBase>.Ok(response);
    }

    private static async Task<Result<IMessage, FailureBase>> WithVerification(
        IServiceProvider services,
        SecureEnvelope envelope,
        EventMetadata metadata,
        Func<VerificationFlowHandler, SecureEnvelope, GrpcCallContext, Task<SecureEnvelope>> invoke,
        CancellationToken cancellationToken)
    {
        uint connectId = GrpcCallContextFactory.ResolveConnectId(metadata);
        using IServiceScope scope = services.CreateScope();
        GrpcCallContext context = GrpcCallContextFactory.BuildContext(
            metadata, connectId, cancellationToken);
        VerificationFlowHandler handler =
            ActivatorUtilities.CreateInstance<VerificationFlowHandler>(scope.ServiceProvider);
        SecureEnvelope response = await invoke(handler, envelope, context);
        return Result<IMessage, FailureBase>.Ok(response);
    }

    private static async Task<Result<IMessage, FailureBase>> WithAccountProfile(
        IServiceProvider services,
        SecureEnvelope envelope,
        EventMetadata metadata,
        Func<AccountProfileHandler, SecureEnvelope, GrpcCallContext, Task<SecureEnvelope>> invoke,
        CancellationToken cancellationToken)
    {
        uint connectId = GrpcCallContextFactory.ResolveConnectId(metadata);
        using IServiceScope scope = services.CreateScope();
        GrpcCallContext context = GrpcCallContextFactory.BuildContext(
            metadata, connectId, cancellationToken);
        AccountProfileHandler handler =
            ActivatorUtilities.CreateInstance<AccountProfileHandler>(scope.ServiceProvider);
        SecureEnvelope response = await invoke(handler, envelope, context);
        return Result<IMessage, FailureBase>.Ok(response);
    }
}

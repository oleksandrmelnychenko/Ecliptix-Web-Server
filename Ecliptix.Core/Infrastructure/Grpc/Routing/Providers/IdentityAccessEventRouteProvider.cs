using Ecliptix.IdentityAccess.Infrastructure.EventHandling;
using Ecliptix.Protobuf.Common;
using Ecliptix.Protobuf.Transport.Common;
using Ecliptix.SharedKernel;
using Google.Protobuf;

namespace Ecliptix.Core.Infrastructure.Grpc.Routing.Providers;

public static class IdentityAccessEventRouteProvider
{
    private const EventContext IdentityAccessContext = EventContext.IdentityAccess;

    [EventRoute(TransportEventType.IdentityAccessRegistrationInit, IdentityAccessContext, IdempotencyRequired = true)]
    internal static Task<Result<IMessage, FailureBase>> HandleRegistrationInit(
        IServiceProvider services,
        SecureEnvelope envelope,
        EventMetadata metadata,
        CancellationToken cancellationToken) =>
        WithMembership(services, envelope, metadata, cancellationToken,
            static (handler, request, context, _) => handler.OpaqueRegistrationInitRequest(request, context));

    [EventRoute(TransportEventType.IdentityAccessRegistrationComplete, IdentityAccessContext, IdempotencyRequired = true)]
    internal static Task<Result<IMessage, FailureBase>> HandleRegistrationComplete(
        IServiceProvider services,
        SecureEnvelope envelope,
        EventMetadata metadata,
        CancellationToken cancellationToken) =>
        WithMembership(services, envelope, metadata, cancellationToken,
            static (handler, request, context, _) => handler.OpaqueRegistrationCompleteRequest(request, context));

    [EventRoute(TransportEventType.IdentityAccessRecoveryInit, IdentityAccessContext, IdempotencyRequired = true)]
    internal static Task<Result<IMessage, FailureBase>> HandleRecoveryInit(
        IServiceProvider services,
        SecureEnvelope envelope,
        EventMetadata metadata,
        CancellationToken cancellationToken) =>
        WithMembership(services, envelope, metadata, cancellationToken,
            static (handler, request, context, _) => handler.OpaqueRecoverySecretKeyInitRequest(request, context));

    [EventRoute(TransportEventType.IdentityAccessRecoveryComplete, IdentityAccessContext, IdempotencyRequired = true)]
    internal static Task<Result<IMessage, FailureBase>> HandleRecoveryComplete(
        IServiceProvider services,
        SecureEnvelope envelope,
        EventMetadata metadata,
        CancellationToken cancellationToken) =>
        WithMembership(services, envelope, metadata, cancellationToken,
            static (handler, request, context, _) => handler.OpaqueRecoverySecretKeyCompleteRequest(request, context));

    [EventRoute(TransportEventType.IdentityAccessSignInInit, IdentityAccessContext, IdempotencyRequired = true)]
    internal static Task<Result<IMessage, FailureBase>> HandleMembershipSignIn(
        IServiceProvider services,
        SecureEnvelope envelope,
        EventMetadata metadata,
        CancellationToken cancellationToken) =>
        WithMembership(services, envelope, metadata, cancellationToken,
            static (handler, request, context, _) => handler.OpaqueSignInInitRequest(request, context));

    [EventRoute(TransportEventType.IdentityAccessSignInComplete, IdentityAccessContext, IdempotencyRequired = true)]
    internal static Task<Result<IMessage, FailureBase>> HandleMembershipSignInComplete(
        IServiceProvider services,
        SecureEnvelope envelope,
        EventMetadata metadata,
        CancellationToken cancellationToken) =>
        WithMembership(services, envelope, metadata, cancellationToken,
            static (handler, request, context, _) => handler.OpaqueSignInCompleteRequest(request, context));

    [EventRoute(TransportEventType.IdentityAccessLogout, IdentityAccessContext, IdempotencyRequired = true)]
    internal static Task<Result<IMessage, FailureBase>> HandleMembershipLogout(
        IServiceProvider services,
        SecureEnvelope envelope,
        EventMetadata metadata,
        CancellationToken cancellationToken) =>
        WithMembership(services, envelope, metadata, cancellationToken,
            static (handler, request, context, _) => handler.Logout(request, context));

    [EventRoute(TransportEventType.IdentityAccessLogoutAnonymous, IdentityAccessContext, IdempotencyRequired = true)]
    internal static Task<Result<IMessage, FailureBase>> HandleMembershipLogoutAnonymous(
        IServiceProvider services,
        SecureEnvelope envelope,
        EventMetadata metadata,
        CancellationToken cancellationToken) =>
        WithMembership(services, envelope, metadata, cancellationToken,
            static (handler, request, context, _) => handler.AnonymousLogout(request, context));

    [EventRoute(TransportEventType.IdentityAccessVerifyOtp, IdentityAccessContext)]
    internal static Task<Result<IMessage, FailureBase>> HandleVerifyOtp(
        IServiceProvider services,
        SecureEnvelope envelope,
        EventMetadata metadata,
        CancellationToken cancellationToken) =>
        WithVerification(services, envelope, metadata, cancellationToken,
            static (handler, request, context) => handler.VerifyOtp(request, context));

    [EventRoute(TransportEventType.IdentityAccessValidateMobileNumber, IdentityAccessContext)]
    internal static Task<Result<IMessage, FailureBase>> HandleValidateMobile(
        IServiceProvider services,
        SecureEnvelope envelope,
        EventMetadata metadata,
        CancellationToken cancellationToken) =>
        WithVerification(services, envelope, metadata, cancellationToken,
            static (handler, request, context) => handler.ValidateMobileNumber(request, context));

    [EventRoute(TransportEventType.IdentityAccessCheckMobileAvailability, IdentityAccessContext)]
    internal static Task<Result<IMessage, FailureBase>> HandleCheckMobileAvailability(
        IServiceProvider services,
        SecureEnvelope envelope,
        EventMetadata metadata,
        CancellationToken cancellationToken) =>
        WithVerification(services, envelope, metadata, cancellationToken,
            static (handler, request, context) => handler.CheckMobileNumberAvailability(request, context));

    [EventRoute(TransportEventType.IdentityAccessRecoveryMobileVerification, IdentityAccessContext)]
    internal static Task<Result<IMessage, FailureBase>> HandleRecoveryMobileVerification(
        IServiceProvider services,
        SecureEnvelope envelope,
        EventMetadata metadata,
        CancellationToken cancellationToken) =>
        WithVerification(services, envelope, metadata, cancellationToken,
            static (handler, request, context) => handler.RecoverySecretKeyMobileVerification(request, context));

    [EventRoute(TransportEventType.IdentityAccessCheckProfileName, IdentityAccessContext, IdempotencyRequired = true)]
    internal static Task<Result<IMessage, FailureBase>> HandleCheckProfileName(
        IServiceProvider services,
        SecureEnvelope envelope,
        EventMetadata metadata,
        CancellationToken cancellationToken) =>
        WithAccountProfile(services, envelope, metadata, cancellationToken,
            static (handler, request, context) => handler.CheckProfileNameAvailability(request, context));

    [EventRoute(TransportEventType.IdentityAccessUpsertProfile, IdentityAccessContext, IdempotencyRequired = true)]
    internal static Task<Result<IMessage, FailureBase>> HandleUpsertProfile(
        IServiceProvider services,
        SecureEnvelope envelope,
        EventMetadata metadata,
        CancellationToken cancellationToken) =>
        WithAccountProfile(services, envelope, metadata, cancellationToken,
            static (handler, request, context) => handler.CreateOrUpdateProfile(request, context));

    [EventRoute(TransportEventType.IdentityAccessGetProfile, IdentityAccessContext)]
    internal static Task<Result<IMessage, FailureBase>> HandleGetProfile(
        IServiceProvider services,
        SecureEnvelope envelope,
        EventMetadata metadata,
        CancellationToken cancellationToken) =>
        WithAccountProfile(services, envelope, metadata, cancellationToken,
            static (handler, request, context) => handler.GetAccountProfile(request, context));

    private static async Task<Result<IMessage, FailureBase>> WithMembership(
        IServiceProvider services,
        SecureEnvelope envelope,
        EventMetadata metadata,
        CancellationToken cancellationToken,
        Func<MembershipEventHandler, SecureEnvelope, GrpcCallContext, CancellationToken, Task<SecureEnvelope>> invoke)
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
        CancellationToken cancellationToken,
        Func<VerificationFlowHandler, SecureEnvelope, GrpcCallContext, Task<SecureEnvelope>> invoke)
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
        CancellationToken cancellationToken,
        Func<AccountProfileHandler, SecureEnvelope, GrpcCallContext, Task<SecureEnvelope>> invoke)
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

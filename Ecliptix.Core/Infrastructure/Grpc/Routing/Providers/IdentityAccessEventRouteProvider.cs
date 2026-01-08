using System;
using Ecliptix.IdentityAccess.Infrastructure.EventHandling;
using Ecliptix.Protobuf.Common;
using Ecliptix.Protobuf.Transport.Common;
using Ecliptix.SharedKernel;
using Microsoft.Extensions.DependencyInjection;

namespace Ecliptix.Core.Infrastructure.Grpc.Routing.Providers;

public sealed class IdentityAccessEventRouteProvider : ProtobufEventRouteProvider
{
    private const EventContext IdentityAccessContext = EventContext.IdentityAccess;

    public IdentityAccessEventRouteProvider(IServiceProvider services) : base(services)
    {
        Register(TransportEventType.IdentityAccessRegistrationInit, IdentityAccessContext,
            SecureEnvelope.Parser, HandleRegistrationInit, idempotencyRequired: true);
        Register(TransportEventType.IdentityAccessRegistrationComplete, IdentityAccessContext,
            SecureEnvelope.Parser, HandleRegistrationComplete, idempotencyRequired: true);
        Register(TransportEventType.IdentityAccessRecoveryInit, IdentityAccessContext,
            SecureEnvelope.Parser, HandleRecoveryInit, idempotencyRequired: true);
        Register(TransportEventType.IdentityAccessRecoveryComplete, IdentityAccessContext,
            SecureEnvelope.Parser, HandleRecoveryComplete, idempotencyRequired: true);
        Register(TransportEventType.IdentityAccessSignInInit, IdentityAccessContext,
            SecureEnvelope.Parser, HandleMembershipSignIn, idempotencyRequired: true);
        Register(TransportEventType.IdentityAccessSignInComplete, IdentityAccessContext,
            SecureEnvelope.Parser, HandleMembershipSignInComplete, idempotencyRequired: true);
        Register(TransportEventType.IdentityAccessLogout, IdentityAccessContext,
            SecureEnvelope.Parser, HandleMembershipLogout, idempotencyRequired: true);
        Register(TransportEventType.IdentityAccessLogoutAnonymous, IdentityAccessContext,
            SecureEnvelope.Parser, HandleMembershipLogoutAnonymous, idempotencyRequired: true);

        Register(TransportEventType.IdentityAccessVerifyOtp, IdentityAccessContext,
            SecureEnvelope.Parser, HandleVerifyOtp);
        Register(TransportEventType.IdentityAccessValidateMobileNumber, IdentityAccessContext,
            SecureEnvelope.Parser, HandleValidateMobile);
        Register(TransportEventType.IdentityAccessCheckMobileAvailability, IdentityAccessContext,
            SecureEnvelope.Parser, HandleCheckMobileAvailability);
        Register(TransportEventType.IdentityAccessRecoveryMobileVerification, IdentityAccessContext,
            SecureEnvelope.Parser, HandleRecoveryMobileVerification);

        Register(TransportEventType.IdentityAccessCheckProfileName, IdentityAccessContext,
            SecureEnvelope.Parser, HandleCheckProfileName, idempotencyRequired: true);
        Register(TransportEventType.IdentityAccessUpsertProfile, IdentityAccessContext,
            SecureEnvelope.Parser, HandleUpsertProfile, idempotencyRequired: true);
        Register(TransportEventType.IdentityAccessGetProfile, IdentityAccessContext,
            SecureEnvelope.Parser, HandleGetProfile);
    }

    private static Task<Result<object, FailureBase>> HandleRegistrationInit(
        IServiceProvider services,
        SecureEnvelope envelope,
        EventMetadata metadata,
        CancellationToken cancellationToken) =>
        WithMembership(services, envelope, metadata, cancellationToken,
            static (handler, request, context, _) => handler.OpaqueRegistrationInitRequest(request, context));

    private static Task<Result<object, FailureBase>> HandleRegistrationComplete(
        IServiceProvider services,
        SecureEnvelope envelope,
        EventMetadata metadata,
        CancellationToken cancellationToken) =>
        WithMembership(services, envelope, metadata, cancellationToken,
            static (handler, request, context, _) => handler.OpaqueRegistrationCompleteRequest(request, context));

    private static Task<Result<object, FailureBase>> HandleRecoveryInit(
        IServiceProvider services,
        SecureEnvelope envelope,
        EventMetadata metadata,
        CancellationToken cancellationToken) =>
        WithMembership(services, envelope, metadata, cancellationToken,
            static (handler, request, context, _) => handler.OpaqueRecoverySecretKeyInitRequest(request, context));

    private static Task<Result<object, FailureBase>> HandleRecoveryComplete(
        IServiceProvider services,
        SecureEnvelope envelope,
        EventMetadata metadata,
        CancellationToken cancellationToken) =>
        WithMembership(services, envelope, metadata, cancellationToken,
            static (handler, request, context, _) => handler.OpaqueRecoverySecretKeyCompleteRequest(request, context));

    private static Task<Result<object, FailureBase>> HandleMembershipSignIn(
        IServiceProvider services,
        SecureEnvelope envelope,
        EventMetadata metadata,
        CancellationToken cancellationToken) =>
        WithMembership(services, envelope, metadata, cancellationToken,
            static (handler, request, context, _) => handler.OpaqueSignInInitRequest(request, context));

    private static Task<Result<object, FailureBase>> HandleMembershipSignInComplete(
        IServiceProvider services,
        SecureEnvelope envelope,
        EventMetadata metadata,
        CancellationToken cancellationToken) =>
        WithMembership(services, envelope, metadata, cancellationToken,
            static (handler, request, context, _) => handler.OpaqueSignInCompleteRequest(request, context));

    private static Task<Result<object, FailureBase>> HandleMembershipLogout(
        IServiceProvider services,
        SecureEnvelope envelope,
        EventMetadata metadata,
        CancellationToken cancellationToken) =>
        WithMembership(services, envelope, metadata, cancellationToken,
            static (handler, request, context, _) => handler.Logout(request, context));

    private static Task<Result<object, FailureBase>> HandleMembershipLogoutAnonymous(
        IServiceProvider services,
        SecureEnvelope envelope,
        EventMetadata metadata,
        CancellationToken cancellationToken) =>
        WithMembership(services, envelope, metadata, cancellationToken,
            static (handler, request, context, _) => handler.AnonymousLogout(request, context));

    private static Task<Result<object, FailureBase>> HandleVerifyOtp(
        IServiceProvider services,
        SecureEnvelope envelope,
        EventMetadata metadata,
        CancellationToken cancellationToken) =>
        WithVerification(services, envelope, metadata, cancellationToken,
            static (handler, request, context) => handler.VerifyOtp(request, context));

    private static Task<Result<object, FailureBase>> HandleValidateMobile(
        IServiceProvider services,
        SecureEnvelope envelope,
        EventMetadata metadata,
        CancellationToken cancellationToken) =>
        WithVerification(services, envelope, metadata, cancellationToken,
            static (handler, request, context) => handler.ValidateMobileNumber(request, context));

    private static Task<Result<object, FailureBase>> HandleCheckMobileAvailability(
        IServiceProvider services,
        SecureEnvelope envelope,
        EventMetadata metadata,
        CancellationToken cancellationToken) =>
        WithVerification(services, envelope, metadata, cancellationToken,
            static (handler, request, context) => handler.CheckMobileNumberAvailability(request, context));

    private static Task<Result<object, FailureBase>> HandleRecoveryMobileVerification(
        IServiceProvider services,
        SecureEnvelope envelope,
        EventMetadata metadata,
        CancellationToken cancellationToken) =>
        WithVerification(services, envelope, metadata, cancellationToken,
            static (handler, request, context) => handler.RecoverySecretKeyMobileVerification(request, context));

    private static Task<Result<object, FailureBase>> HandleCheckProfileName(
        IServiceProvider services,
        SecureEnvelope envelope,
        EventMetadata metadata,
        CancellationToken cancellationToken) =>
        WithAccountProfile(services, envelope, metadata, cancellationToken,
            static (handler, request, context) => handler.CheckProfileNameAvailability(request, context));

    private static Task<Result<object, FailureBase>> HandleUpsertProfile(
        IServiceProvider services,
        SecureEnvelope envelope,
        EventMetadata metadata,
        CancellationToken cancellationToken) =>
        WithAccountProfile(services, envelope, metadata, cancellationToken,
            static (handler, request, context) => handler.CreateOrUpdateProfile(request, context));

    private static Task<Result<object, FailureBase>> HandleGetProfile(
        IServiceProvider services,
        SecureEnvelope envelope,
        EventMetadata metadata,
        CancellationToken cancellationToken) =>
        WithAccountProfile(services, envelope, metadata, cancellationToken,
            static (handler, request, context) => handler.GetAccountProfile(request, context));

    private static async Task<Result<object, FailureBase>> WithMembership(
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
        return Result<object, FailureBase>.Ok(response);
    }

    private static async Task<Result<object, FailureBase>> WithVerification(
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
        return Result<object, FailureBase>.Ok(response);
    }

    private static async Task<Result<object, FailureBase>> WithAccountProfile(
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
        return Result<object, FailureBase>.Ok(response);
    }
}

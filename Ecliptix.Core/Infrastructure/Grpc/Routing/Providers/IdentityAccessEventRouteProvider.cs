using System;
using System.Buffers;
using System.Globalization;
using System.Security.Cryptography;
using Akka.Actor;
using Ecliptix.Core.Infrastructure.Grpc.Utilities.Utilities;
using Ecliptix.IdentityAccess.Domain.Memberships.ActorEvents.Account;
using Ecliptix.IdentityAccess.Domain.Memberships.ActorEvents.AccountProfile;
using Ecliptix.IdentityAccess.Domain.Memberships.ActorEvents.Logout;
using Ecliptix.IdentityAccess.Domain.Memberships.ActorEvents.Membership;
using Ecliptix.IdentityAccess.Domain.Memberships.ActorEvents.VerificationFlow;
using Ecliptix.IdentityAccess.Domain.Memberships.Failures;
using Ecliptix.IdentityAccess.Domain.Memberships.MobileNumberValidation;
using Ecliptix.IdentityAccess.Domain.Memberships.Persistors.QueryRecords;
using Ecliptix.IdentityAccess.Domain.Schema.Entities;
using Ecliptix.IdentityAccess.Domain.Services.Security;
using Ecliptix.IdentityAccess.Infrastructure.EventHandling;
using Ecliptix.Protobuf.Account;
using Ecliptix.Protobuf.Common;
using Ecliptix.Protobuf.Membership;
using Ecliptix.Protobuf.Transport.Common;
using Ecliptix.Protobuf.Transport.Identity;
using Ecliptix.SharedKernel;
using Ecliptix.SharedKernel.Actors;
using Ecliptix.SharedKernel.Configuration;
using Ecliptix.SharedKernel.Grpc;
using Ecliptix.SharedKernel.Grpc.Utilities;
using Ecliptix.SharedKernel.Grpc.Utilities.CipherPayloadHandler;
using Ecliptix.SharedKernel.KeyDerivation;
using Google.Protobuf;
using Grpc.Core;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Ecliptix.Core.Infrastructure.Grpc.Routing.Providers;

/// <summary>
/// Placeholder route provider for IdentityAccess events. Extend by registering event types and handlers.
/// </summary>
public sealed class IdentityAccessEventRouteProvider : ProtobufEventRouteProvider
{
    public IdentityAccessEventRouteProvider(IServiceProvider services) : base(services)
    {
        Register(IdentityAccessEventType.IdentityAccessRegistrationInit.ToString(), "identity_access",
            SecureEnvelope.Parser, HandleRegistrationInit, idempotencyRequired: true);
        Register(IdentityAccessEventType.IdentityAccessRegistrationComplete.ToString(), "identity_access",
            SecureEnvelope.Parser, HandleRegistrationComplete, idempotencyRequired: true);
        Register(IdentityAccessEventType.IdentityAccessRecoveryInit.ToString(), "identity_access",
            SecureEnvelope.Parser, HandleRecoveryInit, idempotencyRequired: true);
        Register(IdentityAccessEventType.IdentityAccessRecoveryComplete.ToString(), "identity_access",
            SecureEnvelope.Parser, HandleRecoveryComplete, idempotencyRequired: true);
        Register(IdentityAccessEventType.IdentityAccessSignInInit.ToString(), "identity_access",
            SecureEnvelope.Parser, HandleMembershipSignIn, idempotencyRequired: true);
        Register(IdentityAccessEventType.IdentityAccessSignInComplete.ToString(), "identity_access",
            SecureEnvelope.Parser, HandleMembershipSignInComplete, idempotencyRequired: true);
        Register(IdentityAccessEventType.IdentityAccessLogout.ToString(), "identity_access",
            SecureEnvelope.Parser, HandleMembershipLogout, idempotencyRequired: true);
        Register(IdentityAccessEventType.IdentityAccessLogoutAnonymous.ToString(), "identity_access",
            SecureEnvelope.Parser, HandleMembershipLogoutAnonymous, idempotencyRequired: true);

        Register(IdentityAccessEventType.IdentityAccessVerifyOtp.ToString(), "identity_access",
            SecureEnvelope.Parser, HandleVerifyOtp);
        Register(IdentityAccessEventType.IdentityAccessValidateMobileNumber.ToString(), "identity_access",
            SecureEnvelope.Parser, HandleValidateMobile);
        Register(IdentityAccessEventType.IdentityAccessCheckMobileAvailability.ToString(), "identity_access",
            SecureEnvelope.Parser, HandleCheckMobileAvailability);
        Register(IdentityAccessEventType.IdentityAccessRecoveryMobileVerification.ToString(), "identity_access",
            SecureEnvelope.Parser, HandleRecoveryMobileVerification);

        Register(IdentityAccessEventType.IdentityAccessCheckProfileName.ToString(), "identity_access",
            SecureEnvelope.Parser, HandleCheckProfileName, idempotencyRequired: true);
        Register(IdentityAccessEventType.IdentityAccessUpsertProfile.ToString(), "identity_access",
            SecureEnvelope.Parser, HandleUpsertProfile, idempotencyRequired: true);
        Register(IdentityAccessEventType.IdentityAccessGetProfile.ToString(), "identity_access",
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
        uint connectId = ResolveConnectId(metadata);
        using IServiceScope scope = services.CreateScope();
        GrpcCallContext context = BuildContext(metadata, connectId, cancellationToken);
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
        uint connectId = ResolveConnectId(metadata);
        using IServiceScope scope = services.CreateScope();
        GrpcCallContext context = BuildContext(metadata, connectId, cancellationToken);
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
        uint connectId = ResolveConnectId(metadata);
        using IServiceScope scope = services.CreateScope();
        GrpcCallContext context = BuildContext(metadata, connectId, cancellationToken);
        AccountProfileHandler handler =
            ActivatorUtilities.CreateInstance<AccountProfileHandler>(scope.ServiceProvider);
        SecureEnvelope response = await invoke(handler, envelope, context);
        return Result<object, FailureBase>.Ok(response);
    }

    private static uint ResolveConnectId(EventMetadata metadata)
    {
        if (metadata.ConnectId != 0)
        {
            return metadata.ConnectId;
        }

        if (uint.TryParse(metadata.PartitionKey, out uint parsed))
        {
            return parsed;
        }

        throw new RpcException(new global::Grpc.Core.Status(StatusCode.InvalidArgument, "connect_id is required"));
    }

    private static GrpcCallContext BuildContext(EventMetadata metadata, uint connectId, CancellationToken cancellationToken)
    {
        Metadata headers = new();
        headers.Add(MetadataConstants.Keys.ConnectId, connectId.ToString(CultureInfo.InvariantCulture));

        // Critical: Copy the connection context ID (exchange type) for encryption to work properly
        if (!string.IsNullOrWhiteSpace(metadata.KeyExchangeContext))
        {
            headers.Add(MetadataConstants.Keys.ConnectionContextId, metadata.KeyExchangeContext);
        }
        else
        {
            // Default to DataCenterEphemeralConnect if not specified
            headers.Add(MetadataConstants.Keys.ConnectionContextId, Ecliptix.Protobuf.Protocol.PubKeyExchangeType.DataCenterEphemeralConnect.ToString());
        }

        if (!string.IsNullOrWhiteSpace(metadata.IdempotencyKey))
        {
            headers.Add(MetadataConstants.Keys.IdempotencyKey, metadata.IdempotencyKey);
        }
        else if (!string.IsNullOrWhiteSpace(metadata.CorrelationId))
        {
            headers.Add(MetadataConstants.Keys.IdempotencyKey, metadata.CorrelationId);
        }

        if (!string.IsNullOrWhiteSpace(metadata.CorrelationId))
        {
            headers.Add(MetadataConstants.Keys.CorrelationId, metadata.CorrelationId);
        }

        if (!string.IsNullOrWhiteSpace(metadata.RequestId))
        {
            headers.Add(MetadataConstants.Keys.RequestId, metadata.RequestId);
        }

        if (!string.IsNullOrWhiteSpace(metadata.Platform))
        {
            headers.Add(MetadataConstants.Keys.Platform, metadata.Platform);
        }

        if (!string.IsNullOrWhiteSpace(metadata.Locale))
        {
            headers.Add(MetadataConstants.Keys.Locale, metadata.Locale);
        }

        if (!string.IsNullOrWhiteSpace(metadata.Version))
        {
            headers.Add(MetadataConstants.Keys.Version, metadata.Version);
        }

        if (!string.IsNullOrWhiteSpace(metadata.Tenant))
        {
            headers.Add(MetadataConstants.Keys.Tenant, metadata.Tenant);
        }

        if (!string.IsNullOrWhiteSpace(metadata.AppDeviceId))
        {
            headers.Add(MetadataConstants.Keys.AppDeviceId, metadata.AppDeviceId);
        }

        if (!string.IsNullOrWhiteSpace(metadata.ApplicationInstanceId))
        {
            headers.Add(MetadataConstants.Keys.ApplicationInstanceId, metadata.ApplicationInstanceId);
        }

        GrpcCallContext ctx = new(metadata.EventType ?? "identity_access", "transport", headers, cancellationToken);
        ctx.UserState[GrpcMetadataHandler.UniqueConnectId] = connectId;
        return ctx;
    }
}

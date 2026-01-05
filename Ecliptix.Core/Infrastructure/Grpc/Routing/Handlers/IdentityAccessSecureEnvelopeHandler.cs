using Ecliptix.Core.Infrastructure.Grpc.Routing;
using Ecliptix.Core.Infrastructure.Grpc.Utilities.Utilities;
using Ecliptix.IdentityAccess.Infrastructure.Grpc;
using Ecliptix.Protobuf.Common;
using Ecliptix.Protobuf.Transport.Common;
using Ecliptix.Protobuf.Transport.Identity;
using Ecliptix.SharedKernel;
using Ecliptix.SharedKernel.Grpc.Utilities;
using Grpc.Core;
using Microsoft.Extensions.DependencyInjection;

namespace Ecliptix.Core.Infrastructure.Grpc.Routing.Handlers;

public sealed class IdentityAccessSecureEnvelopeHandler : IEventHandler<SecureEnvelope>
{
    private readonly IServiceProvider _services;

    public IdentityAccessSecureEnvelopeHandler(IServiceProvider services)
    {
        _services = services;
    }

    public async Task<Result<object, FailureBase>> HandleAsync(
        SecureEnvelope envelope,
        EventMetadata metadata,
        CancellationToken cancellationToken)
    {
        uint connectId = ResolveConnectId(metadata);

        using IServiceScope scope = _services.CreateScope();

        GrpcCallContext context = BuildContext(metadata, connectId, cancellationToken);
        try
        {
            // Route to existing gRPC services to reuse decryption/business logic.
            return metadata.EventType switch
            {
                var t when t == IdentityAccessEventType.IdentityAccessRegistrationInit.ToString() => await HandleRegistrationInit(scope, envelope, context),
                var t when t == IdentityAccessEventType.IdentityAccessRegistrationComplete.ToString() => await HandleRegistrationComplete(scope, envelope, context),
                var t when t == IdentityAccessEventType.IdentityAccessRecoveryInit.ToString() => await HandleRecoveryInit(scope, envelope, context),
                var t when t == IdentityAccessEventType.IdentityAccessRecoveryComplete.ToString() => await HandleRecoveryComplete(scope, envelope, context),
                var t when t == IdentityAccessEventType.IdentityAccessSignInInit.ToString() => await HandleMembershipSignIn(scope, envelope, context),
                var t when t == IdentityAccessEventType.IdentityAccessSignInComplete.ToString() => await HandleMembershipSignInComplete(scope, envelope, context),
                var t when t == IdentityAccessEventType.IdentityAccessLogout.ToString() => await HandleMembershipLogout(scope, envelope, context),
                var t when t == IdentityAccessEventType.IdentityAccessLogoutAnonymous.ToString() => await HandleMembershipLogoutAnonymous(scope, envelope, context),
                var t when t == IdentityAccessEventType.IdentityAccessGetMasterKeyShares.ToString() => await HandleGetMasterKeyShares(scope, envelope, context),
                var t when t == IdentityAccessEventType.IdentityAccessVerifyOtp.ToString() => await HandleVerifyOtp(scope, envelope, context),
                var t when t == IdentityAccessEventType.IdentityAccessValidateMobileNumber.ToString() => await HandleValidateMobile(scope, envelope, context),
                var t when t == IdentityAccessEventType.IdentityAccessCheckMobileAvailability.ToString() => await HandleCheckMobileAvailability(scope, envelope, context),
                var t when t == IdentityAccessEventType.IdentityAccessRecoveryMobileVerification.ToString() => await HandleRecoveryMobileVerification(scope, envelope, context),
                _ => Result<object, FailureBase>.Err(MetaDataSystemFailure.ComponentNotFound(
                    $"Unsupported IdentityAccess eventType '{metadata.EventType}'"))
            };
        }
        catch (RpcException rpcEx)
        {
            return Result<object, FailureBase>.Err(new MetaDataSystemFailure(
                MetaDataSystemFailureType.RequiredComponentNotFound,
                $"RPC failure: {rpcEx.Status.Detail}",
                rpcEx));
        }
        catch (Exception ex)
        {
            return Result<object, FailureBase>.Err(new MetaDataSystemFailure(
                MetaDataSystemFailureType.RequiredComponentNotFound,
                "Unhandled exception in IdentityAccess handler",
                ex));
        }
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

        throw new RpcException(new Status(StatusCode.InvalidArgument, "connect_id is required"));
    }

    private static GrpcCallContext BuildContext(EventMetadata metadata, uint connectId, CancellationToken cancellationToken)
    {
        Metadata headers = new();
        if (!string.IsNullOrWhiteSpace(metadata.IdempotencyKey))
        {
            headers.Add(MetadataConstants.Keys.IdempotencyKey, metadata.IdempotencyKey);
        }
        else if (!string.IsNullOrWhiteSpace(metadata.CorrelationId))
        {
            headers.Add(MetadataConstants.Keys.IdempotencyKey, metadata.CorrelationId);
        }

        GrpcCallContext ctx = new(metadata.EventType ?? "identity_access", "transport", headers, cancellationToken);
        ctx.UserState[GrpcMetadataHandler.UniqueConnectId] = connectId;
        return ctx;
    }

    private static async Task<Result<object, FailureBase>> HandleRegistrationInit(
        IServiceScope scope,
        SecureEnvelope envelope,
        ServerCallContext context)
    {
        MembershipServices svc = scope.ServiceProvider.GetRequiredService<MembershipServices>();
        SecureEnvelope response = await svc.OpaqueRegistrationInitRequest(envelope, context);
        return Result<object, FailureBase>.Ok(response);
    }

    private static async Task<Result<object, FailureBase>> HandleRegistrationComplete(
        IServiceScope scope,
        SecureEnvelope envelope,
        ServerCallContext context)
    {
        MembershipServices svc = scope.ServiceProvider.GetRequiredService<MembershipServices>();
        SecureEnvelope response = await svc.OpaqueRegistrationCompleteRequest(envelope, context);
        return Result<object, FailureBase>.Ok(response);
    }

    private static async Task<Result<object, FailureBase>> HandleRecoveryInit(
        IServiceScope scope,
        SecureEnvelope envelope,
        ServerCallContext context)
    {
        MembershipServices svc = scope.ServiceProvider.GetRequiredService<MembershipServices>();
        SecureEnvelope response = await svc.OpaqueRecoverySecretKeyInitRequest(envelope, context);
        return Result<object, FailureBase>.Ok(response);
    }

    private static async Task<Result<object, FailureBase>> HandleRecoveryComplete(
        IServiceScope scope,
        SecureEnvelope envelope,
        ServerCallContext context)
    {
        MembershipServices svc = scope.ServiceProvider.GetRequiredService<MembershipServices>();
        SecureEnvelope response = await svc.OpaqueRecoverySecretKeyCompleteRequest(envelope, context);
        return Result<object, FailureBase>.Ok(response);
    }

    private static async Task<Result<object, FailureBase>> HandleMembershipSignIn(
        IServiceScope scope,
        SecureEnvelope envelope,
        ServerCallContext context)
    {
        MembershipServices svc = scope.ServiceProvider.GetRequiredService<MembershipServices>();
        SecureEnvelope response = await svc.OpaqueSignInInitRequest(envelope, context);
        return Result<object, FailureBase>.Ok(response);
    }

    private static async Task<Result<object, FailureBase>> HandleMembershipSignInComplete(
        IServiceScope scope,
        SecureEnvelope envelope,
        ServerCallContext context)
    {
        MembershipServices svc = scope.ServiceProvider.GetRequiredService<MembershipServices>();
        SecureEnvelope response = await svc.OpaqueSignInCompleteRequest(envelope, context);
        return Result<object, FailureBase>.Ok(response);
    }

    private static async Task<Result<object, FailureBase>> HandleMembershipLogout(
        IServiceScope scope,
        SecureEnvelope envelope,
        ServerCallContext context)
    {
        MembershipServices svc = scope.ServiceProvider.GetRequiredService<MembershipServices>();
        SecureEnvelope response = await svc.Logout(envelope, context);
        return Result<object, FailureBase>.Ok(response);
    }

    private static async Task<Result<object, FailureBase>> HandleMembershipLogoutAnonymous(
        IServiceScope scope,
        SecureEnvelope envelope,
        ServerCallContext context)
    {
        MembershipServices svc = scope.ServiceProvider.GetRequiredService<MembershipServices>();
        SecureEnvelope response = await svc.AnonymousLogout(envelope, context);
        return Result<object, FailureBase>.Ok(response);
    }

    private static async Task<Result<object, FailureBase>> HandleGetMasterKeyShares(
        IServiceScope scope,
        SecureEnvelope envelope,
        ServerCallContext context)
    {
        MembershipServices svc = scope.ServiceProvider.GetRequiredService<MembershipServices>();
        SecureEnvelope response = await svc.GetMasterKeyShares(envelope, context);
        return Result<object, FailureBase>.Ok(response);
    }

    private static async Task<Result<object, FailureBase>> HandleVerifyOtp(
        IServiceScope scope,
        SecureEnvelope envelope,
        ServerCallContext context)
    {
        VerificationFlowServices svc = scope.ServiceProvider.GetRequiredService<VerificationFlowServices>();
        SecureEnvelope response = await svc.VerifyOtp(envelope, context);
        return Result<object, FailureBase>.Ok(response);
    }

    private static async Task<Result<object, FailureBase>> HandleValidateMobile(
        IServiceScope scope,
        SecureEnvelope envelope,
        ServerCallContext context)
    {
        VerificationFlowServices svc = scope.ServiceProvider.GetRequiredService<VerificationFlowServices>();
        SecureEnvelope response = await svc.ValidateMobileNumber(envelope, context);
        return Result<object, FailureBase>.Ok(response);
    }

    private static async Task<Result<object, FailureBase>> HandleCheckMobileAvailability(
        IServiceScope scope,
        SecureEnvelope envelope,
        ServerCallContext context)
    {
        VerificationFlowServices svc = scope.ServiceProvider.GetRequiredService<VerificationFlowServices>();
        SecureEnvelope response = await svc.CheckMobileNumberAvailability(envelope, context);
        return Result<object, FailureBase>.Ok(response);
    }

    private static async Task<Result<object, FailureBase>> HandleRecoveryMobileVerification(
        IServiceScope scope,
        SecureEnvelope envelope,
        ServerCallContext context)
    {
        VerificationFlowServices svc = scope.ServiceProvider.GetRequiredService<VerificationFlowServices>();
        SecureEnvelope response = await svc.RecoverySecretKeyMobileVerification(envelope, context);
        return Result<object, FailureBase>.Ok(response);
    }
}

using System.Diagnostics;
using System.Text;
using Akka.Actor;
using Ecliptix.Core.Domain.Actors;
using static Ecliptix.Core.Domain.Actors.EcliptixProtocolSystemActor;
using Ecliptix.Core.Infrastructure.Grpc.Utilities.Utilities.CipherPayloadHandler;
using Ecliptix.Core.Observability;
using Ecliptix.Domain.AppDevices.Events;
using Ecliptix.Domain.AppDevices.Failures;
using Ecliptix.Domain.Utilities;
using Ecliptix.Protobuf.Common;
using Ecliptix.Protobuf.Protocol;
using Ecliptix.Protobuf.Device;
using AppDevice = Ecliptix.Protobuf.Device.AppDevice;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.ObjectPool;
using Grpc.Core;

namespace Ecliptix.Core.Api.Grpc.Base;

/// <summary>
/// Base class for device-related gRPC services.
/// Provides device-specific operations like secure channel management and device registration.
/// </summary>
public abstract class DeviceServiceBase : ActorGrpcServiceBase<IActorRef>
{
    protected readonly IActorRef AppDevicePersistorActor;
    protected readonly IActorRef ProtocolActor;

    protected DeviceServiceBase(
        ILogger logger,
        ActivitySource activitySource,
        ObjectPool<StringBuilder> stringBuilderPool,
        IGrpcCipherService cipherService,
        ObjectPool<EncryptionContext> encryptionContextPool,
        IEcliptixActorRegistry actorRegistry)
        : base(logger, activitySource, stringBuilderPool, cipherService, encryptionContextPool, 
               actorRegistry, ActorIds.AppDevicePersistorActor)
    {
        AppDevicePersistorActor = actorRegistry.Get(ActorIds.AppDevicePersistorActor);
        ProtocolActor = actorRegistry.Get(ActorIds.EcliptixProtocolSystemActor);
    }

    /// <summary>
    /// Executes a plain (unencrypted) device operation
    /// </summary>
    protected async Task<TResponse> ExecutePlainDeviceOperationAsync<TRequest, TResponse>(
        TRequest request,
        uint connectId,
        Func<TRequest, uint, CancellationToken, Task<Result<TResponse, FailureBase>>> handler,
        CancellationToken cancellationToken)
        where TRequest : class
        where TResponse : class
    {
        using var activity = ActivitySource.StartActivity("PlainDeviceOperation");
        activity?.SetTag("connect_id", connectId);
        activity?.SetTag("request_type", typeof(TRequest).Name);

        ValidateConnectionId(connectId);

        var result = await handler(request, connectId, cancellationToken);
        
        if (result.IsOk)
        {
            activity?.SetTag("success", true);
            return result.Unwrap();
        }

        activity?.SetTag("success", false);
        activity?.SetTag("failure_type", result.UnwrapErr().GetType().Name);
        
        var failure = result.UnwrapErr();
        Logger.LogWarning("Device operation failed for connect ID {ConnectId}: {Message}", 
            connectId, failure.Message);
            
        throw new RpcException(failure.ToGrpcStatus());
    }

    /// <summary>
    /// Handles secure channel establishment with the protocol actor
    /// </summary>
    protected async Task<PubKeyExchange> EstablishSecureChannelAsync(
        PubKeyExchange request,
        uint connectId,
        CancellationToken cancellationToken)
    {
        using var activity = ActivitySource.StartActivity("EstablishSecureChannel");
        activity?.SetTag("connect_id", connectId);
        activity?.SetTag("exchange_type", request.OfType.ToString());

        // Create the actor event for beginning ephemeral connection
        var actorEvent = new BeginAppDeviceEphemeralConnectActorEvent(request, connectId);

        // Send to protocol actor with timeout
        var reply = await AskActorAsync<BeginAppDeviceEphemeralConnectActorEvent, 
            Result<DeriveSharedSecretReply, EcliptixProtocolFailure>>(
            ProtocolActor, actorEvent, cancellationToken);

        if (reply.IsOk)
        {
            activity?.SetTag("success", true);
            return reply.Unwrap().PubKeyExchange;
        }

        activity?.SetTag("success", false);
        var failure = reply.UnwrapErr();
        Logger.LogError("Failed to establish secure channel for connect ID {ConnectId}: {Message}", 
            connectId, failure.Message);
            
        throw new RpcException(failure.ToGrpcStatus());
    }

    /// <summary>
    /// Handles secure channel restoration
    /// </summary>
    protected async Task<RestoreChannelResponse> RestoreSecureChannelAsync(
        uint connectId,
        CancellationToken cancellationToken)
    {
        using var activity = ActivitySource.StartActivity("RestoreSecureChannel");
        activity?.SetTag("connect_id", connectId);

        var restoreEvent = new RestoreAppDeviceSecrecyChannelState();
        var forwardEvent = new ForwardToConnectActorEvent(connectId, restoreEvent);

        var result = await AskActorAsync<ForwardToConnectActorEvent, 
            Result<RestoreChannelResponse, EcliptixProtocolFailure>>(
            ProtocolActor, forwardEvent, cancellationToken);

        if (result.IsOk)
        {
            activity?.SetTag("success", true);
            return result.Unwrap();
        }

        var failure = result.UnwrapErr();
        activity?.SetTag("success", false);
        activity?.SetTag("failure_type", failure.FailureType.ToString());

        // Handle specific failure cases
        if (failure.FailureType == EcliptixProtocolFailureType.ActorRefNotFound ||
            failure.FailureType == EcliptixProtocolFailureType.StateMissing ||
            ProtocolActor.IsNobody())
        {
            Logger.LogInformation("Session not found for connect ID {ConnectId}, returning not found status", connectId);
            return new RestoreChannelResponse
            {
                Status = RestoreChannelResponse.Types.Status.SessionNotFound
            };
        }

        Logger.LogError("Failed to restore secure channel for connect ID {ConnectId}: {Message}", 
            connectId, failure.Message);
            
        throw new RpcException(failure.ToGrpcStatus());
    }

    /// <summary>
    /// Handles device registration with the persistor actor
    /// </summary>
    protected async Task<TResponse> RegisterDeviceAsync<TResponse>(
        AppDevice deviceRequest,
        CancellationToken cancellationToken)
        where TResponse : class
    {
        using var activity = ActivitySource.StartActivity("RegisterDevice");
        activity?.SetTag("request_type", typeof(AppDevice).Name);

        var registerEvent = new RegisterAppDeviceIfNotExistActorEvent(deviceRequest);

        var result = await AskActorAsync<RegisterAppDeviceIfNotExistActorEvent, 
            Result<TResponse, AppDeviceFailure>>(
            AppDevicePersistorActor, registerEvent, cancellationToken);

        if (result.IsOk)
        {
            activity?.SetTag("success", true);
            return result.Unwrap();
        }

        activity?.SetTag("success", false);
        var failure = result.UnwrapErr();
        Logger.LogError("Device registration failed: {Message}", failure.Message);
        throw new RpcException(failure.ToGrpcStatus());
    }

    /// <summary>
    /// Validates that a device connection is in a valid state
    /// </summary>
    protected async Task<bool> ValidateDeviceConnectionAsync(uint connectId, CancellationToken cancellationToken)
    {
        using var activity = ActivitySource.StartActivity("ValidateDeviceConnection");
        activity?.SetTag("connect_id", connectId);

        try
        {
            // Check if the protocol actor can find the connection
            var isResponsive = await IsActorResponsiveAsync(ProtocolActor);
            if (!isResponsive)
            {
                activity?.SetTag("protocol_actor_responsive", false);
                return false;
            }

            // Additional validation logic can be added here
            activity?.SetTag("validation_result", true);
            return true;
        }
        catch (Exception ex)
        {
            activity?.SetTag("validation_result", false);
            Logger.LogWarning(ex, "Device connection validation failed for connect ID {ConnectId}", connectId);
            return false;
        }
    }
}
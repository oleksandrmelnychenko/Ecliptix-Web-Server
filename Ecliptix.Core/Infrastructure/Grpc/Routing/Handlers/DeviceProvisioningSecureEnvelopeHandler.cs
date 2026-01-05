using Ecliptix.Core.Infrastructure.Grpc.Routing;
using Ecliptix.Core.Infrastructure.Grpc.Utilities.Utilities;
using Ecliptix.Protobuf.Common;
using Ecliptix.Protobuf.Transport.Common;
using Ecliptix.Protobuf.Transport.DeviceProvisioning;
using Ecliptix.SharedKernel;
using Ecliptix.SharedKernel.Grpc.Utilities;
using Grpc.Core;
using Microsoft.Extensions.DependencyInjection;
using DeviceService = Ecliptix.DeviceProvisioning.Infrastructure.Grpc.DeviceService;
using RestoreChannelRequest = Ecliptix.Protobuf.Device.RestoreChannelRequest;
using RestoreChannelResponse = Ecliptix.Protobuf.Device.RestoreChannelResponse;

namespace Ecliptix.Core.Infrastructure.Grpc.Routing.Handlers;

public sealed class DeviceProvisioningSecureEnvelopeHandler : IEventHandler<SecureEnvelope>
{
    private readonly IServiceProvider _services;

    public DeviceProvisioningSecureEnvelopeHandler(IServiceProvider services)
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
            return metadata.EventType switch
            {
                var t when t == DeviceProvisioningEventType.DeviceProvisioningRegisterDevice.ToString() =>
                    await HandleRegister(scope, envelope, context),
                var t when t == DeviceProvisioningEventType.DeviceProvisioningSecureChannelEstablish.ToString() =>
                    await HandleEstablish(scope, envelope, context),
                var t when t == DeviceProvisioningEventType.DeviceProvisioningSecureChannelRestore.ToString() =>
                    await HandleRestore(scope, envelope, context),
                _ => Result<object, FailureBase>.Err(MetaDataSystemFailure.ComponentNotFound(
                    $"Unsupported DeviceProvisioning eventType '{metadata.EventType}'"))
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
                "Unhandled exception in DeviceProvisioning handler",
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

        GrpcCallContext ctx = new(metadata.EventType ?? "device_provisioning", "transport", headers, cancellationToken);
        ctx.UserState[GrpcMetadataHandler.UniqueConnectId] = connectId;
        return ctx;
    }

    private static async Task<Result<object, FailureBase>> HandleRegister(
        IServiceScope scope,
        SecureEnvelope envelope,
        ServerCallContext context)
    {
        DeviceService svc = scope.ServiceProvider.GetRequiredService<DeviceService>();
        SecureEnvelope response = await svc.RegisterDevice(envelope, context);
        return Result<object, FailureBase>.Ok(response);
    }

    private static async Task<Result<object, FailureBase>> HandleEstablish(
        IServiceScope scope,
        SecureEnvelope envelope,
        ServerCallContext context)
    {
        DeviceService svc = scope.ServiceProvider.GetRequiredService<DeviceService>();
        SecureEnvelope response = await svc.EstablishSecureChannel(envelope, context);
        return Result<object, FailureBase>.Ok(response);
    }

    private static async Task<Result<object, FailureBase>> HandleRestore(
        IServiceScope scope,
        SecureEnvelope _,
        ServerCallContext context)
    {
        DeviceService svc = scope.ServiceProvider.GetRequiredService<DeviceService>();
        // RestoreChannelRequest has no fields; we construct a default instance.
        RestoreChannelResponse response = await svc.RestoreSecureChannel(new RestoreChannelRequest(), context);
        return Result<object, FailureBase>.Ok(response);
    }
}

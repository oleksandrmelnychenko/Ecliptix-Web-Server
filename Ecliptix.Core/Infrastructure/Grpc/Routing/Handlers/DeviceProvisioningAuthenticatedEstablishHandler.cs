using DeviceService = Ecliptix.DeviceProvisioning.Infrastructure.Grpc.DeviceService;
using Ecliptix.Core.Infrastructure.Grpc.Utilities.Utilities;
using Ecliptix.Protobuf.Device;
using Ecliptix.Protobuf.Common;
using Ecliptix.Protobuf.Transport.Common;
using Ecliptix.SharedKernel;
using Ecliptix.SharedKernel.Grpc.Utilities;
using Grpc.Core;
using Microsoft.Extensions.DependencyInjection;

namespace Ecliptix.Core.Infrastructure.Grpc.Routing.Handlers;

public sealed class DeviceProvisioningAuthenticatedEstablishHandler : IEventHandler<AuthenticatedEstablishRequest>
{
    private readonly IServiceProvider _services;

    public DeviceProvisioningAuthenticatedEstablishHandler(IServiceProvider services)
    {
        _services = services;
    }

    public async Task<Result<object, FailureBase>> HandleAsync(
        AuthenticatedEstablishRequest request,
        EventMetadata metadata,
        CancellationToken cancellationToken)
    {
        if (!uint.TryParse(metadata.PartitionKey, out uint connectId))
        {
            return Result<object, FailureBase>.Err(MetaDataSystemFailure.ComponentNotFound(
                "partition_key missing or not a valid connectId"));
        }

        using IServiceScope scope = _services.CreateScope();
        GrpcCallContext context = BuildContext(metadata, connectId, cancellationToken);

        DeviceService svc = scope.ServiceProvider.GetRequiredService<DeviceService>();
        SecureEnvelope response = await svc.AuthenticatedEstablishSecureChannel(request, context);
        return Result<object, FailureBase>.Ok(response);
    }

    private static GrpcCallContext BuildContext(EventMetadata metadata, uint connectId, CancellationToken cancellationToken)
    {
        Metadata headers = new();
        if (!string.IsNullOrWhiteSpace(metadata.CorrelationId))
        {
            headers.Add(MetadataConstants.Keys.IdempotencyKey, metadata.CorrelationId);
        }

        GrpcCallContext ctx = new(metadata.EventType ?? "device_provisioning.auth_establish", "transport", headers, cancellationToken);
        ctx.UserState[GrpcMetadataHandler.UniqueConnectId] = connectId;
        return ctx;
    }
}

using System.Globalization;
using Ecliptix.Protobuf.Protocol;
using Ecliptix.Protobuf.Transport.Common;
using Ecliptix.SharedKernel.Grpc.Utilities;
using Grpc.Core;

namespace Ecliptix.Core.Infrastructure.Grpc.Routing;

internal static class GrpcCallContextFactory
{
    private const string TransportHost = "transport";

    public static uint ResolveConnectId(EventMetadata metadata)
    {
        return metadata.Security?.ConnectId != 0
            ? metadata.Security!.ConnectId
            : throw new RpcException(new Status(StatusCode.InvalidArgument, "connect_id is required"));
    }

    public static GrpcCallContext BuildContext(
        EventMetadata metadata,
        uint connectId,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(metadata);

        Metadata headers = [];
        headers.Add(MetadataConstants.Keys.ConnectId, connectId.ToString(CultureInfo.InvariantCulture));
        headers.Add(MetadataConstants.Keys.ConnectionContextId,
            !string.IsNullOrWhiteSpace(metadata.Security?.KeyExchangeContext)
                ? metadata.Security.KeyExchangeContext
                : nameof(PubKeyExchangeType.DataCenterEphemeralConnect));

        if (!string.IsNullOrWhiteSpace(metadata.Client?.IdempotencyKey))
        {
            headers.Add(MetadataConstants.Keys.IdempotencyKey, metadata.Client.IdempotencyKey);
        }
        else if (!string.IsNullOrWhiteSpace(metadata.Identity?.CorrelationId))
        {
            headers.Add(MetadataConstants.Keys.IdempotencyKey, metadata.Identity.CorrelationId);
        }

        if (!string.IsNullOrWhiteSpace(metadata.Identity?.CorrelationId))
        {
            headers.Add(MetadataConstants.Keys.CorrelationId, metadata.Identity.CorrelationId);
        }

        if (!string.IsNullOrWhiteSpace(metadata.Client?.RequestId))
        {
            headers.Add(MetadataConstants.Keys.RequestId, metadata.Client.RequestId);
        }

        if (!string.IsNullOrWhiteSpace(metadata.Client?.Platform))
        {
            headers.Add(MetadataConstants.Keys.Platform, metadata.Client.Platform);
        }

        if (!string.IsNullOrWhiteSpace(metadata.Client?.Locale))
        {
            headers.Add(MetadataConstants.Keys.Locale, metadata.Client.Locale);
        }

        if (!string.IsNullOrWhiteSpace(metadata.Client?.Version))
        {
            headers.Add(MetadataConstants.Keys.Version, metadata.Client.Version);
        }

        if (!string.IsNullOrWhiteSpace(metadata.Client?.Tenant))
        {
            headers.Add(MetadataConstants.Keys.Tenant, metadata.Client.Tenant);
        }

        if (metadata.Client?.DeviceId != null && !metadata.Client.DeviceId.IsEmpty)
        {
            headers.Add(MetadataConstants.Keys.DeviceId, metadata.Client.DeviceId.ToBase64());
        }

        if (metadata.Client?.ApplicationInstanceId != null && !metadata.Client.ApplicationInstanceId.IsEmpty)
        {
            headers.Add(MetadataConstants.Keys.ApplicationInstanceId, metadata.Client.ApplicationInstanceId.ToBase64());
        }

        if (metadata.Identity?.EventType is null or TransportEventType.Unspecified)
        {
            throw new ArgumentException("event_type is required", nameof(metadata));
        }

        GrpcCallContext ctx = new(metadata.Identity.EventType.ToString(), TransportHost, headers, cancellationToken)
        {
            UserState = { [GrpcMetadataHandler.UniqueConnectId] = connectId }
        };
        return ctx;
    }
}

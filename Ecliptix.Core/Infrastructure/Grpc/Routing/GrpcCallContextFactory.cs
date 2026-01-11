using System.Globalization;
using Ecliptix.Core.Infrastructure.Grpc.Utilities.Utilities;
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
        if (metadata.ConnectId != 0)
        {
            return metadata.ConnectId;
        }

        throw new RpcException(new Status(StatusCode.InvalidArgument, "connect_id is required"));
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
            !string.IsNullOrWhiteSpace(metadata.KeyExchangeContext)
                ? metadata.KeyExchangeContext
                : nameof(PubKeyExchangeType.DataCenterEphemeralConnect));

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

        if (metadata.EventType == TransportEventType.Unspecified)
        {
            throw new ArgumentException("event_type is required", nameof(metadata));
        }
        GrpcCallContext ctx = new(metadata.EventType.ToString(), TransportHost, headers, cancellationToken)
        {
            UserState = { [GrpcMetadataHandler.UniqueConnectId] = connectId }
        };
        return ctx;
    }
}

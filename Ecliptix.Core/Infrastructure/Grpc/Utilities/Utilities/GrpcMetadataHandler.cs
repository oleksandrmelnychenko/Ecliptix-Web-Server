using System.Buffers.Binary;
using System.Security.Cryptography;
using Ecliptix.Domain.Utilities;
using Ecliptix.Protobuf.Protocol;
using Grpc.Core;
using Ecliptix.Core.Infrastructure.Grpc.Constants;

namespace Ecliptix.Core.Infrastructure.Grpc.Utilities.Utilities;

public static class GrpcMetadataHandler
{
    private const string RequestIdKey = "request-id";
    private const string DateTimeKey = "request-date";

    private const string LocalIpAddressKey = "local-ip-address";
    private const string PublicIpAddressKey = "public-ip-address";

    private const string LocaleKey = "lang";
    private const string LinkIdKey = "fetch-link";
    private const string ApplicationInstanceIdKey = "application-identifier";

    private const string AppDeviceId = "d-identifier";
    private const string KeyExchangeContextTypeValue = "JmTGdGilMka07zyg5hz6Q";
    private const string KeyExchangeContextTypeKey = "oiwfT6c5kOQsZozxhTBg";

    public const string UniqueConnectId = InterceptorConstants.Connections.UniqueConnectIdKey;

    /// <summary>
    ///     Name of the connection, like (AppDeviceEphemeralConnect)
    /// </summary>
    private const string ConnectionContextId = "c-context-id";

    /// <summary>
    ///     This value is used to identify the operation context id in the metadata (Chats, Calls, etc.)
    /// </summary>
    private const string OperationContextId = "o-context-id";

    private static readonly List<string> AllowedKeyExchangeContextTypes = [KeyExchangeContextTypeValue];

    public static Result<Unit, MetaDataSystemFailure> ValidateRequiredMetaDataParams(Metadata requestHeaders)
    {
        return requestHeaders.GetValueAsResult(LinkIdKey)
            .AndThen(_ => requestHeaders.GetValueAsResult(ApplicationInstanceIdKey))
            .AndThen(_ => requestHeaders.GetValueAsResult(KeyExchangeContextTypeKey))
            .Bind(contextTypeValue =>
            {
                if (!AllowedKeyExchangeContextTypes.Contains(contextTypeValue))
                    return Result<string, MetaDataSystemFailure>.Err(
                        MetaDataSystemFailure.ComponentNotFound(contextTypeValue));

                return Result<string, MetaDataSystemFailure>.Ok(contextTypeValue);
            })
            .AndThen(_ => requestHeaders.GetValueAsResult(LocaleKey))
            .AndThen(_ => requestHeaders.GetValueAsResult(AppDeviceId))
            .AndThen(_ => requestHeaders.GetValueAsResult(ConnectionContextId))
            .Map(_ => Unit.Value);
    }

    public static Result<uint, MetaDataSystemFailure> ComputeUniqueConnectId(Metadata requestHeaders)
    {
        return requestHeaders.GetValueAsResult(ApplicationInstanceIdKey)
            .Bind(appInstanceIdStr => Guid.TryParse(appInstanceIdStr, out Guid appInstanceId)
                ? Result<Guid, MetaDataSystemFailure>.Ok(appInstanceId)
                : Result<Guid, MetaDataSystemFailure>.Err(
                    MetaDataSystemFailure.ComponentNotFound(
                        $"Invalid Guid format for key '{ApplicationInstanceIdKey}'")))
            .AndThen(appInstanceId => requestHeaders.GetValueAsResult(AppDeviceId)
                .Bind(appDeviceIdStr => Guid.TryParse(appDeviceIdStr, out Guid appDeviceId)
                    ? Result<Guid, MetaDataSystemFailure>.Ok(appDeviceId)
                    : Result<Guid, MetaDataSystemFailure>.Err(
                        MetaDataSystemFailure.ComponentNotFound($"Invalid Guid format for key '{AppDeviceId}'")))
                .Map(appDeviceId => (appInstanceId, appDeviceId)))
            .AndThen(data => requestHeaders.GetValueAsResult(ConnectionContextId)
                .Bind(connectionContextIdStr =>
                    Enum.TryParse(connectionContextIdStr, true, out PubKeyExchangeType contextType) &&
                    Enum.IsDefined(contextType)
                        ? Result<PubKeyExchangeType, MetaDataSystemFailure>.Ok(contextType)
                        : Result<PubKeyExchangeType, MetaDataSystemFailure>.Err(
                            MetaDataSystemFailure.ComponentNotFound(
                                $"Invalid PubKeyExchangeType for key '{ConnectionContextId}'")))
                .Map(contextType => (data.appInstanceId, data.appDeviceId, contextType)))
            .AndThen(data => requestHeaders.GetValueAsResult(OperationContextId)
                .Match(
                    opContextIdStr => Guid.TryParse(opContextIdStr, out Guid opContextId)
                        ? Result<Guid?, MetaDataSystemFailure>.Ok(opContextId)
                        : Result<Guid?, MetaDataSystemFailure>.Ok(null),
                    _ => Result<Guid?, MetaDataSystemFailure>.Ok(null))
                .Map(opContextId => (data.appInstanceId, data.appDeviceId, data.contextType, opContextId)))
            .Map(data =>
            {
                byte[] appInstanceIdBytes = data.appInstanceId.ToByteArray();
                byte[] appDeviceIdBytes = data.appDeviceId.ToByteArray();
                uint contextTypeUint = (uint)data.contextType;
                byte[] contextTypeBytes = BitConverter.GetBytes(contextTypeUint);
                if (BitConverter.IsLittleEndian) Array.Reverse(contextTypeBytes);

                int totalLength = appInstanceIdBytes.Length + appDeviceIdBytes.Length + contextTypeBytes.Length;
                if (data.opContextId.HasValue) totalLength += 16;

                byte[] combined = new byte[totalLength];
                int offset = 0;
                Buffer.BlockCopy(appInstanceIdBytes, 0, combined, offset, appInstanceIdBytes.Length);
                offset += appInstanceIdBytes.Length;
                Buffer.BlockCopy(appDeviceIdBytes, 0, combined, offset, appDeviceIdBytes.Length);
                offset += appDeviceIdBytes.Length;
                Buffer.BlockCopy(contextTypeBytes, 0, combined, offset, contextTypeBytes.Length);
                offset += contextTypeBytes.Length;
                if (data.opContextId.HasValue)
                {
                    byte[] opContextBytes = data.opContextId.Value.ToByteArray();
                    Buffer.BlockCopy(opContextBytes, 0, combined, offset, opContextBytes.Length);
                }

                byte[] hash = SHA256.HashData(combined);
                return BinaryPrimitives.ReadUInt32BigEndian(hash.AsSpan(0, 4));
            });
    }

    public static string GetRequestedLocale(Metadata requestHeaders)
    {
        return requestHeaders.GetValueAsResult(LocaleKey).Unwrap();
    }

    public static string GetAppDeviceId(Metadata requestHeaders)
    {
        return requestHeaders.GetValueAsResult(AppDeviceId).Unwrap();
    }

    public static string GetConnectionContextId(Metadata requestHeaders)
    {
        return requestHeaders.GetValueAsResult(ConnectionContextId).Unwrap();
    }

    public static Result<string, MetaDataSystemFailure> GetOperationContextId(Metadata requestHeaders)
    {
        return requestHeaders.GetValueAsResult(OperationContextId);
    }

    public static Result<ExtractedMetadata, MetaDataSystemFailure> ExtractRequiredMetaData(ServerCallContext context)
    {
        Result<string, MetaDataSystemFailure> requestIdResult = context.RequestHeaders.GetValueAsResult(RequestIdKey);
        Result<string, MetaDataSystemFailure> requestDateResult = context.RequestHeaders.GetValueAsResult(DateTimeKey);
        Result<string, MetaDataSystemFailure> localIpAddressResult =
            context.RequestHeaders.GetValueAsResult(LocalIpAddressKey);
        Result<string, MetaDataSystemFailure> publicIpAddressResult =
            context.RequestHeaders.GetValueAsResult(PublicIpAddressKey);

        ExtractedMetadata metadata = new(
            requestIdResult.IsOk ? requestIdResult.Unwrap() : null,
            requestDateResult.IsOk ? requestDateResult.Unwrap() : null,
            localIpAddressResult.IsOk ? localIpAddressResult.Unwrap() : null,
            publicIpAddressResult.IsOk ? publicIpAddressResult.Unwrap() : null);

        return Result<ExtractedMetadata, MetaDataSystemFailure>.Ok(metadata);
    }

    public record ExtractedMetadata(
        string? RequestId,
        string? RequestDate,
        string? LocalIpAddress,
        string? PublicIpAddress);
}
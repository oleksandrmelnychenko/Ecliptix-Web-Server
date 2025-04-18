using System.Buffers.Binary;
using System.Security.Cryptography;
using Ecliptix.Core.Protocol.Utilities;
using Ecliptix.Protobuf.PubKeyExchange;
using Grpc.Core;

namespace Ecliptix.Core.Services.Utilities;

public static class GrpcMetadataHandler
{
    private const string RequestIdKey = "request-id";
    private const string DateTimeKey = "request-date";

    private const string LocalIpAddressKey = "local-ip-address";
    private const string PublicIpAddressKey = "public-ip-address";

    private const string LocaleKey = "lang";
    private const string LinkIdKey = "fetch-link";
    private const string ApiKey = "api-key";

    private const string AppDeviceId = "d-identifier";
    private const string KeyExchangeContextTypeValue = "JmTGdGilMka07zyg5hz6Q";
    private const string KeyExchangeContextTypeKey = "oiwfT6c5kOQsZozxhTBg";

    public const string UniqueConnectId = "UniqueConnectId";
    
    /// <summary>
    ///     Name of the connection, like (AppDeviceEphemeralConnect)
    /// </summary>
    private const string ConnectionContextId = "c-context-id";

    /// <summary>
    ///     This value is used to identify the operation context id in the metadata (Chats, Calls, etc.)
    /// </summary>
    private const string OperationContextId = "o-context-id";

    private static readonly List<string> AllowedKeyExchangeContextTypes = [KeyExchangeContextTypeValue];

    public static Result<Unit, MetaDataSystemFailure> ValidateRequiredMetaDataParams(Metadata requestHeaders) =>
        requestHeaders.GetValueAsResult(LinkIdKey)
            .AndThen(_ => requestHeaders.GetValueAsResult(ApiKey))
            .AndThen(_ => requestHeaders.GetValueAsResult(KeyExchangeContextTypeKey))
            .Bind(contextTypeValue =>
            {
                if (!AllowedKeyExchangeContextTypes.Contains(contextTypeValue))
                {
                    return Result<string, MetaDataSystemFailure>.Err(
                        MetaDataSystemFailure.ComponentNotFound(contextTypeValue));
                }

                return Result<string, MetaDataSystemFailure>.Ok(contextTypeValue);
            })
            .AndThen(_ => requestHeaders.GetValueAsResult(LocaleKey))
            .AndThen(_ => requestHeaders.GetValueAsResult(AppDeviceId))
            .AndThen(_ => requestHeaders.GetValueAsResult(ConnectionContextId))
            .Map(_ => Unit.Value);

   public static Result<uint, MetaDataSystemFailure> ComputeUniqueConnectId(Metadata requestHeaders) =>
        requestHeaders.GetValueAsResult(AppDeviceId)
            .Bind(appDeviceId =>
            {
                if (!Guid.TryParse(appDeviceId, out Guid guid))
                    return Result<Guid, MetaDataSystemFailure>.Err(
                        MetaDataSystemFailure.ComponentNotFound($"Invalid Guid format for key '{AppDeviceId}'"));
                return Result<Guid, MetaDataSystemFailure>.Ok(guid);
            })
            .AndThen(guid => requestHeaders.GetValueAsResult(ConnectionContextId)
                .Bind(contextId =>
                {
                    if (!Enum.TryParse(contextId, true, out PubKeyExchangeType contextType) ||
                        !Enum.IsDefined(contextType))
                        return Result<PubKeyExchangeType, MetaDataSystemFailure>.Err(
                            MetaDataSystemFailure.ComponentNotFound($"Invalid PubKeyExchangeType for key '{ConnectionContextId}'"));
                    return Result<PubKeyExchangeType, MetaDataSystemFailure>.Ok(contextType);
                })
                .AndThen(contextType => requestHeaders.GetValueAsResult(OperationContextId)
                    .Map(opContextId => Guid.TryParse(opContextId, out Guid opGuid) ? opGuid : (Guid?)null)
                    .Map(opContextGuid => (guid, contextType, opContextGuid))))
            .Map(data =>
            {
                byte[] guidBytes = data.guid.ToByteArray();
                byte[] contextBytes = BitConverter.GetBytes((uint)data.contextType);
                if (BitConverter.IsLittleEndian)
                    Array.Reverse(contextBytes);

                int totalLength = guidBytes.Length + contextBytes.Length + (data.opContextGuid.HasValue ? 16 : 0);
                byte[] combined = new byte[totalLength];
                Buffer.BlockCopy(guidBytes, 0, combined, 0, guidBytes.Length);
                Buffer.BlockCopy(contextBytes, 0, combined, guidBytes.Length, contextBytes.Length);
                if (data.opContextGuid.HasValue)
                {
                    byte[] opContextBytes = data.opContextGuid.Value.ToByteArray();
                    Buffer.BlockCopy(opContextBytes, 0, combined, guidBytes.Length + contextBytes.Length, opContextBytes.Length);
                }

                byte[] hash = SHA256.HashData(combined);
                return BinaryPrimitives.ReadUInt32BigEndian(hash.AsSpan(0, 4));
            });


    public static string GetRequestedLocale(Metadata requestHeaders) =>
        requestHeaders.GetValueAsResult(LocaleKey).Unwrap();

    public static string GetAppDeviceId(Metadata requestHeaders) =>
        requestHeaders.GetValueAsResult(AppDeviceId).Unwrap();

    public static string GetConnectionContextId(Metadata requestHeaders) =>
        requestHeaders.GetValueAsResult(ConnectionContextId).Unwrap();

    public static Result<string, MetaDataSystemFailure> GetOperationContextId(Metadata requestHeaders) =>
        requestHeaders.GetValueAsResult(OperationContextId);

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
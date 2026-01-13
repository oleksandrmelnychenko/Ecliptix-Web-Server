using System.Buffers.Binary;
using System.Security.Cryptography;
using Ecliptix.Core.Infrastructure.Grpc.Constants;
using Ecliptix.Protobuf.Protocol;
using Ecliptix.SharedKernel;
using Ecliptix.SharedKernel.Grpc.Utilities;
using Grpc.Core;

namespace Ecliptix.Core.Infrastructure.Grpc;

public static class GrpcMetadataHandler
{
    private const string LocalIpAddressKey = MetadataConstants.Keys.LocalIpAddress;
    private const string PublicIpAddressKey = MetadataConstants.Keys.PublicIpAddress;

    private const string LocaleKey = MetadataConstants.Keys.Locale;
    private const string LinkIdKey = MetadataConstants.Keys.LinkId;
    private const string ApplicationInstanceIdKey = MetadataConstants.Keys.ApplicationInstanceId;

    private const string AppDeviceId = MetadataConstants.Keys.DeviceId;
    private static string KeyExchangeContextTypeValue => MetadataConstants.SecurityKeys.KeyExchangeContextTypeValue;
    private static string KeyExchangeContextTypeKey => MetadataConstants.SecurityKeys.KeyExchangeContextTypeKey;

    public const string UniqueConnectId = InterceptorConstants.Connections.UniqueConnectIdKey;

    private const string ConnectionContextId = MetadataConstants.Keys.ConnectionContextId;

    private const string OperationContextId = MetadataConstants.Keys.OperationContextId;

    private static readonly List<string> AllowedKeyExchangeContextTypes = [KeyExchangeContextTypeValue];

    public static Result<Unit, MetaDataSystemFailure> ValidateRequiredMetaDataParams(Metadata requestHeaders)
    {
        Result<string, MetaDataSystemFailure> linkIdResult = requestHeaders.GetValueAsResult(LinkIdKey);
        if (linkIdResult.IsErr)
        {
            return Result<Unit, MetaDataSystemFailure>.Err(linkIdResult.UnwrapErr());
        }

        Result<string, MetaDataSystemFailure> appInstanceIdResult =
            requestHeaders.GetValueAsResult(ApplicationInstanceIdKey);
        if (appInstanceIdResult.IsErr)
        {
            return Result<Unit, MetaDataSystemFailure>.Err(appInstanceIdResult.UnwrapErr());
        }

        Result<string, MetaDataSystemFailure> contextTypeResult =
            requestHeaders.GetValueAsResult(KeyExchangeContextTypeKey);
        if (contextTypeResult.IsErr)
        {
            return Result<Unit, MetaDataSystemFailure>.Err(contextTypeResult.UnwrapErr());
        }

        string contextTypeValue = contextTypeResult.Unwrap();
        if (!AllowedKeyExchangeContextTypes.Contains(contextTypeValue))
        {
            return Result<Unit, MetaDataSystemFailure>.Err(MetaDataSystemFailure.ComponentNotFound(contextTypeValue));
        }

        Result<string, MetaDataSystemFailure> localeResult = requestHeaders.GetValueAsResult(LocaleKey);
        if (localeResult.IsErr)
        {
            return Result<Unit, MetaDataSystemFailure>.Err(localeResult.UnwrapErr());
        }

        Result<string, MetaDataSystemFailure> appDeviceIdResult = requestHeaders.GetValueAsResult(AppDeviceId);
        if (appDeviceIdResult.IsErr)
        {
            return Result<Unit, MetaDataSystemFailure>.Err(appDeviceIdResult.UnwrapErr());
        }

        Result<string, MetaDataSystemFailure> connectionContextResult =
            requestHeaders.GetValueAsResult(ConnectionContextId);
        if (connectionContextResult.IsErr)
        {
            return Result<Unit, MetaDataSystemFailure>.Err(connectionContextResult.UnwrapErr());
        }

        return Result<Unit, MetaDataSystemFailure>.Ok(Unit.Value);
    }

    public static Result<uint, MetaDataSystemFailure> ComputeUniqueConnectId(Metadata requestHeaders)
    {
        Result<string, MetaDataSystemFailure> appInstanceIdResult =
            requestHeaders.GetValueAsResult(ApplicationInstanceIdKey);
        if (appInstanceIdResult.IsErr)
        {
            return Result<uint, MetaDataSystemFailure>.Err(appInstanceIdResult.UnwrapErr());
        }

        if (!Guid.TryParse(appInstanceIdResult.Unwrap(), out Guid appInstanceId))
        {
            return Result<uint, MetaDataSystemFailure>.Err(
                MetaDataSystemFailure.ComponentNotFound(string.Format(MetadataConstants.ErrorMessages.InvalidGuidFormat,
                    ApplicationInstanceIdKey)));
        }

        Result<string, MetaDataSystemFailure> appDeviceIdResult = requestHeaders.GetValueAsResult(AppDeviceId);
        if (appDeviceIdResult.IsErr)
        {
            return Result<uint, MetaDataSystemFailure>.Err(appDeviceIdResult.UnwrapErr());
        }

        if (!Guid.TryParse(appDeviceIdResult.Unwrap(), out Guid appDeviceId))
        {
            return Result<uint, MetaDataSystemFailure>.Err(
                MetaDataSystemFailure.ComponentNotFound(string.Format(MetadataConstants.ErrorMessages.InvalidGuidFormat,
                    AppDeviceId)));
        }

        Result<string, MetaDataSystemFailure> connectionContextIdResult =
            requestHeaders.GetValueAsResult(ConnectionContextId);
        if (connectionContextIdResult.IsErr)
        {
            return Result<uint, MetaDataSystemFailure>.Err(connectionContextIdResult.UnwrapErr());
        }

        if (!Enum.TryParse(connectionContextIdResult.Unwrap(), true, out PubKeyExchangeType contextType) ||
            !Enum.IsDefined(contextType))
        {
            return Result<uint, MetaDataSystemFailure>.Err(
                MetaDataSystemFailure.ComponentNotFound(
                    string.Format(MetadataConstants.ErrorMessages.InvalidPubKeyExchangeType, ConnectionContextId)));
        }

        Option<Guid> opContextId = Option<Guid>.None;
        Result<string, MetaDataSystemFailure> operationContextResult =
            requestHeaders.GetValueAsResult(OperationContextId);
        if (operationContextResult.IsOk)
        {
            string opContextIdStr = operationContextResult.Unwrap();
            if (Guid.TryParse(opContextIdStr, out Guid parsedOpContextId))
            {
                opContextId = Option<Guid>.Some(parsedOpContextId);
            }
        }

        return Result<uint, MetaDataSystemFailure>.Ok(ComputeHashFromComponents(appInstanceId, appDeviceId, contextType,
            opContextId));
    }

    private static uint ComputeHashFromComponents(Guid appInstanceId, Guid appDeviceId, PubKeyExchangeType contextType,
        Option<Guid> opContextId)
    {
        const int guidSize = 16;
        const int contextTypeSize = sizeof(uint);
        int totalLength = guidSize + guidSize + contextTypeSize;
        if (opContextId.IsSome)
        {
            totalLength += guidSize;
        }

        Span<byte> buffer = stackalloc byte[totalLength];

        int offset = 0;
        appInstanceId.TryWriteBytes(buffer[offset..]);
        offset += guidSize;

        appDeviceId.TryWriteBytes(buffer[offset..]);
        offset += guidSize;

        BinaryPrimitives.WriteUInt32BigEndian(buffer[offset..], (uint)contextType);
        offset += contextTypeSize;

        if (opContextId.IsSome)
        {
            opContextId.Value.TryWriteBytes(buffer[offset..]);
        }

        Span<byte> hash = stackalloc byte[32];
        SHA256.TryHashData(buffer, hash, out _);

        return BinaryPrimitives.ReadUInt32BigEndian(hash[..MetadataConstants.ByteLengths.HashSpanLength]);
    }

    public static string GetRequestedLocale(Metadata requestHeaders)
    {
        return requestHeaders.GetValueAsResult(LocaleKey).Unwrap();
    }

    public static Option<string> GetConnectionContextId(Metadata requestHeaders)
    {
        return requestHeaders.GetValueAsResult(ConnectionContextId).ToOption();
    }

    public static Option<string> GetLocalIpAddress(Metadata requestHeaders)
    {
        return requestHeaders.GetValueAsResult(LocalIpAddressKey).ToOption();
    }

    public static Option<string> GetPublicIpAddress(Metadata requestHeaders)
    {
        return requestHeaders.GetValueAsResult(PublicIpAddressKey).ToOption();
    }

    public static Option<string> GetPlatform(Metadata requestHeaders)
    {
        return requestHeaders.GetValueAsResult(MetadataConstants.Keys.Platform).ToOption();
    }
}

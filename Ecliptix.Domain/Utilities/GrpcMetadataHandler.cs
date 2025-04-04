using Ecliptix.Protobuf.CipherPayload;
using Grpc.Core;
using Microsoft.Extensions.Configuration;

namespace Ecliptix.Domain.Utilities;

public static class GrpcMetadataHandler {
    private const string ExchangeMethodTypeErrorMessage = "The key exchange context type is missing from the request headers, and therefore the interceptor is unable to determine how to proceed with the key exchange process.";

    private const string ConnectionIdHeaderErrorMessage = "The Connection-Id header is not valid and cannot be used to establish a connection between the client and server.";

    private const string SecretsAreNotMatch = "The secrets provided are invalid and cannot be used to authenticate the user or establish a secure connection.";

    private const string ApiKeyIsInvalid = "The provided API KEY is invalid.";
    
    private const string DeviceAppIdKeyIsInvalid = "The provided mobile app device is invalid.";
    
    private const string RequestIdKey = "request-id";
    private const string DateTimeKey = "request-date";
    private const string LocalIpAddressKey = "local-ip-address";
    private const string PublicIpAddressKey = "public-ip-address";
    private const string LocaleKey = "lang";
    private const string ConnectionIdKey = "fetch-link";
    private const string ApiKey = "api-key";
    private const string DeviceAppIdKey = "d-identifier";
    private const string KeyExchangeContextTypeValue = "JmTGdGilMka07zyg5hz6Q";
    private const string KeyExchangeContextTypeKey = "oiwfT6c5kOQsZozxhTBg";

    public const string MobileDeviceAppId = "MobileDeviceAppId";
    
    private static readonly List<string> AllowedKeyExchangeContextTypes = new() {
        KeyExchangeContextTypeValue
    };

    public static void ValidateRequiredMetaDataParams(Metadata requestHeaders) {
        string? connectionId = requestHeaders.GetValueOrDefault(ConnectionIdKey);
        connectionId.ThrowIfNull(ConnectionIdHeaderErrorMessage);

        string? apiKey = requestHeaders.GetValueOrDefault(ApiKey);
        apiKey.ThrowIfNull(ConnectionIdHeaderErrorMessage);
        
        string? keyExchangeContextTypeValue = requestHeaders.GetValueOrDefault(KeyExchangeContextTypeKey);
        keyExchangeContextTypeValue.ThrowIfNull(ConnectionIdHeaderErrorMessage);
        if (!AllowedKeyExchangeContextTypes.Any(c => c.Equals(keyExchangeContextTypeValue))) {
            throw new ArgumentException(ExchangeMethodTypeErrorMessage);
        }

        string? locale = requestHeaders.GetValueOrDefault(LocaleKey);
        locale.ThrowIfNull(ConnectionIdHeaderErrorMessage);
        
        string? deviceAppId = requestHeaders.GetValueOrDefault(DeviceAppIdKey);
        deviceAppId.ThrowIfNull(DeviceAppIdKeyIsInvalid);
    }

    public static string GetConnectionId(Metadata requestHeaders) => requestHeaders.GetValueOrDefault(ConnectionIdKey)!;
    public static string GetRequestLocale(Metadata requestHeaders) => requestHeaders.GetValueOrDefault(LocaleKey)!;
    public static string GetMobileDeviceAppId(Metadata requestHeaders) => requestHeaders.GetValueOrDefault(DeviceAppIdKey)!;

    public static (string? RequestId, string? RequestDate, string? LocalIpAddress, string? PublicIpAddress) ExtractMetadata(ServerCallContext context) {
        string? requestId = null;
        string? requestDate = null;
        string? localIpAddress = null;
        string? publicIpAddress = null;

        foreach (Metadata.Entry entry in context.RequestHeaders) {
            switch (entry.Key) {
                case RequestIdKey:
                    requestId = entry.Value;
                    break;
                case DateTimeKey:
                    requestDate = entry.Value;
                    break;
                case LocalIpAddressKey:
                    localIpAddress = entry.Value;
                    break;
                case PublicIpAddressKey:
                    publicIpAddress = entry.Value;
                    break;
            }
        }

        return (requestId, requestDate, localIpAddress, publicIpAddress);
    }

    public static void ValidateSecrets(IEnumerable<byte> secretToMatch, IEnumerable<byte> payload) {
        if (!secretToMatch.SequenceEqual(payload)) {
            throw new ArgumentException(SecretsAreNotMatch);
        }
    }
}
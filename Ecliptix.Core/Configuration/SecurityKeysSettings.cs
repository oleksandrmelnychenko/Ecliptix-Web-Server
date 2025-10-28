namespace Ecliptix.Core.Configuration;

internal sealed class SecurityKeysSettings
{
    public string KeyExchangeContextTypeKey { get; set; } = string.Empty;
    public string KeyExchangeContextTypeValue { get; set; } = string.Empty;
    public string OpaqueSecretKeySeed { get; set; } = string.Empty;
}

namespace Ecliptix.Core.Configuration.Settings;

internal sealed class SecurityKeysSettings
{
    public string KeyExchangeContextTypeKey { get; set; } = string.Empty;
    public string KeyExchangeContextTypeValue { get; set; } = string.Empty;
    public string OpaqueSecretKeySeed { get; set; } = string.Empty;
}

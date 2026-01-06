using System.Diagnostics.CodeAnalysis;

namespace Ecliptix.Protobuf.Transport.Common;

/// <summary>
/// Helper shim to expose flattened metadata properties while proto uses grouped sub-messages.
/// </summary>
public sealed partial class EventMetadata
{
    private EventIdentity EnsureIdentity()
    {
        if (Identity == null)
        {
            Identity = new EventIdentity();
        }

        return Identity;
    }

    private ClientContext EnsureClient()
    {
        if (Client == null)
        {
            Client = new ClientContext();
        }

        return Client;
    }

    private SecurityContext EnsureSecurity()
    {
        if (Security == null)
        {
            Security = new SecurityContext();
        }

        return Security;
    }

    private EventOutcome EnsureOutcome()
    {
        if (Outcome == null)
        {
            Outcome = new EventOutcome();
        }

        return Outcome;
    }

    public string EventId
    {
        get => Identity?.EventId ?? string.Empty;
        set => EnsureIdentity().EventId = value ?? string.Empty;
    }

    public string EventType
    {
        get => Identity?.EventType ?? string.Empty;
        set => EnsureIdentity().EventType = value ?? string.Empty;
    }

    public string Context
    {
        get => Identity?.Context ?? string.Empty;
        set => EnsureIdentity().Context = value ?? string.Empty;
    }

    public string CorrelationId
    {
        get => Identity?.CorrelationId ?? string.Empty;
        set => EnsureIdentity().CorrelationId = value ?? string.Empty;
    }

    public string CausationId
    {
        get => Identity?.CausationId ?? string.Empty;
        set => EnsureIdentity().CausationId = value ?? string.Empty;
    }

    public string PartitionKey
    {
        get => Identity?.PartitionKey ?? string.Empty;
        set => EnsureIdentity().PartitionKey = value ?? string.Empty;
    }

    public DeliveryKind DeliveryKind
    {
        get => Identity?.DeliveryKind ?? DeliveryKind.Unspecified;
        set => EnsureIdentity().DeliveryKind = value;
    }

    public string Locale
    {
        get => Client?.Locale ?? string.Empty;
        set => EnsureClient().Locale = value ?? string.Empty;
    }

    public string Tenant
    {
        get => Client?.Tenant ?? string.Empty;
        set => EnsureClient().Tenant = value ?? string.Empty;
    }

    public string RequestId
    {
        get => Client?.RequestId ?? string.Empty;
        set => EnsureClient().RequestId = value ?? string.Empty;
    }

    public string IdempotencyKey
    {
        get => Client?.IdempotencyKey ?? string.Empty;
        set => EnsureClient().IdempotencyKey = value ?? string.Empty;
    }

    public string Platform
    {
        get => Client?.Platform ?? string.Empty;
        set => EnsureClient().Platform = value ?? string.Empty;
    }

    public string Version
    {
        get => Client?.Version ?? string.Empty;
        set => EnsureClient().Version = value ?? string.Empty;
    }

    public string AppDeviceId
    {
        get => Client?.AppDeviceId ?? string.Empty;
        set => EnsureClient().AppDeviceId = value ?? string.Empty;
    }

    public string ApplicationInstanceId
    {
        get => Client?.ApplicationInstanceId ?? string.Empty;
        set => EnsureClient().ApplicationInstanceId = value ?? string.Empty;
    }

    public uint ConnectId
    {
        get => Security?.ConnectId ?? 0;
        set => EnsureSecurity().ConnectId = value;
    }

    public string KeyExchangeContext
    {
        get => Security?.KeyExchangeContext ?? string.Empty;
        set => EnsureSecurity().KeyExchangeContext = value ?? string.Empty;
    }

    public string Status
    {
        get => Outcome?.Status ?? string.Empty;
        set => EnsureOutcome().Status = value ?? string.Empty;
    }

    public string ErrorCode
    {
        get => Outcome?.ErrorCode ?? string.Empty;
        set => EnsureOutcome().ErrorCode = value ?? string.Empty;
    }
}

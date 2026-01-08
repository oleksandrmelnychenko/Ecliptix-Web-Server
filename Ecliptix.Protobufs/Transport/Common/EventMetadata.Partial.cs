namespace Ecliptix.Protobuf.Transport.Common;

public sealed partial class EventMetadata
{
    public string EventId
    {
        get => Identity?.EventId ?? string.Empty;
        set => (Identity ??= new EventIdentity()).EventId = value;
    }

    public TransportEventType EventType
    {
        get => Identity?.EventType ?? TransportEventType.Unspecified;
        set => (Identity ??= new EventIdentity()).EventType = value;
    }

    public EventContext Context
    {
        get => Identity?.Context ?? EventContext.Unspecified;
        set => (Identity ??= new EventIdentity()).Context = value;
    }

    public string CorrelationId
    {
        get => Identity?.CorrelationId ?? string.Empty;
        set => (Identity ??= new EventIdentity()).CorrelationId = value;
    }

    public string CausationId
    {
        get => Identity?.CausationId ?? string.Empty;
        set => (Identity ??= new EventIdentity()).CausationId = value;
    }

    public string PartitionKey
    {
        get => Identity?.PartitionKey ?? string.Empty;
        set => (Identity ??= new EventIdentity()).PartitionKey = value;
    }

    public DeliveryKind DeliveryKind
    {
        get => Identity?.DeliveryKind ?? DeliveryKind.Unspecified;
        set => (Identity ??= new EventIdentity()).DeliveryKind = value;
    }

    public string Locale
    {
        get => Client?.Locale ?? string.Empty;
        set => (Client ??= new ClientContext()).Locale = value;
    }

    public string Tenant
    {
        get => Client?.Tenant ?? string.Empty;
        set => (Client ??= new ClientContext()).Tenant = value;
    }

    public string RequestId
    {
        get => Client?.RequestId ?? string.Empty;
        set => (Client ??= new ClientContext()).RequestId = value;
    }

    public string IdempotencyKey
    {
        get => Client?.IdempotencyKey ?? string.Empty;
        set => (Client ??= new ClientContext()).IdempotencyKey = value;
    }

    public string Platform
    {
        get => Client?.Platform ?? string.Empty;
        set => (Client ??= new ClientContext()).Platform = value;
    }

    public string Version
    {
        get => Client?.Version ?? string.Empty;
        set => (Client ??= new ClientContext()).Version = value;
    }

    public string AppDeviceId
    {
        get => Client?.AppDeviceId ?? string.Empty;
        set => (Client ??= new ClientContext()).AppDeviceId = value;
    }

    public string ApplicationInstanceId
    {
        get => Client?.ApplicationInstanceId ?? string.Empty;
        set => (Client ??= new ClientContext()).ApplicationInstanceId = value;
    }

    public uint ConnectId
    {
        get => Security?.ConnectId ?? 0;
        set => (Security ??= new SecurityContext()).ConnectId = value;
    }

    public string KeyExchangeContext
    {
        get => Security?.KeyExchangeContext ?? string.Empty;
        set => (Security ??= new SecurityContext()).KeyExchangeContext = value;
    }

    public string Status
    {
        get => Outcome?.Status ?? string.Empty;
        set => (Outcome ??= new EventOutcome()).Status = value;
    }

    public string ErrorCode
    {
        get => Outcome?.ErrorCode ?? string.Empty;
        set => (Outcome ??= new EventOutcome()).ErrorCode = value;
    }
}

using Ecliptix.Core.Domain.Protocol;
using Ecliptix.Protobuf.Common;
using Ecliptix.Protobuf.Protocol;

namespace Ecliptix.Core.Domain.Events;

public record BeginAppDeviceEphemeralConnectActorEvent(PubKeyExchange PubKeyExchange, uint UniqueConnectId);

public record DecryptSecureEnvelopeActorEvent(
    PubKeyExchangeType PubKeyExchangeType,
    SecureEnvelope SecureEnvelope);

public record EncryptPayloadActorEvent(
    PubKeyExchangeType PubKeyExchangeType,
    byte[] Payload);

public record EncryptPayloadComponentsActorEvent(
    PubKeyExchangeType ExchangeType,
    byte[] Payload);

public record DecryptPayloadWithHeaderActorEvent(
    PubKeyExchangeType ExchangeType,
    EnvelopeMetadata Metadata,
    byte[] EncryptedPayload);

public record ForwardToConnectActorEvent(uint ConnectId, object Payload);

public record RestoreAppDeviceSecrecyChannelState;

public record DeriveSharedSecretActorEvent(uint ConnectId, PubKeyExchange PubKeyExchange);

public record DeriveSharedSecretReply(PubKeyExchange PubKeyExchange);

public record InitializeProtocolWithMasterKeyActorEvent(
    uint ConnectId,
    EcliptixSystemIdentityKeys IdentityKeys,
    PubKeyExchange ClientPubKeyExchange,
    Guid AccountId,
    byte[] RootKey);

public record InitializeProtocolWithMasterKeyReply(PubKeyExchange ServerPubKeyExchange);

public record CleanupProtocolForTypeActorEvent(PubKeyExchangeType ExchangeType);

public sealed record KeepAlive
{
    public static readonly KeepAlive Instance = new();

    private KeepAlive()
    {
    }
}

public sealed record RetryRecoveryMessage;
using Ecliptix.Protobuf.Common;
using Ecliptix.Protobuf.Protocol;

namespace Ecliptix.Core.Domain.Events;

public record BeginAppDeviceEphemeralConnectActorEvent(PubKeyExchange PubKeyExchange, uint UniqueConnectId);

public record DecryptCipherPayloadActorEvent(
    PubKeyExchangeType PubKeyExchangeType,
    CipherPayload CipherPayload);

public record EncryptPayloadActorEvent(
    PubKeyExchangeType PubKeyExchangeType,
    byte[] Payload);

public record ForwardToConnectActorEvent(uint ConnectId, object Payload);

public record RestoreAppDeviceSecrecyChannelState;

public record DeriveSharedSecretActorEvent(uint ConnectId, PubKeyExchange PubKeyExchange);

public record DeriveSharedSecretReply(PubKeyExchange PubKeyExchange);

public record CleanupProtocolForTypeActorEvent(PubKeyExchangeType ExchangeType);

public sealed record KeepAlive
{
    public static readonly KeepAlive Instance = new();

    private KeepAlive()
    {
    }
}

public sealed record RetryRecoveryMessage;
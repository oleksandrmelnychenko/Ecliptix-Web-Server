using Ecliptix.Protobuf.Common;
using Ecliptix.Protobuf.Protocol;
using Ecliptix.Protobuf.SecureProtocol;

namespace Ecliptix.SharedKernel.Actors;

public record InitiateEphemeralConnectCommand(PubKeyExchange PubKeyExchange, uint UniqueConnectId);

public record DecryptSecureEnvelopeCommand(
    PubKeyExchangeType PubKeyExchangeType,
    SecureEnvelope SecureEnvelope);

public record EncryptPayloadCommand(
    PubKeyExchangeType PubKeyExchangeType,
    byte[] Payload);

public record EncryptPayloadComponentsCommand(
    PubKeyExchangeType ExchangeType,
    byte[] Payload);

public record DecryptPayloadWithHeaderCommand(
    PubKeyExchangeType ExchangeType,
    byte[] Metadata,
    byte[] EncryptedPayload);

public record RouteToConnectionCommand(uint ConnectId, object Payload);

public record RestoreProtocolSessionCommand;

public record DeriveSharedSecretCommand(uint ConnectId, PubKeyExchange PubKeyExchange);

public record DeriveSharedSecretResponse(PubKeyExchange PubKeyExchange);

public record InitializeProtocolWithMasterKeyCommand(
    uint ConnectId,
    PubKeyExchange ClientPubKeyExchange,
    Guid MembershipId,
    Guid AccountId,
    byte[] RootKey);

public record InitializeProtocolWithMasterKeyResponse(PubKeyExchange ServerPubKeyExchange);

public record GetProtocolStateQuery(uint ConnectId);

public record GetProtocolStateResponse(EcliptixSessionState? SessionState);

public record GetConnectionKyberPublicKeyQuery;

public record CleanupProtocolForTypeCommand(PubKeyExchangeType ExchangeType);

public sealed record KeepAlive
{
    public static readonly KeepAlive Instance = new();
    private KeepAlive() { }
}

public sealed record RetryRecoveryMessage;

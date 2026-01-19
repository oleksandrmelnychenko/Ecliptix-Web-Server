using Ecliptix.Protobuf.Protocol;
using Ecliptix.Protobuf.SecureProtocol;

namespace Ecliptix.SharedKernel.Actors;

public record InitiateEphemeralConnectCommand(
    PubKeyExchangeType ExchangeType,
    byte[] HandshakeInit,
    uint UniqueConnectId);

public record DecryptSecureEnvelopeCommand(
    PubKeyExchangeType PubKeyExchangeType,
    SecureEnvelope SecureEnvelope);

public record EncryptPayloadCommand(
    PubKeyExchangeType PubKeyExchangeType,
    EnvelopeType EnvelopeType,
    uint EnvelopeId,
    byte[] Payload,
    string? CorrelationId = null);

public record RouteToConnectionCommand(uint ConnectId, object Payload);

public record RestoreProtocolSessionCommand;

public record DeriveSharedSecretCommand(
    uint ConnectId,
    PubKeyExchangeType ExchangeType,
    byte[] HandshakeInit);

public record DeriveSharedSecretResponse(byte[] HandshakeAck);

public record InitializeAuthenticatedSessionCommand(
    uint ConnectId,
    PubKeyExchangeType ExchangeType,
    byte[] HandshakeInit,
    Guid MembershipId,
    Guid AccountId);

public record InitializeAuthenticatedSessionResponse(byte[] HandshakeAck);

public record GetProtocolStateQuery(uint ConnectId);

public record GetProtocolStateResponse(EcliptixSessionState? SessionState);

public record GetPreKeyBundleQuery;

public record CleanupProtocolForTypeCommand(PubKeyExchangeType ExchangeType);

public sealed record KeepAlive
{
    public static readonly KeepAlive Instance = new();
    private KeepAlive() { }
}

public sealed record RetryRecoveryMessage;

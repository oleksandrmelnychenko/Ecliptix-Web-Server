using Ecliptix.Protobuf.Common;
using Ecliptix.Protobuf.Protocol;
using Ecliptix.Protobuf.ProtocolState;
using Ecliptix.Utilities;

namespace Ecliptix.Core.Domain.Protocol.Handlers;

public sealed class EncryptionHandler
{
    public Result<EncryptionResult, EcliptixProtocolFailure> EncryptPayload(
        EcliptixProtocolSystem system,
        EcliptixSessionState? currentState,
        byte[] payload,
        PubKeyExchangeType exchangeType)
    {
        Result<SecureEnvelope, EcliptixProtocolFailure> encryptionResult = system.ProduceOutboundMessage(payload);

        if (encryptionResult.IsErr)
        {
            return Result<EncryptionResult, EcliptixProtocolFailure>.Err(encryptionResult.UnwrapErr());
        }

        Result<EcliptixSessionState, EcliptixProtocolFailure> newStateResult =
            EcliptixProtocol.CreateStateFromSystem(currentState ?? new EcliptixSessionState(), system);

        if (newStateResult.IsErr)
        {
            return Result<EncryptionResult, EcliptixProtocolFailure>.Err(newStateResult.UnwrapErr());
        }

        bool shouldPersist = exchangeType != PubKeyExchangeType.ServerStreaming;

        return Result<EncryptionResult, EcliptixProtocolFailure>.Ok(new EncryptionResult(
            newStateResult.Unwrap(),
            encryptionResult.Unwrap(),
            shouldPersist
        ));
    }

    public Result<EncryptionComponentsResult, EcliptixProtocolFailure> EncryptPayloadComponents(
        EcliptixProtocolSystem system,
        EcliptixSessionState? currentState,
        byte[] payload,
        PubKeyExchangeType exchangeType)
    {
        Result<(EnvelopeMetadata Header, byte[] EncryptedPayload), EcliptixProtocolFailure> encryptionResult =
            system.ProduceOutboundEnvelopeMaterials(payload);

        if (encryptionResult.IsErr)
        {
            return Result<EncryptionComponentsResult, EcliptixProtocolFailure>.Err(encryptionResult.UnwrapErr());
        }

        Result<EcliptixSessionState, EcliptixProtocolFailure> newStateResult =
            EcliptixProtocol.CreateStateFromSystem(currentState ?? new EcliptixSessionState(), system);

        if (newStateResult.IsErr)
        {
            return Result<EncryptionComponentsResult, EcliptixProtocolFailure>.Err(newStateResult.UnwrapErr());
        }

        bool shouldPersist = exchangeType == PubKeyExchangeType.DataCenterEphemeralConnect;
        (EnvelopeMetadata Header, byte[] EncryptedPayload) components = encryptionResult.Unwrap();

        return Result<EncryptionComponentsResult, EcliptixProtocolFailure>.Ok(new EncryptionComponentsResult(
            newStateResult.Unwrap(),
            components.Header,
            components.EncryptedPayload,
            shouldPersist
        ));
    }
}

public sealed record EncryptionResult(
    EcliptixSessionState NewState,
    SecureEnvelope Envelope,
    bool ShouldPersist
);

public sealed record EncryptionComponentsResult(
    EcliptixSessionState NewState,
    EnvelopeMetadata Header,
    byte[] EncryptedPayload,
    bool ShouldPersist
);

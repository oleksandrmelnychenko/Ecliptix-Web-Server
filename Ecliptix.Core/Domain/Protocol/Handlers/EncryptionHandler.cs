using Ecliptix.Protobuf.Common;
using Ecliptix.Protobuf.Protocol;
using Ecliptix.Protobuf.ProtocolState;
using Ecliptix.Utilities;

namespace Ecliptix.Core.Domain.Protocol.Handlers;

public sealed class EncryptionHandler
{
    public static Result<EncryptionResult, EcliptixProtocolFailure> EncryptPayload(
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

        bool shouldPersist = exchangeType == PubKeyExchangeType.DataCenterEphemeralConnect;
        return Result<EncryptionResult, EcliptixProtocolFailure>.Ok(new EncryptionResult(
            newStateResult.Unwrap(),
            encryptionResult.Unwrap(),
            shouldPersist
        ));
    }

    public static Result<EncryptionMaterialsResult, EcliptixProtocolFailure> EncryptPayloadMaterials(
        EcliptixProtocolSystem system,
        EcliptixSessionState? currentState,
        byte[] payload,
        PubKeyExchangeType exchangeType)
    {
        Result<(EnvelopeMetadata Header, byte[] EncryptedPayload), EcliptixProtocolFailure> encryptionResult =
            system.ProduceOutboundEnvelopeMaterials(payload);

        if (encryptionResult.IsErr)
        {
            return Result<EncryptionMaterialsResult, EcliptixProtocolFailure>.Err(encryptionResult.UnwrapErr());
        }

        Result<EcliptixSessionState, EcliptixProtocolFailure> newStateResult =
            EcliptixProtocol.CreateStateFromSystem(currentState ?? new EcliptixSessionState(), system);

        if (newStateResult.IsErr)
        {
            return Result<EncryptionMaterialsResult, EcliptixProtocolFailure>.Err(newStateResult.UnwrapErr());
        }

        bool shouldPersist = exchangeType == PubKeyExchangeType.DataCenterEphemeralConnect;
        (EnvelopeMetadata Header, byte[] EncryptedPayload) components = encryptionResult.Unwrap();

        return Result<EncryptionMaterialsResult, EcliptixProtocolFailure>.Ok(new EncryptionMaterialsResult(
            newStateResult.Unwrap(),
            components.Header,
            components.EncryptedPayload,
            shouldPersist
        ));
    }
}

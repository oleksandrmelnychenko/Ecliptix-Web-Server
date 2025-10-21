using Ecliptix.Protobuf.Common;
using Ecliptix.Protobuf.Protocol;
using Ecliptix.Protobuf.ProtocolState;
using Ecliptix.Utilities;

namespace Ecliptix.Core.Domain.Protocol.Handlers;

public sealed class DecryptionHandler
{
    public Result<DecryptionResult, EcliptixProtocolFailure> DecryptEnvelope(
        EcliptixProtocolSystem system,
        EcliptixSessionState? currentState,
        SecureEnvelope envelope,
        PubKeyExchangeType exchangeType)
    {
        Result<byte[], EcliptixProtocolFailure> decryptionResult = system.ProcessInboundEnvelope(envelope);

        if (decryptionResult.IsErr)
        {
            EcliptixProtocolFailure error = decryptionResult.UnwrapErr();
            return Result<DecryptionResult, EcliptixProtocolFailure>.Err(error);
        }

        Result<EcliptixSessionState, EcliptixProtocolFailure> newStateResult =
            EcliptixProtocol.CreateStateFromSystem(currentState ?? new EcliptixSessionState(), system);

        if (newStateResult.IsErr)
        {
            return Result<DecryptionResult, EcliptixProtocolFailure>.Err(newStateResult.UnwrapErr());
        }

        bool shouldPersist = exchangeType == PubKeyExchangeType.DataCenterEphemeralConnect;

        return Result<DecryptionResult, EcliptixProtocolFailure>.Ok(new DecryptionResult(
            newStateResult.Unwrap(),
            decryptionResult.Unwrap(),
            shouldPersist,
            false
        ));
    }

    public Result<DecryptionResult, EcliptixProtocolFailure> DecryptWithHeader(
        EcliptixProtocolSystem system,
        EcliptixSessionState? currentState,
        EnvelopeMetadata metadata,
        byte[] encryptedPayload,
        PubKeyExchangeType exchangeType)
    {
        Result<byte[], EcliptixProtocolFailure> decryptionResult =
            system.ProcessInboundEnvelopeFromMaterials(metadata, encryptedPayload);

        if (decryptionResult.IsErr)
        {
            EcliptixProtocolFailure error = decryptionResult.UnwrapErr();
            bool requiresSessionClear = error.FailureType == EcliptixProtocolFailureType.SessionAuthenticationFailed;

            return Result<DecryptionResult, EcliptixProtocolFailure>.Ok(new DecryptionResult(
                currentState ?? new EcliptixSessionState(),
                [],
                false,
                requiresSessionClear
            ));
        }

        Result<EcliptixSessionState, EcliptixProtocolFailure> newStateResult =
            EcliptixProtocol.CreateStateFromSystem(currentState ?? new EcliptixSessionState(), system);

        if (newStateResult.IsErr)
        {
            return Result<DecryptionResult, EcliptixProtocolFailure>.Err(newStateResult.UnwrapErr());
        }

        bool shouldPersist = exchangeType == PubKeyExchangeType.DataCenterEphemeralConnect;

        return Result<DecryptionResult, EcliptixProtocolFailure>.Ok(new DecryptionResult(
            newStateResult.Unwrap(),
            decryptionResult.Unwrap(),
            shouldPersist,
            false
        ));
    }

    public static bool ShouldClearSession(EcliptixProtocolFailure error)
    {
        return error.FailureType == EcliptixProtocolFailureType.SessionAuthenticationFailed;
    }
}

public sealed record DecryptionResult(
    EcliptixSessionState NewState,
    byte[] Plaintext,
    bool ShouldPersist,
    bool RequiresSessionClear
);

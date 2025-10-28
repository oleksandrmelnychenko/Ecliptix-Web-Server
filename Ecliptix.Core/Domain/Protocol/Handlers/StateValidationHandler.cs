using Ecliptix.Core.Domain.Actors;
using Ecliptix.Protobuf.ProtocolState;
using Ecliptix.Utilities;

namespace Ecliptix.Core.Domain.Protocol.Handlers;

public sealed class StateValidationHandler
{
    public static Result<Unit, EcliptixProtocolFailure> ValidateRecoveredState(EcliptixSessionState? state)
    {
        if (state?.RatchetState == null)
        {
            return Result<Unit, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.ActorStateNotFound(ActorConstants.ErrorMessages.RatchetStateMissing));
        }

        uint sendingIdx = state.RatchetState.SendingStep.CurrentIndex;
        uint receivingIdx = state.RatchetState.ReceivingStep.CurrentIndex;

        if (sendingIdx > ActorConstants.Validation.MaxChainIndex ||
            receivingIdx > ActorConstants.Validation.MaxChainIndex)
        {
            return Result<Unit, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.Generic(
                    $"Chain indices appear corrupted: sending={sendingIdx}, receiving={receivingIdx}"));
        }

        if (state.RatchetState.RootKey.IsEmpty)
        {
            return Result<Unit, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.Generic(ActorConstants.ErrorMessages.RootKeyMissing));
        }

        if (state.RatchetState.SendingStep.ChainKey.IsEmpty ||
            state.RatchetState.ReceivingStep.ChainKey.IsEmpty)
        {
            return Result<Unit, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.Generic(ActorConstants.ErrorMessages.ChainKeysMissing));
        }

        Google.Protobuf.ByteString sendingDhKey = state.RatchetState.SendingStep.DhPublicKey;
        if (!sendingDhKey.IsEmpty && sendingDhKey.Length != ActorConstants.Validation.ExpectedDhKeySize)
        {
            return Result<Unit, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.Generic($"Invalid DH key size: {sendingDhKey.Length}"));
        }

        if (state.RatchetState.NonceCounter > uint.MaxValue - ActorConstants.Constants.NonceCounterWarningThreshold)
        {
            return Result<Unit, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.Generic(ActorConstants.ErrorMessages.NonceCounterOverflow));
        }

        return Result<Unit, EcliptixProtocolFailure>.Ok(Unit.Value);
    }
}

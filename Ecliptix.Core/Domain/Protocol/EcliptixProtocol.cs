using Ecliptix.Utilities;
using Ecliptix.Protobuf.Protocol;
using Ecliptix.Protobuf.ProtocolState;
using Serilog;
using Serilog.Events;

namespace Ecliptix.Core.Domain.Protocol;

public static class EcliptixProtocol
{
    public static Result<EcliptixProtocolSystem, EcliptixProtocolFailure> RecreateSystemFromState(
        EcliptixSessionState state)
    {
        Result<EcliptixSystemIdentityKeys, EcliptixProtocolFailure> idKeysResult =
            EcliptixSystemIdentityKeys.FromProtoState(state.IdentityKeys);
        if (idKeysResult.IsErr)
        {
            if (Log.IsEnabled(LogEventLevel.Debug))

                return Result<EcliptixProtocolSystem, EcliptixProtocolFailure>.Err(idKeysResult.UnwrapErr());
        }

        Result<EcliptixProtocolConnection, EcliptixProtocolFailure> connResult =
            EcliptixProtocolConnection.FromProtoState(state.ConnectId, state.RatchetState);
        if (connResult.IsErr)
        {
            idKeysResult.Unwrap().Dispose();
            if (Log.IsEnabled(LogEventLevel.Debug))

                return Result<EcliptixProtocolSystem, EcliptixProtocolFailure>.Err(connResult.UnwrapErr());
        }

        if (Log.IsEnabled(LogEventLevel.Debug))
        {

        }

        return EcliptixProtocolSystem.CreateFrom(idKeysResult.Unwrap(), connResult.Unwrap());
    }

    public static Result<EcliptixSessionState, EcliptixProtocolFailure> CreateStateFromSystem(
        EcliptixSessionState oldState, EcliptixProtocolSystem system)
    {
        Result<RatchetState, EcliptixProtocolFailure> ratchetStateResult = system.GetConnection().ToProtoState();
        if (ratchetStateResult.IsErr)
            return Result<EcliptixSessionState, EcliptixProtocolFailure>.Err(ratchetStateResult.UnwrapErr());

        RatchetState newRatchetState = ratchetStateResult.Unwrap();
        EcliptixSessionState newState = oldState.Clone();
        newState.RatchetState = newRatchetState;

        if (Log.IsEnabled(LogEventLevel.Debug))
        {

        }

        return Result<EcliptixSessionState, EcliptixProtocolFailure>.Ok(newState);
    }

    public static Result<EcliptixSessionState, EcliptixProtocolFailure> CreateInitialState(uint connectId,
        PubKeyExchange peerMsg, EcliptixProtocolSystem system)
    {
        EcliptixSystemIdentityKeys idKeys = system.GetIdentityKeys();
        EcliptixProtocolConnection connection = system.GetConnection();

        Result<IdentityKeysState, EcliptixProtocolFailure> identityKeysResult = idKeys.ToProtoState();
        if (identityKeysResult.IsErr)
            return Result<EcliptixSessionState, EcliptixProtocolFailure>.Err(identityKeysResult.UnwrapErr());

        IdentityKeysState identityKeysProto = identityKeysResult.Unwrap();

        Result<RatchetState, EcliptixProtocolFailure> ratchetStateResult = connection.ToProtoState();
        if (ratchetStateResult.IsErr)
            return Result<EcliptixSessionState, EcliptixProtocolFailure>.Err(ratchetStateResult.UnwrapErr());

        RatchetState ratchetStateProto = ratchetStateResult.Unwrap();

        EcliptixSessionState state = new()
        {
            ConnectId = connectId,
            IdentityKeys = identityKeysProto,
            PeerHandshakeMessage = peerMsg,
            RatchetState = ratchetStateProto
        };

        if (Log.IsEnabled(LogEventLevel.Debug))
        {

        }

        return Result<EcliptixSessionState, EcliptixProtocolFailure>.Ok(state);
    }
}
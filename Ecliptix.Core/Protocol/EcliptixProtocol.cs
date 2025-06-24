using Ecliptix.Domain.Utilities;
using Ecliptix.Protobuf.ProtocolState;
using Ecliptix.Protobuf.PubKeyExchange;
using Ecliptix.Protobuf.CipherPayload;

namespace Ecliptix.Core.Protocol;

public static class EcliptixProtocol
{
    private const int LocalKeyCount = 10;

    public static Result<(EcliptixSessionState NewState, PubKeyExchange Reply), EcliptixProtocolFailure>
        EstablishSession(uint connectId, PubKeyExchange peerHandshakeMessage)
    {
        Result<EcliptixSystemIdentityKeys, EcliptixProtocolFailure> identityKeysResult =
            EcliptixSystemIdentityKeys.Create(LocalKeyCount);
        if (identityKeysResult.IsErr)
        {
            return Result<(EcliptixSessionState, PubKeyExchange), EcliptixProtocolFailure>.Err(identityKeysResult
                .UnwrapErr());
        }

        using EcliptixSystemIdentityKeys identityKeys = identityKeysResult.Unwrap();
        using EcliptixProtocolSystem system = new(identityKeys);

        Result<PubKeyExchange, EcliptixProtocolFailure> replyResult =
            system.ProcessAndRespondToPubKeyExchange(connectId, peerHandshakeMessage);
        if (replyResult.IsErr)
        {
            return Result<(EcliptixSessionState, PubKeyExchange), EcliptixProtocolFailure>.Err(replyResult.UnwrapErr());
        }

        Result<EcliptixSessionState, EcliptixProtocolFailure> initialStateResult =
            CreateInitialState(connectId, peerHandshakeMessage, system);
        if (initialStateResult.IsErr)
        {
            return Result<(EcliptixSessionState, PubKeyExchange), EcliptixProtocolFailure>.Err(initialStateResult
                .UnwrapErr());
        }

        return Result<(EcliptixSessionState, PubKeyExchange), EcliptixProtocolFailure>.Ok(
            (initialStateResult.Unwrap(), replyResult.Unwrap())
        );
    }

    public static Result<(EcliptixSessionState NewState, CipherPayload Ciphertext), EcliptixProtocolFailure>
        Encrypt(EcliptixSessionState currentState, byte[] plaintext)
    {
        Result<EcliptixProtocolSystem, EcliptixProtocolFailure> systemResult = RecreateSystemFromState(currentState);
        if (systemResult.IsErr)
            return Result<(EcliptixSessionState, CipherPayload), EcliptixProtocolFailure>.Err(systemResult.UnwrapErr());

        using EcliptixProtocolSystem system = systemResult.Unwrap();

        Result<CipherPayload, EcliptixProtocolFailure> result = system.ProduceOutboundMessage(plaintext);
        if (result.IsErr)
        {
            return Result<(EcliptixSessionState, CipherPayload), EcliptixProtocolFailure>.Err(result.UnwrapErr());
        }

        return CreateStateFromSystem(currentState, system).Map(newState => (newState, result.Unwrap()));
    }

    public static Result<(EcliptixSessionState NewState, byte[] Plaintext), EcliptixProtocolFailure>
        Decrypt(EcliptixSessionState currentState, CipherPayload ciphertext)
    {
        Result<EcliptixProtocolSystem, EcliptixProtocolFailure> systemResult = RecreateSystemFromState(currentState);
        if (systemResult.IsErr)
            return Result<(EcliptixSessionState, byte[]), EcliptixProtocolFailure>.Err(systemResult.UnwrapErr());

        using EcliptixProtocolSystem system = systemResult.Unwrap();

        Result<byte[], EcliptixProtocolFailure> result = system.ProcessInboundMessage(ciphertext);
        if (result.IsErr)
        {
            return Result<(EcliptixSessionState, byte[]), EcliptixProtocolFailure>.Err(result.UnwrapErr());
        }

        return CreateStateFromSystem(currentState, system).Map(newState => (newState, result.Unwrap()));
    }

    public static Result<EcliptixProtocolSystem, EcliptixProtocolFailure> RecreateSystemFromState(
        EcliptixSessionState state)
    {
        Result<EcliptixSystemIdentityKeys, EcliptixProtocolFailure> idKeysResult =
            EcliptixSystemIdentityKeys.FromProtoState(state.IdentityKeys);
        if (idKeysResult.IsErr)
            return Result<EcliptixProtocolSystem, EcliptixProtocolFailure>.Err(idKeysResult.UnwrapErr());

        Result<EcliptixProtocolConnection, EcliptixProtocolFailure> connResult =
            EcliptixProtocolConnection.FromProtoState(state.ConnectId, state.RatchetState);
        if (connResult.IsErr)
        {
            idKeysResult.Unwrap().Dispose();
            return Result<EcliptixProtocolSystem, EcliptixProtocolFailure>.Err(connResult.UnwrapErr());
        }

        return EcliptixProtocolSystem.CreateFrom(idKeysResult.Unwrap(), connResult.Unwrap());
    }

    public static Result<EcliptixSessionState, EcliptixProtocolFailure> CreateStateFromSystem(
        EcliptixSessionState oldState, EcliptixProtocolSystem system)
    {
        return system.GetConnection().ToProtoState().Map(newRatchetState =>
        {
            EcliptixSessionState? newState = oldState.Clone();
            newState.RatchetState = newRatchetState;
            return newState;
        });
    }

    public static Result<EcliptixSessionState, EcliptixProtocolFailure> CreateInitialState(uint connectId,
        PubKeyExchange peerMsg, EcliptixProtocolSystem system)
    {
        EcliptixSystemIdentityKeys idKeys = system.GetIdentityKeys();
        EcliptixProtocolConnection connection = system.GetConnection();

        return idKeys.ToProtoState()
            .AndThen(identityKeysProto => connection.ToProtoState()
                .Map(ratchetStateProto => new EcliptixSessionState
                {
                    ConnectId = connectId,
                    IdentityKeys = identityKeysProto,
                    PeerHandshakeMessage = peerMsg,
                    RatchetState = ratchetStateProto
                })
            );
    }
}
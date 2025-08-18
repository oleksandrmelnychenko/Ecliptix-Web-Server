using Ecliptix.Domain.Utilities;
using Ecliptix.Protobuf.ProtocolState;
using Ecliptix.Protobuf.PubKeyExchange;
using Serilog;
using Serilog.Events;

namespace Ecliptix.Core.Protocol;

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
                Log.Debug("[EcliptixProtocol] RecreateSystemFromState: Error restoring identity keys: {Message}", idKeysResult.UnwrapErr().Message);
            return Result<EcliptixProtocolSystem, EcliptixProtocolFailure>.Err(idKeysResult.UnwrapErr());
        }

        Result<EcliptixProtocolConnection, EcliptixProtocolFailure> connResult =
            EcliptixProtocolConnection.FromProtoState(state.ConnectId, state.RatchetState);
        if (connResult.IsErr)
        {
            idKeysResult.Unwrap().Dispose();
            if (Log.IsEnabled(LogEventLevel.Debug))
                Log.Debug("[EcliptixProtocol] RecreateSystemFromState: Error restoring connection: {Message}", connResult.UnwrapErr().Message);
            return Result<EcliptixProtocolSystem, EcliptixProtocolFailure>.Err(connResult.UnwrapErr());
        }

        if (Log.IsEnabled(LogEventLevel.Debug))
        {
            Log.Debug("[EcliptixProtocol] RecreateSystemFromState (ConnectId: {ConnectId}):", state.ConnectId);
            Log.Debug("  Identity Keys: IdentityX25519PublicKey={IdentityX25519PublicKey}", Convert.ToHexString(state.IdentityKeys.IdentityX25519PublicKey.ToByteArray()));
            Log.Debug("  Connection Root Key: {RootKey}", Convert.ToHexString(state.RatchetState.RootKey.ToByteArray()));
            Log.Debug("  Peer DH Public Key: {PeerDhPublicKey}", state.RatchetState.PeerDhPublicKey.IsEmpty ? "<null>" : Convert.ToHexString(state.RatchetState.PeerDhPublicKey.ToByteArray()));
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
            if (Log.IsEnabled(LogEventLevel.Debug))
            {
                Log.Debug("[EcliptixProtocol] CreateStateFromSystem:");
                Log.Debug("  Updated Connection Root Key: {RootKey}", Convert.ToHexString(newRatchetState.RootKey.ToByteArray()));
                Log.Debug("  Updated Peer DH Public Key: {PeerDhPublicKey}", newRatchetState.PeerDhPublicKey.IsEmpty ? "<null>" : Convert.ToHexString(newRatchetState.PeerDhPublicKey.ToByteArray()));
            }
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
                .Map(ratchetStateProto =>
                {
                    EcliptixSessionState state = new()
                    {
                        ConnectId = connectId,
                        IdentityKeys = identityKeysProto,
                        PeerHandshakeMessage = peerMsg,
                        RatchetState = ratchetStateProto
                    };
                    if (Log.IsEnabled(LogEventLevel.Debug))
                    {
                        Log.Debug("[EcliptixProtocol] CreateInitialState (ConnectId: {ConnectId}):", connectId);
                        Log.Debug("  Identity Keys: IdentityX25519PublicKey={IdentityX25519PublicKey}", Convert.ToHexString(identityKeysProto.IdentityX25519PublicKey.ToByteArray()));
                        Log.Debug("  Connection Root Key: {RootKey}", Convert.ToHexString(ratchetStateProto.RootKey.ToByteArray()));
                        Log.Debug("  Peer DH Public Key: {PeerDhPublicKey}", ratchetStateProto.PeerDhPublicKey.IsEmpty ? "<null>" : Convert.ToHexString(ratchetStateProto.PeerDhPublicKey.ToByteArray()));
                    }
                    return state;
                })
            );
    }
}
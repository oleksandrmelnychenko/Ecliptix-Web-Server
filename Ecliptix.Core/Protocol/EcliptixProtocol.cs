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
            Log.Debug("  Identity Keys: IdentityX25519PublicKey={IdentityX25519PublicKey}", Convert.ToHexString(state.IdentityKeys.IdentityX25519PublicKey.Span));
            Log.Debug("  Connection Root Key: {RootKey}", Convert.ToHexString(state.RatchetState.RootKey.Span));
            Log.Debug("  Peer DH Public Key: {PeerDhPublicKey}", state.RatchetState.PeerDhPublicKey.IsEmpty ? "<null>" : Convert.ToHexString(state.RatchetState.PeerDhPublicKey.Span));
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
            Log.Debug("[EcliptixProtocol] CreateStateFromSystem:");
            Log.Debug("  Updated Connection Root Key: {RootKey}", Convert.ToHexString(newRatchetState.RootKey.Span));
            Log.Debug("  Updated Peer DH Public Key: {PeerDhPublicKey}", newRatchetState.PeerDhPublicKey.IsEmpty ? "<null>" : Convert.ToHexString(newRatchetState.PeerDhPublicKey.Span));
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
            Log.Debug("[EcliptixProtocol] CreateInitialState (ConnectId: {ConnectId}):", connectId);
            Log.Debug("  Identity Keys: IdentityX25519PublicKey={IdentityX25519PublicKey}", Convert.ToHexString(identityKeysProto.IdentityX25519PublicKey.Span));
            Log.Debug("  Connection Root Key: {RootKey}", Convert.ToHexString(ratchetStateProto.RootKey.Span));
            Log.Debug("  Peer DH Public Key: {PeerDhPublicKey}", ratchetStateProto.PeerDhPublicKey.IsEmpty ? "<null>" : Convert.ToHexString(ratchetStateProto.PeerDhPublicKey.Span));
        }
        
        return Result<EcliptixSessionState, EcliptixProtocolFailure>.Ok(state);
    }
}
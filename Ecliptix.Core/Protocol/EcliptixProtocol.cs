using Ecliptix.Domain.Utilities;
using Ecliptix.Protobuf.ProtocolState;
using Ecliptix.Protobuf.PubKeyExchange;
using Ecliptix.Protobuf.CipherPayload;
using Serilog;
using Serilog.Events;

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
            if (Log.IsEnabled(LogEventLevel.Debug))
                Log.Debug("[EcliptixProtocol] EstablishSession: Error creating identity keys: {Message}", identityKeysResult.UnwrapErr().Message);
            return Result<(EcliptixSessionState, PubKeyExchange), EcliptixProtocolFailure>.Err(identityKeysResult
                .UnwrapErr());
        }

        using EcliptixSystemIdentityKeys identityKeys = identityKeysResult.Unwrap();
        using EcliptixProtocolSystem system = new(identityKeys);

        Result<PubKeyExchange, EcliptixProtocolFailure> replyResult =
            system.ProcessAndRespondToPubKeyExchange(connectId, peerHandshakeMessage);
        if (replyResult.IsErr)
        {
            if (Log.IsEnabled(LogEventLevel.Debug))
                Log.Debug("[EcliptixProtocol] EstablishSession: Error processing pub key exchange: {Message}", replyResult.UnwrapErr().Message);
            return Result<(EcliptixSessionState, PubKeyExchange), EcliptixProtocolFailure>.Err(replyResult.UnwrapErr());
        }

        Result<EcliptixSessionState, EcliptixProtocolFailure> initialStateResult =
            CreateInitialState(connectId, peerHandshakeMessage, system);
        if (initialStateResult.IsErr)
        {
            if (Log.IsEnabled(LogEventLevel.Debug))
                Log.Debug("[EcliptixProtocol] EstablishSession: Error creating initial state: {Message}", initialStateResult.UnwrapErr().Message);
            return Result<(EcliptixSessionState, PubKeyExchange), EcliptixProtocolFailure>.Err(initialStateResult
                .UnwrapErr());
        }

        // Log session state
        EcliptixSessionState state = initialStateResult.Unwrap();
        if (Log.IsEnabled(LogEventLevel.Debug))
        {
            Log.Debug("[EcliptixProtocol] EstablishSession (ConnectId: {ConnectId}):", connectId);
            Log.Debug("  Identity Keys: IdentityX25519PublicKey={IdentityX25519PublicKey}", Convert.ToHexString(state.IdentityKeys.IdentityX25519PublicKey.ToByteArray()));
            Log.Debug("  Connection Root Key: {RootKey}", Convert.ToHexString(state.RatchetState.RootKey.ToByteArray()));
            Log.Debug("  Peer DH Public Key: {PeerDhPublicKey}", state.RatchetState.PeerDhPublicKey.IsEmpty ? "<null>" : Convert.ToHexString(state.RatchetState.PeerDhPublicKey.ToByteArray()));
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
        {
            if (Log.IsEnabled(LogEventLevel.Debug))
                Log.Debug("[EcliptixProtocol] Encrypt: Error recreating system: {Message}", systemResult.UnwrapErr().Message);
            return Result<(EcliptixSessionState, CipherPayload), EcliptixProtocolFailure>.Err(systemResult.UnwrapErr());
        }

        using EcliptixProtocolSystem system = systemResult.Unwrap();

        Result<CipherPayload, EcliptixProtocolFailure> result = system.ProduceOutboundMessage(plaintext);
        if (result.IsErr)
        {
            if (Log.IsEnabled(LogEventLevel.Debug))
                Log.Debug("[EcliptixProtocol] Encrypt: Error producing outbound message: {Message}", result.UnwrapErr().Message);
            return Result<(EcliptixSessionState, CipherPayload), EcliptixProtocolFailure>.Err(result.UnwrapErr());
        }

        CipherPayload ciphertext = result.Unwrap();
        // Log ciphertext details
        if (Log.IsEnabled(LogEventLevel.Debug))
        {
            Log.Debug("[EcliptixProtocol] Encrypt:");
            Log.Debug("  Message Key Index: {RatchetIndex}", ciphertext.RatchetIndex);
            Log.Debug("  Nonce: {Nonce}", Convert.ToHexString(ciphertext.Nonce.ToByteArray()));
            Log.Debug("  DH Public Key: {DhPublicKey}", ciphertext.DhPublicKey.IsEmpty ? "<none>" : Convert.ToHexString(ciphertext.DhPublicKey.ToByteArray()));
        }

        return CreateStateFromSystem(currentState, system).Map(newState => (newState, result.Unwrap()));
    }

    public static Result<(EcliptixSessionState NewState, byte[] Plaintext), EcliptixProtocolFailure>
        Decrypt(EcliptixSessionState currentState, CipherPayload ciphertext)
    {
        Result<EcliptixProtocolSystem, EcliptixProtocolFailure> systemResult = RecreateSystemFromState(currentState);
        if (systemResult.IsErr)
        {
            if (Log.IsEnabled(LogEventLevel.Debug))
                Log.Debug("[EcliptixProtocol] Decrypt: Error recreating system: {Message}", systemResult.UnwrapErr().Message);
            return Result<(EcliptixSessionState, byte[]), EcliptixProtocolFailure>.Err(systemResult.UnwrapErr());
        }

        using EcliptixProtocolSystem system = systemResult.Unwrap();

        Result<byte[], EcliptixProtocolFailure> result = system.ProcessInboundMessage(ciphertext);
        if (result.IsErr)
        {
            if (Log.IsEnabled(LogEventLevel.Debug))
                Log.Debug("[EcliptixProtocol] Decrypt: Error processing inbound message: {Message}", result.UnwrapErr().Message);
            return Result<(EcliptixSessionState, byte[]), EcliptixProtocolFailure>.Err(result.UnwrapErr());
        }

        // Log decrypted message details
        if (Log.IsEnabled(LogEventLevel.Debug))
        {
            Log.Debug("[EcliptixProtocol] Decrypt:");
            Log.Debug("  Received Message Key Index: {RatchetIndex}", ciphertext.RatchetIndex);
            Log.Debug("  Received DH Public Key: {DhPublicKey}", ciphertext.DhPublicKey.IsEmpty ? "<none>" : Convert.ToHexString(ciphertext.DhPublicKey.ToByteArray()));
        }

        return CreateStateFromSystem(currentState, system).Map(newState => (newState, result.Unwrap()));
    }

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

        // Log restored keys
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
            // Log updated connection state
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
                    // Log initial state
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
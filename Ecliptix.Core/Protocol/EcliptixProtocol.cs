using System;
using Ecliptix.Core.Protocol.Failures;
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
            Console.WriteLine($"[EcliptixProtocol] EstablishSession: Error creating identity keys: {identityKeysResult.UnwrapErr().Message}");
            return Result<(EcliptixSessionState, PubKeyExchange), EcliptixProtocolFailure>.Err(identityKeysResult
                .UnwrapErr());
        }

        using EcliptixSystemIdentityKeys identityKeys = identityKeysResult.Unwrap();
        using EcliptixProtocolSystem system = new(identityKeys);

        Result<PubKeyExchange, EcliptixProtocolFailure> replyResult =
            system.ProcessAndRespondToPubKeyExchange(connectId, peerHandshakeMessage);
        if (replyResult.IsErr)
        {
            Console.WriteLine($"[EcliptixProtocol] EstablishSession: Error processing pub key exchange: {replyResult.UnwrapErr().Message}");
            return Result<(EcliptixSessionState, PubKeyExchange), EcliptixProtocolFailure>.Err(replyResult.UnwrapErr());
        }

        Result<EcliptixSessionState, EcliptixProtocolFailure> initialStateResult =
            CreateInitialState(connectId, peerHandshakeMessage, system);
        if (initialStateResult.IsErr)
        {
            Console.WriteLine($"[EcliptixProtocol] EstablishSession: Error creating initial state: {initialStateResult.UnwrapErr().Message}");
            return Result<(EcliptixSessionState, PubKeyExchange), EcliptixProtocolFailure>.Err(initialStateResult
                .UnwrapErr());
        }

        // Log session state
        EcliptixSessionState state = initialStateResult.Unwrap();
        Console.WriteLine($"[EcliptixProtocol] EstablishSession (ConnectId: {connectId}):");
        Console.WriteLine($"  Identity Keys: IdentityX25519PublicKey={Convert.ToHexString(state.IdentityKeys.IdentityX25519PublicKey.ToByteArray())}");
        Console.WriteLine($"  Connection Root Key: {Convert.ToHexString(state.RatchetState.RootKey.ToByteArray())}");
        Console.WriteLine($"  Peer DH Public Key: {(state.RatchetState.PeerDhPublicKey.IsEmpty ? "<null>" : Convert.ToHexString(state.RatchetState.PeerDhPublicKey.ToByteArray()))}");

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
            Console.WriteLine($"[EcliptixProtocol] Encrypt: Error recreating system: {systemResult.UnwrapErr().Message}");
            return Result<(EcliptixSessionState, CipherPayload), EcliptixProtocolFailure>.Err(systemResult.UnwrapErr());
        }

        using EcliptixProtocolSystem system = systemResult.Unwrap();

        Result<CipherPayload, EcliptixProtocolFailure> result = system.ProduceOutboundMessage(plaintext);
        if (result.IsErr)
        {
            Console.WriteLine($"[EcliptixProtocol] Encrypt: Error producing outbound message: {result.UnwrapErr().Message}");
            return Result<(EcliptixSessionState, CipherPayload), EcliptixProtocolFailure>.Err(result.UnwrapErr());
        }

        CipherPayload ciphertext = result.Unwrap();
        // Log ciphertext details
        Console.WriteLine($"[EcliptixProtocol] Encrypt:");
        Console.WriteLine($"  Message Key Index: {ciphertext.RatchetIndex}");
        Console.WriteLine($"  Nonce: {Convert.ToHexString(ciphertext.Nonce.ToByteArray())}");
        Console.WriteLine($"  DH Public Key: {(ciphertext.DhPublicKey.IsEmpty ? "<none>" : Convert.ToHexString(ciphertext.DhPublicKey.ToByteArray()))}");

        return CreateStateFromSystem(currentState, system).Map(newState => (newState, result.Unwrap()));
    }

    public static Result<(EcliptixSessionState NewState, byte[] Plaintext), EcliptixProtocolFailure>
        Decrypt(EcliptixSessionState currentState, CipherPayload ciphertext)
    {
        Result<EcliptixProtocolSystem, EcliptixProtocolFailure> systemResult = RecreateSystemFromState(currentState);
        if (systemResult.IsErr)
        {
            Console.WriteLine($"[EcliptixProtocol] Decrypt: Error recreating system: {systemResult.UnwrapErr().Message}");
            return Result<(EcliptixSessionState, byte[]), EcliptixProtocolFailure>.Err(systemResult.UnwrapErr());
        }

        using EcliptixProtocolSystem system = systemResult.Unwrap();

        Result<byte[], EcliptixProtocolFailure> result = system.ProcessInboundMessage(ciphertext);
        if (result.IsErr)
        {
            Console.WriteLine($"[EcliptixProtocol] Decrypt: Error processing inbound message: {result.UnwrapErr().Message}");
            return Result<(EcliptixSessionState, byte[]), EcliptixProtocolFailure>.Err(result.UnwrapErr());
        }

        // Log decrypted message details
        Console.WriteLine($"[EcliptixProtocol] Decrypt:");
        Console.WriteLine($"  Received Message Key Index: {ciphertext.RatchetIndex}");
        Console.WriteLine($"  Received DH Public Key: {(ciphertext.DhPublicKey.IsEmpty ? "<none>" : Convert.ToHexString(ciphertext.DhPublicKey.ToByteArray()))}");

        return CreateStateFromSystem(currentState, system).Map(newState => (newState, result.Unwrap()));
    }

    public static Result<EcliptixProtocolSystem, EcliptixProtocolFailure> RecreateSystemFromState(
        EcliptixSessionState state)
    {
        Result<EcliptixSystemIdentityKeys, EcliptixProtocolFailure> idKeysResult =
            EcliptixSystemIdentityKeys.FromProtoState(state.IdentityKeys);
        if (idKeysResult.IsErr)
        {
            Console.WriteLine($"[EcliptixProtocol] RecreateSystemFromState: Error restoring identity keys: {idKeysResult.UnwrapErr().Message}");
            return Result<EcliptixProtocolSystem, EcliptixProtocolFailure>.Err(idKeysResult.UnwrapErr());
        }

        Result<EcliptixProtocolConnection, EcliptixProtocolFailure> connResult =
            EcliptixProtocolConnection.FromProtoState(state.ConnectId, state.RatchetState);
        if (connResult.IsErr)
        {
            idKeysResult.Unwrap().Dispose();
            Console.WriteLine($"[EcliptixProtocol] RecreateSystemFromState: Error restoring connection: {connResult.UnwrapErr().Message}");
            return Result<EcliptixProtocolSystem, EcliptixProtocolFailure>.Err(connResult.UnwrapErr());
        }

        // Log restored keys
        Console.WriteLine($"[EcliptixProtocol] RecreateSystemFromState (ConnectId: {state.ConnectId}):");
        Console.WriteLine($"  Identity Keys: IdentityX25519PublicKey={Convert.ToHexString(state.IdentityKeys.IdentityX25519PublicKey.ToByteArray())}");
        Console.WriteLine($"  Connection Root Key: {Convert.ToHexString(state.RatchetState.RootKey.ToByteArray())}");
        Console.WriteLine($"  Peer DH Public Key: {(state.RatchetState.PeerDhPublicKey.IsEmpty ? "<null>" : Convert.ToHexString(state.RatchetState.PeerDhPublicKey.ToByteArray()))}");

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
            Console.WriteLine($"[EcliptixProtocol] CreateStateFromSystem:");
            Console.WriteLine($"  Updated Connection Root Key: {Convert.ToHexString(newRatchetState.RootKey.ToByteArray())}");
            Console.WriteLine($"  Updated Peer DH Public Key: {(newRatchetState.PeerDhPublicKey.IsEmpty ? "<null>" : Convert.ToHexString(newRatchetState.PeerDhPublicKey.ToByteArray()))}");
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
                    Console.WriteLine($"[EcliptixProtocol] CreateInitialState (ConnectId: {connectId}):");
                    Console.WriteLine($"  Identity Keys: IdentityX25519PublicKey={Convert.ToHexString(identityKeysProto.IdentityX25519PublicKey.ToByteArray())}");
                    Console.WriteLine($"  Connection Root Key: {Convert.ToHexString(ratchetStateProto.RootKey.ToByteArray())}");
                    Console.WriteLine($"  Peer DH Public Key: {(ratchetStateProto.PeerDhPublicKey.IsEmpty ? "<null>" : Convert.ToHexString(ratchetStateProto.PeerDhPublicKey.ToByteArray()))}");
                    return state;
                })
            );
    }
}
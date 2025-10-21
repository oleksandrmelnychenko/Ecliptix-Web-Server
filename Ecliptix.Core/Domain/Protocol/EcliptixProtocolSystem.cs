using System.Buffers;
using System.Security.Cryptography;
using Ecliptix.Core.Domain.Protocol.Utilities;
using Ecliptix.Utilities;
using Ecliptix.Protobuf.Common;
using Ecliptix.Protobuf.Protocol;
using Ecliptix.Utilities.Failures.Sodium;
using ProtocolPublicKeyBundle = Ecliptix.Protobuf.Protocol.PublicKeyBundle;
using CorePublicKeyBundle = Ecliptix.Core.Domain.Protocol.PublicKeyBundle;
using Google.Protobuf;
using Google.Protobuf.WellKnownTypes;

namespace Ecliptix.Core.Domain.Protocol;

public class EcliptixProtocolSystem(EcliptixSystemIdentityKeys ecliptixSystemIdentityKeys) : IDisposable
{
    private readonly Lock _lock = new();

    private EcliptixProtocolConnection? _connectSession;

    public void Dispose()
    {
        EcliptixProtocolConnection? connectionToDispose;

        lock (_lock)
        {
            connectionToDispose = _connectSession;
            _connectSession = null;
        }

        connectionToDispose?.Dispose();
        ecliptixSystemIdentityKeys.Dispose();
    }

    public EcliptixSystemIdentityKeys GetIdentityKeys()
    {
        return ecliptixSystemIdentityKeys;
    }

    public EcliptixProtocolConnection GetConnection()
    {
        lock (_lock)
        {
            return _connectSession!;
        }
    }

    private Option<EcliptixProtocolConnection> GetConnectionSafe()
    {
        lock (_lock)
        {
            return _connectSession is not null
                ? Option<EcliptixProtocolConnection>.Some(_connectSession)
                : Option<EcliptixProtocolConnection>.None;
        }
    }

    public static Result<EcliptixProtocolSystem, EcliptixProtocolFailure> CreateFrom(EcliptixSystemIdentityKeys keys,
        EcliptixProtocolConnection connection)
    {
        EcliptixProtocolSystem system = new(keys) { _connectSession = connection };
        return Result<EcliptixProtocolSystem, EcliptixProtocolFailure>.Ok(system);
    }

    public Result<PubKeyExchange, EcliptixProtocolFailure> BeginDataCenterPubKeyExchange(
        uint connectId, PubKeyExchangeType exchangeType)
    {
        ecliptixSystemIdentityKeys.GenerateEphemeralKeyPair();

        Result<CorePublicKeyBundle, EcliptixProtocolFailure> bundleResult =
            ecliptixSystemIdentityKeys.CreatePublicBundle();
        if (bundleResult.IsErr)
            return Result<PubKeyExchange, EcliptixProtocolFailure>.Err(bundleResult.UnwrapErr());

        CorePublicKeyBundle bundle = bundleResult.Unwrap();

        RatchetConfig configToUse = GetConfigForExchangeType(exchangeType);

        Result<EcliptixProtocolConnection, EcliptixProtocolFailure> sessionResult =
            EcliptixProtocolConnection.Create(connectId, true, configToUse);
        if (sessionResult.IsErr)
            return Result<PubKeyExchange, EcliptixProtocolFailure>.Err(sessionResult.UnwrapErr());

        EcliptixProtocolConnection session = sessionResult.Unwrap();

        lock (_lock)
        {
            _connectSession = session;
        }

        Result<byte[]?, EcliptixProtocolFailure> dhKeyResult = _connectSession.GetCurrentSenderDhPublicKey();
        if (dhKeyResult.IsErr)
            return Result<PubKeyExchange, EcliptixProtocolFailure>.Err(dhKeyResult.UnwrapErr());

        byte[]? dhPublicKey = dhKeyResult.Unwrap();
        if (dhPublicKey == null)
            return Result<PubKeyExchange, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.Generic("DH public key is null"));

        return Result<PubKeyExchange, EcliptixProtocolFailure>.Ok(new PubKeyExchange
        {
            State = PubKeyExchangeState.Init,
            OfType = exchangeType,
            Payload = bundle.ToProtobufExchange().ToByteString(),
            InitialDhPublicKey = ByteString.CopyFrom(dhPublicKey.AsSpan())
        });
    }

    public Result<PubKeyExchange, EcliptixProtocolFailure> ProcessAndRespondToPubKeyExchange(
        uint connectId, PubKeyExchange peerInitialMessageProto)
    {
        if (_connectSession != null)
        {
            Result<Unit, EcliptixProtocolFailure> stateVerificationResult = VerifyRecoveredSessionState();
            if (stateVerificationResult.IsErr)
            {
                return Result<PubKeyExchange, EcliptixProtocolFailure>.Err(
                    EcliptixProtocolFailure.ActorStateNotFound(
                        "Session state corrupted - full re-handshake required"));
            }
            else
            {
                Result<Unit, EcliptixProtocolFailure> clientIdentityCheckResult =
                    CheckClientIdentityForFreshHandshake(peerInitialMessageProto);
                if (clientIdentityCheckResult.IsErr)
                {
                    _connectSession?.Dispose();
                    _connectSession = null;
                }
                else
                {
                    Result<CorePublicKeyBundle, EcliptixProtocolFailure> bundleResult =
                        ecliptixSystemIdentityKeys.CreatePublicBundle();
                    if (bundleResult.IsErr)
                        return Result<PubKeyExchange, EcliptixProtocolFailure>.Err(bundleResult.UnwrapErr());

                    CorePublicKeyBundle bundle = bundleResult.Unwrap();

                    Result<byte[]?, EcliptixProtocolFailure>
                        dhKeyResult = _connectSession.GetCurrentSenderDhPublicKey();
                    if (dhKeyResult.IsErr)
                        return Result<PubKeyExchange, EcliptixProtocolFailure>.Err(dhKeyResult.UnwrapErr());

                    byte[] dhPublicKey = dhKeyResult.Unwrap() ??
                                         throw new InvalidOperationException("DH public key is null");

                    return Result<PubKeyExchange, EcliptixProtocolFailure>.Ok(new PubKeyExchange
                    {
                        State = PubKeyExchangeState.Pending,
                        OfType = peerInitialMessageProto.OfType,
                        Payload = bundle.ToProtobufExchange().ToByteString(),
                        InitialDhPublicKey = ByteString.CopyFrom(dhPublicKey.AsSpan())
                    });
                }
            }
        }

        SodiumSecureMemoryHandle? rootKeyHandle = null;
        try
        {
            if (peerInitialMessageProto.State != PubKeyExchangeState.Init)
            {
                return Result<PubKeyExchange, EcliptixProtocolFailure>.Err(
                    EcliptixProtocolFailure.InvalidInput(
                        $"Expected peer message state to be Init, but was {peerInitialMessageProto.State}."));
            }

            Result<ProtocolPublicKeyBundle, EcliptixProtocolFailure> bundleParseResult;
            try
            {
                ProtocolPublicKeyBundle parsedBundle =
                    ProtocolPublicKeyBundle.Parser.ParseFrom(peerInitialMessageProto.Payload);
                bundleParseResult =
                    Result<ProtocolPublicKeyBundle, EcliptixProtocolFailure>.Ok(parsedBundle);
            }
            catch (Exception ex)
            {
                bundleParseResult = Result<ProtocolPublicKeyBundle, EcliptixProtocolFailure>.Err(
                    EcliptixProtocolFailure.Decode("Failed to parse peer public key bundle from protobuf.", ex));
            }

            if (bundleParseResult.IsErr)
                return Result<PubKeyExchange, EcliptixProtocolFailure>.Err(bundleParseResult.UnwrapErr());

            ProtocolPublicKeyBundle bundle = bundleParseResult.Unwrap();

            if (bundle.IdentityX25519PublicKey.Length != Constants.X25519PublicKeySize ||
                bundle.SignedPreKeyPublicKey.Length != Constants.X25519PublicKeySize ||
                bundle.EphemeralX25519PublicKey.Length != Constants.X25519PublicKeySize)
            {
                return Result<PubKeyExchange, EcliptixProtocolFailure>.Err(
                    EcliptixProtocolFailure.InvalidInput("Invalid key lengths in peer bundle."));
            }

            Result<CorePublicKeyBundle, EcliptixProtocolFailure> peerBundleResult =
                CorePublicKeyBundle.FromProtobufExchange(bundle);
            if (peerBundleResult.IsErr)
                return Result<PubKeyExchange, EcliptixProtocolFailure>.Err(peerBundleResult.UnwrapErr());

            CorePublicKeyBundle peerBundle = peerBundleResult.Unwrap();

            Result<bool, EcliptixProtocolFailure> signatureCheckResult =
                EcliptixSystemIdentityKeys.VerifyRemoteSpkSignature(
                    peerBundle.IdentityEd25519, peerBundle.SignedPreKeyPublic, peerBundle.SignedPreKeySignature);
            if (signatureCheckResult.IsErr)
                return Result<PubKeyExchange, EcliptixProtocolFailure>.Err(signatureCheckResult.UnwrapErr());

            if (!signatureCheckResult.Unwrap())
                return Result<PubKeyExchange, EcliptixProtocolFailure>.Err(
                    EcliptixProtocolFailure.InvalidInput("SPK signature verification failed"));

            ecliptixSystemIdentityKeys.GenerateEphemeralKeyPair();

            Result<CorePublicKeyBundle, EcliptixProtocolFailure> localBundleResult =
                ecliptixSystemIdentityKeys.CreatePublicBundle();
            if (localBundleResult.IsErr)
                return Result<PubKeyExchange, EcliptixProtocolFailure>.Err(localBundleResult.UnwrapErr());

            CorePublicKeyBundle localBundle = localBundleResult.Unwrap();

            RatchetConfig configToUse = GetConfigForExchangeType(peerInitialMessageProto.OfType);

            Result<EcliptixProtocolConnection, EcliptixProtocolFailure> sessionResult =
                EcliptixProtocolConnection.Create(connectId, false, configToUse);
            if (sessionResult.IsErr)
                return Result<PubKeyExchange, EcliptixProtocolFailure>.Err(sessionResult.UnwrapErr());

            EcliptixProtocolConnection session = sessionResult.Unwrap();

            lock (_lock)
            {
                _connectSession = session;
            }

            Result<SodiumSecureMemoryHandle, EcliptixProtocolFailure> sharedSecretResult =
                ecliptixSystemIdentityKeys.CalculateSharedSecretAsRecipient(
                    peerBundle.IdentityX25519, peerBundle.EphemeralX25519,
                    Constants.X3dhInfo);
            if (sharedSecretResult.IsErr)
                return Result<PubKeyExchange, EcliptixProtocolFailure>.Err(sharedSecretResult.UnwrapErr());

            rootKeyHandle = sharedSecretResult.Unwrap();

            byte[] rootKeyBytes = new byte[Constants.X25519KeySize];
            Result<Unit, SodiumFailure> readResult = rootKeyHandle.Read(rootKeyBytes);
            if (readResult.IsErr)
            {
                SodiumInterop.SecureWipe(rootKeyBytes);
                return Result<PubKeyExchange, EcliptixProtocolFailure>.Err(readResult.UnwrapErr().ToEcliptixProtocolFailure());
            }

            ReadOnlySpan<byte> dhKeySpan = peerInitialMessageProto.InitialDhPublicKey.Span;
            byte[] dhKeyBytes = new byte[dhKeySpan.Length];
            dhKeySpan.CopyTo(dhKeyBytes);

            Result<Unit, EcliptixProtocolFailure> dhKeyValidation = DhValidator.ValidateX25519PublicKey(dhKeyBytes);
            if (dhKeyValidation.IsErr)
            {
                SodiumInterop.SecureWipe(rootKeyBytes);
                SodiumInterop.SecureWipe(dhKeyBytes);
                return Result<PubKeyExchange, EcliptixProtocolFailure>.Err(dhKeyValidation.UnwrapErr());
            }

            Result<Unit, EcliptixProtocolFailure> finalizeResult;
            try
            {
                finalizeResult = _connectSession.FinalizeChainAndDhKeys(rootKeyBytes, dhKeyBytes);
            }
            finally
            {
                SodiumInterop.SecureWipe(rootKeyBytes);
                SodiumInterop.SecureWipe(dhKeyBytes);
            }

            if (finalizeResult.IsErr)
                return Result<PubKeyExchange, EcliptixProtocolFailure>.Err(finalizeResult.UnwrapErr());

            Result<Unit, EcliptixProtocolFailure> setPeerResult = _connectSession.SetPeerBundle(peerBundle);
            if (setPeerResult.IsErr)
                return Result<PubKeyExchange, EcliptixProtocolFailure>.Err(setPeerResult.UnwrapErr());

            Result<byte[]?, EcliptixProtocolFailure> dhPublicKeyResult = _connectSession.GetCurrentSenderDhPublicKey();
            if (dhPublicKeyResult.IsErr)
                return Result<PubKeyExchange, EcliptixProtocolFailure>.Err(dhPublicKeyResult.UnwrapErr());

            byte[]? dhPublicKey = dhPublicKeyResult.Unwrap();
            if (dhPublicKey == null)
                return Result<PubKeyExchange, EcliptixProtocolFailure>.Err(
                    EcliptixProtocolFailure.Generic("DH public key is null"));

            return Result<PubKeyExchange, EcliptixProtocolFailure>.Ok(new PubKeyExchange
            {
                State = PubKeyExchangeState.Pending,
                OfType = peerInitialMessageProto.OfType,
                Payload = localBundle.ToProtobufExchange().ToByteString(),
                InitialDhPublicKey = ByteString.CopyFrom(dhPublicKey.AsSpan())
            });
        }
        finally
        {
            rootKeyHandle?.Dispose();
        }
    }

    public Result<PubKeyExchange, EcliptixProtocolFailure> ProcessAuthenticatedPubKeyExchange(
        uint connectId, PubKeyExchange clientPubKeyExchange, byte[] rootKey)
    {
        byte[]? rootKeyCopy = null;
        byte[]? dhKeyBytes = null;
        try
        {
            if (clientPubKeyExchange.State != PubKeyExchangeState.Init)
            {
                return Result<PubKeyExchange, EcliptixProtocolFailure>.Err(
                    EcliptixProtocolFailure.InvalidInput(
                        $"Expected client message state to be Init, but was {clientPubKeyExchange.State}."));
            }

            Result<ProtocolPublicKeyBundle, EcliptixProtocolFailure> bundleParseResult;
            try
            {
                ProtocolPublicKeyBundle parsedBundle =
                    ProtocolPublicKeyBundle.Parser.ParseFrom(clientPubKeyExchange.Payload);
                bundleParseResult =
                    Result<ProtocolPublicKeyBundle, EcliptixProtocolFailure>.Ok(parsedBundle);
            }
            catch (Exception ex)
            {
                bundleParseResult = Result<ProtocolPublicKeyBundle, EcliptixProtocolFailure>.Err(
                    EcliptixProtocolFailure.Decode("Failed to parse client public key bundle from protobuf.", ex));
            }

            if (bundleParseResult.IsErr)
                return Result<PubKeyExchange, EcliptixProtocolFailure>.Err(bundleParseResult.UnwrapErr());

            ProtocolPublicKeyBundle bundle = bundleParseResult.Unwrap();

            if (bundle.IdentityX25519PublicKey.Length != Constants.X25519PublicKeySize ||
                bundle.SignedPreKeyPublicKey.Length != Constants.X25519PublicKeySize ||
                bundle.EphemeralX25519PublicKey.Length != Constants.X25519PublicKeySize)
            {
                return Result<PubKeyExchange, EcliptixProtocolFailure>.Err(
                    EcliptixProtocolFailure.InvalidInput("Invalid key lengths in client bundle."));
            }

            Result<CorePublicKeyBundle, EcliptixProtocolFailure> clientBundleResult =
                CorePublicKeyBundle.FromProtobufExchange(bundle);
            if (clientBundleResult.IsErr)
                return Result<PubKeyExchange, EcliptixProtocolFailure>.Err(clientBundleResult.UnwrapErr());

            CorePublicKeyBundle clientBundle = clientBundleResult.Unwrap();

            Result<bool, EcliptixProtocolFailure> signatureCheckResult =
                EcliptixSystemIdentityKeys.VerifyRemoteSpkSignature(
                    clientBundle.IdentityEd25519, clientBundle.SignedPreKeyPublic, clientBundle.SignedPreKeySignature);
            if (signatureCheckResult.IsErr)
                return Result<PubKeyExchange, EcliptixProtocolFailure>.Err(signatureCheckResult.UnwrapErr());

            if (!signatureCheckResult.Unwrap())
                return Result<PubKeyExchange, EcliptixProtocolFailure>.Err(
                    EcliptixProtocolFailure.InvalidInput("SPK signature verification failed"));

            ecliptixSystemIdentityKeys.GenerateEphemeralKeyPair();

            Result<CorePublicKeyBundle, EcliptixProtocolFailure> serverBundleResult =
                ecliptixSystemIdentityKeys.CreatePublicBundle();
            if (serverBundleResult.IsErr)
                return Result<PubKeyExchange, EcliptixProtocolFailure>.Err(serverBundleResult.UnwrapErr());

            CorePublicKeyBundle serverBundle = serverBundleResult.Unwrap();

            RatchetConfig configToUse = GetConfigForExchangeType(clientPubKeyExchange.OfType);

            Result<EcliptixProtocolConnection, EcliptixProtocolFailure> sessionResult =
                EcliptixProtocolConnection.Create(connectId, false, configToUse);
            if (sessionResult.IsErr)
                return Result<PubKeyExchange, EcliptixProtocolFailure>.Err(sessionResult.UnwrapErr());

            EcliptixProtocolConnection session = sessionResult.Unwrap();

            lock (_lock)
            {
                _connectSession = session;
            }

            rootKeyCopy = new byte[rootKey.Length];
            Array.Copy(rootKey, rootKeyCopy, rootKey.Length);

            ReadOnlySpan<byte> dhKeySpan = clientPubKeyExchange.InitialDhPublicKey.Span;
            dhKeyBytes = new byte[dhKeySpan.Length];
            dhKeySpan.CopyTo(dhKeyBytes);

            Result<Unit, EcliptixProtocolFailure> finalizeResult =
                _connectSession.FinalizeChainAndDhKeys(rootKeyCopy, dhKeyBytes);

            if (finalizeResult.IsErr)
                return Result<PubKeyExchange, EcliptixProtocolFailure>.Err(finalizeResult.UnwrapErr());

            Result<Unit, EcliptixProtocolFailure> setPeerResult = _connectSession.SetPeerBundle(clientBundle);
            if (setPeerResult.IsErr)
                return Result<PubKeyExchange, EcliptixProtocolFailure>.Err(setPeerResult.UnwrapErr());

            Result<byte[]?, EcliptixProtocolFailure> dhPublicKeyResult = _connectSession.GetCurrentSenderDhPublicKey();
            if (dhPublicKeyResult.IsErr)
                return Result<PubKeyExchange, EcliptixProtocolFailure>.Err(dhPublicKeyResult.UnwrapErr());

            byte[]? dhPublicKey = dhPublicKeyResult.Unwrap();
            if (dhPublicKey == null)
                return Result<PubKeyExchange, EcliptixProtocolFailure>.Err(
                    EcliptixProtocolFailure.Generic("DH public key is null"));

            return Result<PubKeyExchange, EcliptixProtocolFailure>.Ok(new PubKeyExchange
            {
                State = PubKeyExchangeState.Pending,
                OfType = clientPubKeyExchange.OfType,
                Payload = serverBundle.ToProtobufExchange().ToByteString(),
                InitialDhPublicKey = ByteString.CopyFrom(dhPublicKey.AsSpan())
            });
        }
        finally
        {
            if (rootKeyCopy != null)
            {
                SodiumInterop.SecureWipe(rootKeyCopy);
            }

            if (dhKeyBytes != null)
            {
                SodiumInterop.SecureWipe(dhKeyBytes);
            }
        }
    }

    public Result<Unit, EcliptixProtocolFailure> CompleteDataCenterPubKeyExchange(PubKeyExchange peerMessage)
    {
        if (_connectSession != null)
        {
            Result<byte[]?, EcliptixProtocolFailure> ourDhKeyResult = _connectSession.GetCurrentSenderDhPublicKey();
            if (ourDhKeyResult.IsOk)
            {
                byte[]? ourDhKey = ourDhKeyResult.Unwrap();
                if (ourDhKey != null)
                {
                    Result<bool, SodiumFailure> constantTimeResult = SodiumInterop.ConstantTimeEquals(
                        peerMessage.InitialDhPublicKey.Span, ourDhKey);
                    if (constantTimeResult.IsOk && constantTimeResult.Unwrap())
                    {
                        return Result<Unit, EcliptixProtocolFailure>.Err(
                            EcliptixProtocolFailure.Generic(
                                "Potential reflection attack detected - peer echoed our DH key"));
                    }
                }
            }
        }

        SodiumSecureMemoryHandle? rootKeyHandle = null;
        try
        {
            Result<ProtocolPublicKeyBundle, EcliptixProtocolFailure> bundleParseResult;
            try
            {
                ProtocolPublicKeyBundle parsedBundle =
                    ProtocolPublicKeyBundle.Parser.ParseFrom(peerMessage.Payload);
                bundleParseResult =
                    Result<ProtocolPublicKeyBundle, EcliptixProtocolFailure>.Ok(parsedBundle);
            }
            catch (Exception ex)
            {
                bundleParseResult = Result<ProtocolPublicKeyBundle, EcliptixProtocolFailure>.Err(
                    EcliptixProtocolFailure.Decode("Failed to parse peer public key bundle from protobuf.", ex));
            }

            if (bundleParseResult.IsErr)
                return Result<Unit, EcliptixProtocolFailure>.Err(bundleParseResult.UnwrapErr());

            ProtocolPublicKeyBundle bundle = bundleParseResult.Unwrap();

            if (bundle.IdentityX25519PublicKey.Length != Constants.X25519PublicKeySize ||
                bundle.SignedPreKeyPublicKey.Length != Constants.X25519PublicKeySize ||
                bundle.EphemeralX25519PublicKey.Length != Constants.X25519PublicKeySize)
            {
                return Result<Unit, EcliptixProtocolFailure>.Err(
                    EcliptixProtocolFailure.InvalidInput("Invalid key lengths in peer bundle."));
            }

            Result<CorePublicKeyBundle, EcliptixProtocolFailure> peerBundleResult =
                CorePublicKeyBundle.FromProtobufExchange(bundle);
            if (peerBundleResult.IsErr)
                return Result<Unit, EcliptixProtocolFailure>.Err(peerBundleResult.UnwrapErr());

            CorePublicKeyBundle peerBundle = peerBundleResult.Unwrap();

            Result<bool, EcliptixProtocolFailure> signatureCheckResult2 =
                EcliptixSystemIdentityKeys.VerifyRemoteSpkSignature(
                    peerBundle.IdentityEd25519, peerBundle.SignedPreKeyPublic, peerBundle.SignedPreKeySignature);
            if (signatureCheckResult2.IsErr)
                return Result<Unit, EcliptixProtocolFailure>.Err(signatureCheckResult2.UnwrapErr());

            if (!signatureCheckResult2.Unwrap())
                return Result<Unit, EcliptixProtocolFailure>.Err(
                    EcliptixProtocolFailure.InvalidInput("SPK signature verification failed"));

            Result<SodiumSecureMemoryHandle, EcliptixProtocolFailure> sharedSecretResult =
                ecliptixSystemIdentityKeys.X3dhDeriveSharedSecret(peerBundle, Constants.X3dhInfo);
            if (sharedSecretResult.IsErr)
                return Result<Unit, EcliptixProtocolFailure>.Err(sharedSecretResult.UnwrapErr());

            rootKeyHandle = sharedSecretResult.Unwrap();

            byte[] rootKeyBytes = new byte[Constants.X25519KeySize];
            Result<Unit, SodiumFailure> readResult = rootKeyHandle.Read(rootKeyBytes);
            if (readResult.IsErr)
            {
                SodiumInterop.SecureWipe(rootKeyBytes);
                return Result<Unit, EcliptixProtocolFailure>.Err(readResult.UnwrapErr().ToEcliptixProtocolFailure());
            }

            ReadOnlySpan<byte> dhKeySpan = peerMessage.InitialDhPublicKey.Span;
            byte[] dhKeyBytes = new byte[dhKeySpan.Length];
            dhKeySpan.CopyTo(dhKeyBytes);

            Result<Unit, EcliptixProtocolFailure> dhKeyValidation = DhValidator.ValidateX25519PublicKey(dhKeyBytes);
            if (dhKeyValidation.IsErr)
            {
                SodiumInterop.SecureWipe(rootKeyBytes);
                SodiumInterop.SecureWipe(dhKeyBytes);
                return Result<Unit, EcliptixProtocolFailure>.Err(dhKeyValidation.UnwrapErr());
            }

            Result<Unit, EcliptixProtocolFailure> finalizeResult;
            try
            {
                finalizeResult = _connectSession!.FinalizeChainAndDhKeys(rootKeyBytes, dhKeyBytes);
            }
            finally
            {
                SodiumInterop.SecureWipe(rootKeyBytes);
                SodiumInterop.SecureWipe(dhKeyBytes);
            }

            if (finalizeResult.IsErr)
                return Result<Unit, EcliptixProtocolFailure>.Err(finalizeResult.UnwrapErr());

            Result<Unit, EcliptixProtocolFailure> setPeerResult = _connectSession!.SetPeerBundle(peerBundle);
            if (setPeerResult.IsErr)
                return Result<Unit, EcliptixProtocolFailure>.Err(setPeerResult.UnwrapErr());

            return Result<Unit, EcliptixProtocolFailure>.Ok(Unit.Value);
        }
        finally
        {
            rootKeyHandle?.Dispose();
        }
    }

    public Result<SecureEnvelope, EcliptixProtocolFailure> ProduceOutboundMessage(byte[] plainPayload)
    {
        Option<EcliptixProtocolConnection> connectionOpt = GetConnectionSafe();
        if (!connectionOpt.HasValue)
            return Result<SecureEnvelope, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.Generic("Protocol connection not initialized"));

        return ProduceSingleMessage(plainPayload, connectionOpt.Value!);
    }

    private Result<SecureEnvelope, EcliptixProtocolFailure> ProduceSingleMessage(byte[] plainPayload,
        EcliptixProtocolConnection connection)
    {
        RatchetChainKey? messageKeyClone = null;
        byte[]? nonce = null;
        byte[]? ad = null;
        byte[]? encrypted = null;
        byte[]? newSenderDhPublicKey = null;
        byte[]? metadataKey = null;
        byte[]? encryptedMetadataBytes = null;
        try
        {
            Result<(RatchetChainKey MessageKey, bool IncludeDhKey), EcliptixProtocolFailure> prepResult =
                connection.PrepareNextSendMessage();
            if (prepResult.IsErr) return Result<SecureEnvelope, EcliptixProtocolFailure>.Err(prepResult.UnwrapErr());

            (RatchetChainKey MessageKey, bool IncludeDhKey) prep = prepResult.Unwrap();

            Result<byte[], EcliptixProtocolFailure> nonceResult = connection.GenerateNextNonce();
            if (nonceResult.IsErr) return Result<SecureEnvelope, EcliptixProtocolFailure>.Err(nonceResult.UnwrapErr());
            nonce = nonceResult.Unwrap();

            Result<byte[], EcliptixProtocolFailure> dhKeyResult = GetOptionalSenderDhKey(prep.IncludeDhKey);
            if (dhKeyResult.IsErr) return Result<SecureEnvelope, EcliptixProtocolFailure>.Err(dhKeyResult.UnwrapErr());
            newSenderDhPublicKey = dhKeyResult.Unwrap();

            if (prep.IncludeDhKey && newSenderDhPublicKey.Length > 0)
            {
                connection.NotifyRatchetRotation();
            }

            Result<RatchetChainKey, EcliptixProtocolFailure> cloneResult = CloneRatchetChainKey(prep.MessageKey);
            if (cloneResult.IsErr) return Result<SecureEnvelope, EcliptixProtocolFailure>.Err(cloneResult.UnwrapErr());
            messageKeyClone = cloneResult.Unwrap();

            Result<CorePublicKeyBundle, EcliptixProtocolFailure> peerBundleResult = connection.GetPeerBundle();
            if (peerBundleResult.IsErr)
                return Result<SecureEnvelope, EcliptixProtocolFailure>.Err(peerBundleResult.UnwrapErr());
            CorePublicKeyBundle peerBundle = peerBundleResult.Unwrap();

            bool isInitiator = connection.IsInitiator();
            ad = isInitiator
                ? CreateAssociatedData(ecliptixSystemIdentityKeys.IdentityX25519PublicKey, peerBundle.IdentityX25519)
                : CreateAssociatedData(peerBundle.IdentityX25519, ecliptixSystemIdentityKeys.IdentityX25519PublicKey);

            byte[] encryptKeyMaterial = new byte[Constants.AesKeySize];
            Result<Unit, EcliptixProtocolFailure> encryptKeyReadResult =
                messageKeyClone.ReadKeyMaterial(encryptKeyMaterial);
            if (encryptKeyReadResult.IsOk)
            {
                SodiumInterop.SecureWipe(encryptKeyMaterial);
            }

            Result<byte[], EcliptixProtocolFailure> encryptResult =
                Encrypt(messageKeyClone!, nonce, plainPayload, ad);
            if (encryptResult.IsErr)
                return Result<SecureEnvelope, EcliptixProtocolFailure>.Err(encryptResult.UnwrapErr());
            encrypted = encryptResult.Unwrap();

            EnvelopeMetadata metadata = SecureEnvelopeBuilder.CreateEnvelopeMetadata(
                GenerateRequestId(),
                ByteString.CopyFrom(nonce.AsSpan()),
                messageKeyClone!.Index);

            byte[] metadataNonce = new byte[Constants.AesGcmNonceSize];
            RandomNumberGenerator.Fill(metadataNonce);

            Result<byte[], EcliptixProtocolFailure> metadataKeyResult = connection.GetMetadataEncryptionKey();
            if (metadataKeyResult.IsErr)
                return Result<SecureEnvelope, EcliptixProtocolFailure>.Err(metadataKeyResult.UnwrapErr());
            metadataKey = metadataKeyResult.Unwrap();

            Result<byte[], EcliptixProtocolFailure> encryptMetadataResult =
                SecureEnvelopeBuilder.EncryptMetadata(metadata, metadataKey, metadataNonce, ad);
            if (encryptMetadataResult.IsErr)
                return Result<SecureEnvelope, EcliptixProtocolFailure>.Err(encryptMetadataResult.UnwrapErr());
            encryptedMetadataBytes = encryptMetadataResult.Unwrap();

            SecureEnvelope payload = new()
            {
                MetaData = ByteString.CopyFrom(encryptedMetadataBytes),
                EncryptedPayload = ByteString.CopyFrom(encrypted.AsSpan()),
                HeaderNonce = ByteString.CopyFrom(metadataNonce),
                Timestamp = Timestamp.FromDateTimeOffset(DateTimeOffset.UtcNow),
                ResultCode = ByteString.CopyFrom(BitConverter.GetBytes((int)EnvelopeResultCode.Success)),
                DhPublicKey = newSenderDhPublicKey.Length > 0
                    ? ByteString.CopyFrom(newSenderDhPublicKey.AsSpan())
                    : ByteString.Empty
            };
            return Result<SecureEnvelope, EcliptixProtocolFailure>.Ok(payload);
        }
        finally
        {
            messageKeyClone?.Dispose();
            if (nonce != null) SodiumInterop.SecureWipe(nonce);
            if (ad != null) SodiumInterop.SecureWipe(ad);
            if (encrypted != null) SodiumInterop.SecureWipe(encrypted);
            if (newSenderDhPublicKey != null) SodiumInterop.SecureWipe(newSenderDhPublicKey);
            if (metadataKey != null) SodiumInterop.SecureWipe(metadataKey);
            if (encryptedMetadataBytes != null) Array.Clear(encryptedMetadataBytes);
        }
    }

    private Result<(SecureEnvelope Envelope, EnvelopeMetadata Metadata), EcliptixProtocolFailure>
        ProduceOutboundEnvelope(byte[] plainPayload,
            EcliptixProtocolConnection connection)
    {
        RatchetChainKey? messageKeyClone = null;
        byte[]? nonce = null;
        byte[]? ad = null;
        byte[]? encrypted = null;
        byte[]? newSenderDhPublicKey = null;
        byte[]? metadataKey = null;
        byte[]? encryptedMetadataBytes = null;
        try
        {
            Result<(RatchetChainKey MessageKey, bool IncludeDhKey), EcliptixProtocolFailure> prepResult =
                connection.PrepareNextSendMessage();
            if (prepResult.IsErr)
                return Result<(SecureEnvelope, EnvelopeMetadata), EcliptixProtocolFailure>.Err(prepResult.UnwrapErr());

            (RatchetChainKey MessageKey, bool IncludeDhKey) prep = prepResult.Unwrap();

            Result<byte[], EcliptixProtocolFailure> nonceResult = connection.GenerateNextNonce();
            if (nonceResult.IsErr)
                return Result<(SecureEnvelope, EnvelopeMetadata), EcliptixProtocolFailure>.Err(nonceResult.UnwrapErr());
            nonce = nonceResult.Unwrap();

            Result<byte[], EcliptixProtocolFailure> dhKeyResult = GetOptionalSenderDhKey(prep.IncludeDhKey);
            if (dhKeyResult.IsErr)
                return Result<(SecureEnvelope, EnvelopeMetadata), EcliptixProtocolFailure>.Err(dhKeyResult.UnwrapErr());
            newSenderDhPublicKey = dhKeyResult.Unwrap();

            if (prep.IncludeDhKey && newSenderDhPublicKey.Length > 0)
            {
                connection.NotifyRatchetRotation();
            }

            Result<RatchetChainKey, EcliptixProtocolFailure> cloneResult = CloneRatchetChainKey(prep.MessageKey);
            if (cloneResult.IsErr)
                return Result<(SecureEnvelope, EnvelopeMetadata), EcliptixProtocolFailure>.Err(cloneResult.UnwrapErr());
            messageKeyClone = cloneResult.Unwrap();

            Result<CorePublicKeyBundle, EcliptixProtocolFailure> peerBundleResult = connection.GetPeerBundle();
            if (peerBundleResult.IsErr)
                return Result<(SecureEnvelope, EnvelopeMetadata), EcliptixProtocolFailure>.Err(
                    peerBundleResult.UnwrapErr());
            CorePublicKeyBundle peerBundle = peerBundleResult.Unwrap();

            bool isInitiator = connection.IsInitiator();
            ad = isInitiator
                ? CreateAssociatedData(ecliptixSystemIdentityKeys.IdentityX25519PublicKey, peerBundle.IdentityX25519)
                : CreateAssociatedData(peerBundle.IdentityX25519, ecliptixSystemIdentityKeys.IdentityX25519PublicKey);

            byte[] encryptKeyMaterial = new byte[Constants.AesKeySize];
            Result<Unit, EcliptixProtocolFailure> encryptKeyReadResult =
                messageKeyClone.ReadKeyMaterial(encryptKeyMaterial);
            if (encryptKeyReadResult.IsOk)
            {
                SodiumInterop.SecureWipe(encryptKeyMaterial);
            }

            Result<byte[], EcliptixProtocolFailure> encryptResult =
                Encrypt(messageKeyClone!, nonce, plainPayload, ad);
            if (encryptResult.IsErr)
                return Result<(SecureEnvelope, EnvelopeMetadata), EcliptixProtocolFailure>.Err(
                    encryptResult.UnwrapErr());
            encrypted = encryptResult.Unwrap();

            EnvelopeMetadata metadata = SecureEnvelopeBuilder.CreateEnvelopeMetadata(
                GenerateRequestId(),
                ByteString.CopyFrom(nonce.AsSpan()),
                messageKeyClone!.Index);

            byte[] metadataNonce = new byte[Constants.AesGcmNonceSize];
            RandomNumberGenerator.Fill(metadataNonce);

            Result<byte[], EcliptixProtocolFailure> metadataKeyResult = connection.GetMetadataEncryptionKey();
            if (metadataKeyResult.IsErr)
                return Result<(SecureEnvelope, EnvelopeMetadata), EcliptixProtocolFailure>.Err(metadataKeyResult
                    .UnwrapErr());
            metadataKey = metadataKeyResult.Unwrap();

            Result<byte[], EcliptixProtocolFailure> encryptMetadataResult =
                SecureEnvelopeBuilder.EncryptMetadata(metadata, metadataKey, metadataNonce, ad);
            if (encryptMetadataResult.IsErr)
                return Result<(SecureEnvelope, EnvelopeMetadata), EcliptixProtocolFailure>.Err(encryptMetadataResult
                    .UnwrapErr());
            encryptedMetadataBytes = encryptMetadataResult.Unwrap();

            SecureEnvelope payload = new()
            {
                MetaData = ByteString.CopyFrom(encryptedMetadataBytes),
                EncryptedPayload = ByteString.CopyFrom(encrypted.AsSpan()),
                HeaderNonce = ByteString.CopyFrom(metadataNonce),
                Timestamp = Timestamp.FromDateTimeOffset(DateTimeOffset.UtcNow),
                ResultCode = ByteString.CopyFrom(BitConverter.GetBytes((int)EnvelopeResultCode.Success)),
                DhPublicKey = newSenderDhPublicKey.Length > 0
                    ? ByteString.CopyFrom(newSenderDhPublicKey.AsSpan())
                    : ByteString.Empty
            };
            return Result<(SecureEnvelope, EnvelopeMetadata), EcliptixProtocolFailure>.Ok((payload, metadata));
        }
        finally
        {
            messageKeyClone?.Dispose();
            if (nonce != null) SodiumInterop.SecureWipe(nonce);
            if (ad != null) SodiumInterop.SecureWipe(ad);
            if (encrypted != null) SodiumInterop.SecureWipe(encrypted);
            if (newSenderDhPublicKey != null) SodiumInterop.SecureWipe(newSenderDhPublicKey);
            if (metadataKey != null) SodiumInterop.SecureWipe(metadataKey);
            if (encryptedMetadataBytes != null) Array.Clear(encryptedMetadataBytes);
        }
    }

    public Result<(EnvelopeMetadata Metadata, byte[] EncryptedPayload), EcliptixProtocolFailure>
        ProduceOutboundEnvelopeMaterials(byte[] plainPayload)
    {
        Option<EcliptixProtocolConnection> connectionOpt = GetConnectionSafe();
        if (!connectionOpt.HasValue)
            return Result<(EnvelopeMetadata Metadata, byte[] EncryptedPayload), EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.Generic("Protocol connection not initialized"));

        Result<(SecureEnvelope Envelope, EnvelopeMetadata Metadata), EcliptixProtocolFailure> payloadResult =
            ProduceOutboundEnvelope(plainPayload, connectionOpt.Value!);
        if (payloadResult.IsErr)
            return Result<(EnvelopeMetadata Metadata, byte[] EncryptedPayload), EcliptixProtocolFailure>.Err(
                payloadResult.UnwrapErr());

        (SecureEnvelope envelope, EnvelopeMetadata metadata) = payloadResult.Unwrap();
        byte[] encryptedPayload = envelope.EncryptedPayload.ToByteArray();

        return Result<(EnvelopeMetadata Metadata, byte[] EncryptedPayload), EcliptixProtocolFailure>.Ok((metadata,
            encryptedPayload));
    }

    public Result<byte[], EcliptixProtocolFailure> ProcessInboundEnvelopeFromMaterials(EnvelopeMetadata metadata,
        byte[] encryptedPayload)
    {
        SecureEnvelope payload = SecureEnvelopeBuilder.CreateSecureEnvelope(
            metadata,
            ByteString.CopyFrom(encryptedPayload),
            Timestamp.FromDateTimeOffset(DateTimeOffset.UtcNow));

        return ProcessInboundEnvelope(payload);
    }

    public Result<byte[], EcliptixProtocolFailure> ProcessInboundEnvelope(SecureEnvelope cipherPayloadProto)
    {
        Option<EcliptixProtocolConnection> connectionOpt = GetConnectionSafe();
        if (!connectionOpt.HasValue)
            return Result<byte[], EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.Generic("Protocol connection not initialized"));

        return ProcessInboundEnvelopeInternal(cipherPayloadProto, connectionOpt.Value!);
    }

    private Result<byte[], EcliptixProtocolFailure> ProcessInboundEnvelopeInternal(SecureEnvelope cipherPayloadProto,
        EcliptixProtocolConnection connection)
    {
        RatchetChainKey? messageKeyClone = null;
        byte[]? metadataKey = null;
        byte[]? metadataNonceBytes = null;
        try
        {
            byte[]? incomingDhKey = null;
            EnvelopeMetadata metadata;
            try
            {
                if (cipherPayloadProto.DhPublicKey != null && cipherPayloadProto.DhPublicKey.Length > 0)
                {
                    ReadOnlySpan<byte> dhKeySpan = cipherPayloadProto.DhPublicKey.Span;
                    incomingDhKey = new byte[dhKeySpan.Length];
                    dhKeySpan.CopyTo(incomingDhKey);
                }

                if (incomingDhKey != null)
                {
                    connection.NotifyRatchetRotation();
                    Result<Unit, EcliptixProtocolFailure> ratchetResult =
                        connection.PerformReceivingRatchet(incomingDhKey);
                    if (ratchetResult.IsErr)
                    {
                        return Result<byte[], EcliptixProtocolFailure>.Err(ratchetResult.UnwrapErr());
                    }

                    connection.NotifyRatchetRotation();
                }

                if (cipherPayloadProto.HeaderNonce.IsEmpty ||
                    cipherPayloadProto.HeaderNonce.Length != Constants.AesGcmNonceSize)
                {
                    return Result<byte[], EcliptixProtocolFailure>.Err(
                        EcliptixProtocolFailure.Generic("Invalid or missing metadata nonce"));
                }

                metadataNonceBytes = cipherPayloadProto.HeaderNonce.ToByteArray();

                Result<CorePublicKeyBundle, EcliptixProtocolFailure> metadataPeerBundleResult =
                    connection.GetPeerBundle();
                if (metadataPeerBundleResult.IsErr)
                    return Result<byte[], EcliptixProtocolFailure>.Err(metadataPeerBundleResult.UnwrapErr());
                CorePublicKeyBundle metadataPeerBundle = metadataPeerBundleResult.Unwrap();

                bool metadataIsInitiator = connection.IsInitiator();
                byte[] metadataAssociatedData = metadataIsInitiator
                    ? CreateAssociatedData(ecliptixSystemIdentityKeys.IdentityX25519PublicKey,
                        metadataPeerBundle.IdentityX25519)
                    : CreateAssociatedData(metadataPeerBundle.IdentityX25519,
                        ecliptixSystemIdentityKeys.IdentityX25519PublicKey);

                Result<byte[], EcliptixProtocolFailure> metadataKeyResult = connection.GetMetadataEncryptionKey();
                if (metadataKeyResult.IsErr)
                {
                    return Result<byte[], EcliptixProtocolFailure>.Err(metadataKeyResult.UnwrapErr());
                }

                metadataKey = metadataKeyResult.Unwrap();

                byte[] encryptedMetadataBytes = cipherPayloadProto.MetaData.ToByteArray();
                Result<EnvelopeMetadata, EcliptixProtocolFailure> metadataResult =
                    SecureEnvelopeBuilder.DecryptMetadata(encryptedMetadataBytes, metadataKey, metadataNonceBytes,
                        metadataAssociatedData);

                if (metadataResult.IsErr)
                {
                    return Result<byte[], EcliptixProtocolFailure>.Err(metadataResult.UnwrapErr());
                }

                metadata = metadataResult.Unwrap();

                Result<Unit, EcliptixProtocolFailure> validationResult =
                    ValidateIncomingMessage(cipherPayloadProto, metadata);
                if (validationResult.IsErr)
                {
                    return Result<byte[], EcliptixProtocolFailure>.Err(validationResult.UnwrapErr());
                }
            }
            catch (Exception ex)
            {
                return Result<byte[], EcliptixProtocolFailure>.Err(
                    EcliptixProtocolFailure.Generic("Failed to parse envelope metadata", ex));
            }

            Result<Unit, EcliptixProtocolFailure> replayCheckResult =
                connection.CheckReplayProtection(metadata.Nonce.Span, metadata.RatchetIndex);
            if (replayCheckResult.IsErr)
            {
                return Result<byte[], EcliptixProtocolFailure>.Err(replayCheckResult.UnwrapErr());
            }

            Result<RatchetChainKey, EcliptixProtocolFailure> deriveResult =
                AttemptMessageProcessingWithRecovery(metadata, incomingDhKey, connection);
            if (deriveResult.IsErr) return Result<byte[], EcliptixProtocolFailure>.Err(deriveResult.UnwrapErr());

            Result<RatchetChainKey, EcliptixProtocolFailure>
                clonedKeyResult = CloneRatchetChainKey(deriveResult.Unwrap());
            if (clonedKeyResult.IsErr) return Result<byte[], EcliptixProtocolFailure>.Err(clonedKeyResult.UnwrapErr());
            messageKeyClone = clonedKeyResult.Unwrap();

            Result<CorePublicKeyBundle, EcliptixProtocolFailure> peerBundleResult = connection.GetPeerBundle();
            if (peerBundleResult.IsErr)
                return Result<byte[], EcliptixProtocolFailure>.Err(peerBundleResult.UnwrapErr());
            CorePublicKeyBundle peerBundle = peerBundleResult.Unwrap();

            bool isInitiator = connection.IsInitiator();
            byte[] associatedData = isInitiator
                ? CreateAssociatedData(ecliptixSystemIdentityKeys.IdentityX25519PublicKey, peerBundle.IdentityX25519)
                : CreateAssociatedData(peerBundle.IdentityX25519, ecliptixSystemIdentityKeys.IdentityX25519PublicKey);

            byte[] keyMaterial = new byte[Constants.AesKeySize];
            Result<Unit, EcliptixProtocolFailure> keyReadResult = messageKeyClone.ReadKeyMaterial(keyMaterial);
            if (keyReadResult.IsOk)
            {
                SodiumInterop.SecureWipe(keyMaterial);
            }

            Result<byte[], EcliptixProtocolFailure> decryptResult =
                Decrypt(messageKeyClone, metadata, cipherPayloadProto, associatedData, connection);
            if (decryptResult.IsErr)
            {
                return decryptResult;
            }

            if (incomingDhKey != null) SodiumInterop.SecureWipe(incomingDhKey);
            SodiumInterop.SecureWipe(associatedData);

            return decryptResult;
        }
        finally
        {
            messageKeyClone?.Dispose();
            if (metadataKey != null) SodiumInterop.SecureWipe(metadataKey);
            if (metadataNonceBytes != null) SodiumInterop.SecureWipe(metadataNonceBytes);
        }
    }

    private Result<byte[], EcliptixProtocolFailure> GetOptionalSenderDhKey(bool include)
    {
        if (!include) return Result<byte[], EcliptixProtocolFailure>.Ok([]);
        if (_connectSession == null)
            return Result<byte[], EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.Generic("Session not established."));
        Result<byte[]?, EcliptixProtocolFailure> dhKeyResult = _connectSession.GetCurrentSenderDhPublicKey();
        if (dhKeyResult.IsErr)
            return Result<byte[], EcliptixProtocolFailure>.Err(dhKeyResult.UnwrapErr());

        byte[]? dhKey = dhKeyResult.Unwrap();
        if (dhKey == null)
            return Result<byte[], EcliptixProtocolFailure>.Err(EcliptixProtocolFailure.Generic("DH key is null"));
        return Result<byte[], EcliptixProtocolFailure>.Ok(dhKey);
    }

    private static Result<RatchetChainKey, EcliptixProtocolFailure> CloneRatchetChainKey(RatchetChainKey key)
    {
        byte[]? keyMaterial = null;
        try
        {
            keyMaterial = ArrayPool<byte>.Shared.Rent(Constants.AesKeySize);
            Span<byte> keySpan = keyMaterial.AsSpan(0, Constants.AesKeySize);
            Result<Unit, EcliptixProtocolFailure> readResult = key.ReadKeyMaterial(keySpan);
            if (readResult.IsErr)
                return Result<RatchetChainKey, EcliptixProtocolFailure>.Err(readResult.UnwrapErr());
            return RatchetChainKey.New(key.Index, keySpan);
        }
        finally
        {
            if (keyMaterial != null) ArrayPool<byte>.Shared.Return(keyMaterial, clearArray: true);
        }
    }

    private static byte[] CreateAssociatedData(ReadOnlySpan<byte> id1, ReadOnlySpan<byte> id2)
    {
        if (id1.Length != Constants.X25519PublicKeySize || id2.Length != Constants.X25519PublicKeySize)
            throw new ArgumentException("Invalid identity key lengths for associated data.");

        Span<byte> ad = stackalloc byte[Constants.X25519PublicKeySize * 2];
        id1.CopyTo(ad);
        id2.CopyTo(ad[Constants.X25519PublicKeySize..]);
        return ad.ToArray();
    }

    private static Result<byte[], EcliptixProtocolFailure> Encrypt(RatchetChainKey key, byte[] nonce,
        byte[] plaintext, byte[] ad)
    {
        byte[]? keyMaterial = null;
        byte[]? ciphertext = null;
        byte[]? tag = null;
        try
        {
            keyMaterial = ArrayPool<byte>.Shared.Rent(Constants.AesKeySize);
            Span<byte> keySpan = keyMaterial.AsSpan(0, Constants.AesKeySize);
            Result<Unit, EcliptixProtocolFailure> readResult = key.ReadKeyMaterial(keySpan);
            if (readResult.IsErr) return Result<byte[], EcliptixProtocolFailure>.Err(readResult.UnwrapErr());

            ciphertext = new byte[plaintext.Length];
            tag = new byte[Constants.AesGcmTagSize];

            using (AesGcm aesGcm = new(keySpan, Constants.AesGcmTagSize))
            {
                aesGcm.Encrypt(nonce, plaintext, ciphertext, tag, ad);
            }

            byte[] result = new byte[ciphertext.Length + tag.Length];
            Buffer.BlockCopy(ciphertext, 0, result, 0, ciphertext.Length);
            Buffer.BlockCopy(tag, 0, result, ciphertext.Length, tag.Length);

            return Result<byte[], EcliptixProtocolFailure>.Ok(result);
        }
        catch (Exception ex)
        {
            if (ciphertext != null) SodiumInterop.SecureWipe(ciphertext);
            if (tag != null) SodiumInterop.SecureWipe(tag);
            return Result<byte[], EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.Generic("AES-GCM encryption failed.", ex));
        }
        finally
        {
            if (keyMaterial != null) ArrayPool<byte>.Shared.Return(keyMaterial, clearArray: true);
        }
    }

    private static Result<byte[], EcliptixProtocolFailure> Decrypt(RatchetChainKey key, EnvelopeMetadata metadata,
        SecureEnvelope payload,
        byte[] ad, EcliptixProtocolConnection? connection = null)
    {
        ReadOnlySpan<byte> fullCipherSpan = payload.EncryptedPayload.Span;
        const int tagSize = Constants.AesGcmTagSize;
        int cipherLength = fullCipherSpan.Length - tagSize;

        if (cipherLength < 0)
            return Result<byte[], EcliptixProtocolFailure>.Err(EcliptixProtocolFailure.BufferTooSmall(
                $"Received ciphertext length ({fullCipherSpan.Length}) is smaller than the GCM tag size ({tagSize})."));

        byte[]? keyMaterial = null;
        byte[]? plaintext = null;
        try
        {
            keyMaterial = ArrayPool<byte>.Shared.Rent(Constants.AesKeySize);
            Span<byte> keySpan = keyMaterial.AsSpan(0, Constants.AesKeySize);
            Result<Unit, EcliptixProtocolFailure> readResult = key.ReadKeyMaterial(keySpan);
            if (readResult.IsErr) return Result<byte[], EcliptixProtocolFailure>.Err(readResult.UnwrapErr());

            ReadOnlySpan<byte> ciphertextSpan = fullCipherSpan[..cipherLength];
            ReadOnlySpan<byte> tagSpan = fullCipherSpan[cipherLength..];
            ReadOnlySpan<byte> nonceSpan = metadata.Nonce.Span;

            plaintext = new byte[cipherLength];
            Span<byte> plaintextSpan = plaintext.AsSpan();

            using (AesGcm aesGcm = new(keySpan, Constants.AesGcmTagSize))
            {
                aesGcm.Decrypt(nonceSpan, ciphertextSpan, tagSpan, plaintextSpan, ad);
            }

            return Result<byte[], EcliptixProtocolFailure>.Ok(plaintext);
        }
        catch (CryptographicException cryptoEx)
        {
            if (plaintext != null) SodiumInterop.SecureWipe(plaintext);
            return Result<byte[], EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.Generic("AES-GCM decryption failed (authentication tag mismatch).", cryptoEx));
        }
        catch (Exception ex)
        {
            if (plaintext != null) SodiumInterop.SecureWipe(plaintext);
            return Result<byte[], EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.Generic("Unexpected error during AES-GCM decryption.", ex));
        }
        finally
        {
            if (keyMaterial != null) ArrayPool<byte>.Shared.Return(keyMaterial, clearArray: true);
        }
    }

    private Result<Unit, EcliptixProtocolFailure> ValidateIncomingMessage(SecureEnvelope payload,
        EnvelopeMetadata metadata)
    {
        if (payload.MetaData.IsEmpty || payload.EncryptedPayload.IsEmpty)
            return Result<Unit, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.Generic("Invalid payload - missing metadata or payload"));

        if (metadata.Nonce.IsEmpty)
            return Result<Unit, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.Generic("Invalid payload - missing nonce"));

        if (metadata.Nonce.Length != Constants.AesGcmNonceSize)
            return Result<Unit, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.Generic(
                    $"Invalid nonce size: {metadata.Nonce.Length}, expected: {Constants.AesGcmNonceSize}"));

        return Result<Unit, EcliptixProtocolFailure>.Ok(Unit.Value);
    }

    private Result<RatchetChainKey, EcliptixProtocolFailure> AttemptMessageProcessingWithRecovery(
        EnvelopeMetadata metadata, byte[]? receivedDhKey, EcliptixProtocolConnection connection)
    {
        try
        {
            Result<RatchetChainKey, EcliptixProtocolFailure> normalResult =
                connection.ProcessReceivedMessage(metadata.RatchetIndex);
            if (normalResult.IsOk)
            {
                return normalResult;
            }

            if (receivedDhKey != null && metadata.RatchetIndex <= 5)
            {
                Result<Unit, EcliptixProtocolFailure>
                    ratchetResult = connection.PerformReceivingRatchet(receivedDhKey);
                if (ratchetResult.IsOk)
                {
                    Result<RatchetChainKey, EcliptixProtocolFailure> retryResult =
                        connection.ProcessReceivedMessage(metadata.RatchetIndex);
                    if (retryResult.IsOk)
                    {
                        return retryResult;
                    }
                }
                else
                {
                }
            }

            Result<Option<RatchetChainKey>, EcliptixProtocolFailure> recoveryResult =
                connection.TryRecoverMessageKey(metadata.RatchetIndex);
            if (recoveryResult.IsOk)
            {
                Option<RatchetChainKey> optionResult = recoveryResult.Unwrap();
                if (optionResult.HasValue)
                {
                    return Result<RatchetChainKey, EcliptixProtocolFailure>.Ok(optionResult.Value!);
                }
            }

            return normalResult;
        }
        catch (Exception ex)
        {
            return Result<RatchetChainKey, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.Generic("Failed to parse cipher header", ex));
        }
    }

    private Result<Unit, EcliptixProtocolFailure> VerifyRecoveredSessionState()
    {
        if (_connectSession == null)
            return Result<Unit, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.Generic("No session to verify"));

        try
        {
            Result<CorePublicKeyBundle, EcliptixProtocolFailure> peerBundleResult = _connectSession.GetPeerBundle();
            if (peerBundleResult.IsErr)
                return Result<Unit, EcliptixProtocolFailure>.Err(
                    EcliptixProtocolFailure.Generic(
                        $"Cannot retrieve peer bundle: {peerBundleResult.UnwrapErr().Message}"));

            Result<byte[]?, EcliptixProtocolFailure> dhKeyResult = _connectSession.GetCurrentSenderDhPublicKey();
            if (dhKeyResult.IsErr)
                return Result<Unit, EcliptixProtocolFailure>.Err(
                    EcliptixProtocolFailure.Generic(
                        $"Cannot retrieve sender DH key: {dhKeyResult.UnwrapErr().Message}"));

            CorePublicKeyBundle peerBundle = peerBundleResult.Unwrap();
            if (peerBundle.IdentityX25519 is not { Length: Constants.X25519PublicKeySize })
                return Result<Unit, EcliptixProtocolFailure>.Err(
                    EcliptixProtocolFailure.Generic("Invalid peer identity key in recovered state"));

            if (peerBundle.SignedPreKeyPublic is not { Length: Constants.X25519PublicKeySize })
                return Result<Unit, EcliptixProtocolFailure>.Err(
                    EcliptixProtocolFailure.Generic("Invalid peer signed pre-key in recovered state"));

            if (ecliptixSystemIdentityKeys.IdentityX25519PublicKey == null ||
                ecliptixSystemIdentityKeys.IdentityX25519PublicKey.Length != Constants.X25519PublicKeySize)
                return Result<Unit, EcliptixProtocolFailure>.Err(
                    EcliptixProtocolFailure.Generic("Invalid system identity key"));

            return Result<Unit, EcliptixProtocolFailure>.Ok(Unit.Value);
        }
        catch (Exception ex)
        {
            return Result<Unit, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.Generic($"Session state verification failed: {ex.Message}"));
        }
    }

    private Result<Unit, EcliptixProtocolFailure> CheckClientIdentityForFreshHandshake(PubKeyExchange peerMessage)
    {
        if (_connectSession == null)
            return Result<Unit, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.Generic("No session to compare against"));

        try
        {
            Result<ProtocolPublicKeyBundle, EcliptixProtocolFailure> currentBundleResult;
            try
            {
                ProtocolPublicKeyBundle parsedBundle =
                    ProtocolPublicKeyBundle.Parser.ParseFrom(peerMessage.Payload);
                currentBundleResult =
                    Result<ProtocolPublicKeyBundle, EcliptixProtocolFailure>.Ok(parsedBundle);
            }
            catch (Exception ex)
            {
                currentBundleResult = Result<ProtocolPublicKeyBundle, EcliptixProtocolFailure>.Err(
                    EcliptixProtocolFailure.Decode("Failed to parse client bundle for identity check", ex));
            }

            if (currentBundleResult.IsErr)
                return Result<Unit, EcliptixProtocolFailure>.Err(currentBundleResult.UnwrapErr());

            ProtocolPublicKeyBundle currentBundle = currentBundleResult.Unwrap();

            Result<CorePublicKeyBundle, EcliptixProtocolFailure> storedBundleResult = _connectSession.GetPeerBundle();
            if (storedBundleResult.IsErr)
                return Result<Unit, EcliptixProtocolFailure>.Err(storedBundleResult.UnwrapErr());

            CorePublicKeyBundle storedBundle = storedBundleResult.Unwrap();

            Result<bool, SodiumFailure> x25519ComparisonResult =
                SodiumInterop.ConstantTimeEquals(currentBundle.IdentityX25519PublicKey.Span, storedBundle.IdentityX25519);
            Result<bool, SodiumFailure> ed25519ComparisonResult =
                SodiumInterop.ConstantTimeEquals(currentBundle.IdentityPublicKey.Span, storedBundle.IdentityEd25519);

            bool x25519Matches = x25519ComparisonResult.IsOk && x25519ComparisonResult.Unwrap();
            bool ed25519Matches = ed25519ComparisonResult.IsOk && ed25519ComparisonResult.Unwrap();

            if (!x25519Matches || !ed25519Matches)
            {
                return Result<Unit, EcliptixProtocolFailure>.Err(
                    EcliptixProtocolFailure.Generic(
                        $"Client identity keys have changed - X25519 match: {x25519Matches}, Ed25519 match: {ed25519Matches}. Fresh handshake required."));
            }

            return Result<Unit, EcliptixProtocolFailure>.Ok(Unit.Value);
        }
        catch (Exception ex)
        {
            return Result<Unit, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.Generic($"Client identity check failed: {ex.Message}"));
        }
    }
    
    private static uint GenerateRequestId()
    {
        Span<byte> buffer = stackalloc byte[4];
        RandomNumberGenerator.Fill(buffer);
        return BitConverter.ToUInt32(buffer);
    }

    private static RatchetConfig GetConfigForExchangeType(PubKeyExchangeType exchangeType)
    {
        return RatchetConfig.Default;
    }
}
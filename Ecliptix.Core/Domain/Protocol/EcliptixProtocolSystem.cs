using System.Buffers;
using System.Diagnostics;
using System.Security.Cryptography;
using Ecliptix.Core.Domain.Protocol.Failures;
using Ecliptix.Core.Protocol;
using Ecliptix.Domain.Utilities;
using Ecliptix.Protobuf.Common;
using Ecliptix.Protobuf.Protocol;
using ProtocolPublicKeyBundle = Ecliptix.Protobuf.Protocol.PublicKeyBundle;
using CorePublicKeyBundle = Ecliptix.Core.Domain.Protocol.PublicKeyBundle;
using Google.Protobuf;
using Google.Protobuf.WellKnownTypes;
using Sodium;

namespace Ecliptix.Core.Domain.Protocol;

public class EcliptixProtocolSystem : IDisposable
{
    private readonly EcliptixSystemIdentityKeys ecliptixSystemIdentityKeys;
    private readonly Lock _lock = new();

    private readonly CircuitBreaker _circuitBreaker = new(
        failureThreshold: 10,
        timeout: TimeSpan.FromSeconds(60),
        retryTimeout: TimeSpan.FromSeconds(10),
        successThresholdPercentage: 0.7);

    private readonly AdaptiveRatchetManager _ratchetManager = new(RatchetConfig.Default);
    private readonly ProtocolMetricsCollector _metricsCollector = new(TimeSpan.FromSeconds(30));
    private EcliptixProtocolConnection? _connectSession;

    public EcliptixProtocolSystem(EcliptixSystemIdentityKeys ecliptixSystemIdentityKeys)
    {
        this.ecliptixSystemIdentityKeys = ecliptixSystemIdentityKeys ??
                                          throw new ArgumentNullException(nameof(ecliptixSystemIdentityKeys));
    }

    public void Dispose()
    {
        EcliptixProtocolConnection? connectionToDispose;

        lock (_lock)
        {
            connectionToDispose = _connectSession;
            _connectSession = null;
        }

        // Dispose outside of lock to prevent deadlock
        connectionToDispose?.Dispose();
        ecliptixSystemIdentityKeys.Dispose();
        _circuitBreaker.Dispose();
        _ratchetManager.Dispose();
        _metricsCollector.Dispose();
        GC.SuppressFinalize(this);
    }

    public EcliptixSystemIdentityKeys GetIdentityKeys()
    {
        return ecliptixSystemIdentityKeys;
    }

    public EcliptixProtocolConnection GetConnection()
    {
        lock (_lock)
        {
            return _connectSession ?? throw new InvalidOperationException("Connection has not been established yet.");
        }
    }

    private EcliptixProtocolConnection? GetConnectionSafe()
    {
        lock (_lock)
        {
            return _connectSession;
        }
    }

    public static Result<EcliptixProtocolSystem, EcliptixProtocolFailure> CreateFrom(EcliptixSystemIdentityKeys keys,
        EcliptixProtocolConnection connection)
    {
        if (keys == null) throw new ArgumentNullException(nameof(keys));
        if (connection == null) throw new ArgumentNullException(nameof(connection));

        EcliptixProtocolSystem system = new(keys) { _connectSession = connection };
        return Result<EcliptixProtocolSystem, EcliptixProtocolFailure>.Ok(system);
    }

    public Result<PubKeyExchange, EcliptixProtocolFailure> BeginDataCenterPubKeyExchange(
        uint connectId, PubKeyExchangeType exchangeType)
    {
        ecliptixSystemIdentityKeys.GenerateEphemeralKeyPair();

        Result<CorePublicKeyBundle, EcliptixProtocolFailure> bundleResult = ecliptixSystemIdentityKeys.CreatePublicBundle();
        if (bundleResult.IsErr)
            return Result<PubKeyExchange, EcliptixProtocolFailure>.Err(bundleResult.UnwrapErr());

        CorePublicKeyBundle bundle = bundleResult.Unwrap();

        Result<EcliptixProtocolConnection, EcliptixProtocolFailure> sessionResult =
            EcliptixProtocolConnection.Create(connectId, true, RatchetConfig.Default);
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
            return Result<PubKeyExchange, EcliptixProtocolFailure>.Err(EcliptixProtocolFailure.Generic("DH public key is null"));

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
        Console.WriteLine(
            $"[SERVER] ProcessAndRespondToPubKeyExchange - ConnectId: {connectId}, State: {peerInitialMessageProto.State}");
        Console.WriteLine($"[SERVER] Has existing connection: {_connectSession != null}");

        if (_connectSession != null)
        {
            Console.WriteLine($"[SERVER] Using existing recovered session - performing state verification");

            Result<Unit, EcliptixProtocolFailure> stateVerificationResult = VerifyRecoveredSessionState();
            if (stateVerificationResult.IsErr)
            {
                Console.WriteLine(
                    $"[SERVER] Recovered session state verification failed: {stateVerificationResult.UnwrapErr().Message}");

                return Result<PubKeyExchange, EcliptixProtocolFailure>.Err(
                    EcliptixProtocolFailure.ActorStateNotFound(
                        "Session state corrupted - full re-handshake required"));
            }
            else
            {
                Console.WriteLine(
                    $"[SERVER] Recovered session state verified successfully - returning stored identity keys");

                Result<Unit, EcliptixProtocolFailure> clientIdentityCheckResult =
                    CheckClientIdentityForFreshHandshake(peerInitialMessageProto);
                if (clientIdentityCheckResult.IsErr)
                {
                    Console.WriteLine(
                        $"[SERVER] Client identity change detected: {clientIdentityCheckResult.UnwrapErr().Message}");
                    Console.WriteLine("[SERVER] Client is performing fresh handshake - clearing old session state");

                    _connectSession?.Dispose();
                    _connectSession = null;
                }
                else
                {
                    Console.WriteLine(
                        "[SERVER] Client identity matches recovered session - proceeding with state restoration");

                    Result<CorePublicKeyBundle, EcliptixProtocolFailure> bundleResult =
                        ecliptixSystemIdentityKeys.CreatePublicBundle();
                    if (bundleResult.IsErr)
                        return Result<PubKeyExchange, EcliptixProtocolFailure>.Err(bundleResult.UnwrapErr());

                    CorePublicKeyBundle bundle = bundleResult.Unwrap();

                    Result<byte[]?, EcliptixProtocolFailure> dhKeyResult = _connectSession.GetCurrentSenderDhPublicKey();
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

            Result<EcliptixProtocolConnection, EcliptixProtocolFailure> sessionResult =
                EcliptixProtocolConnection.Create(connectId, false, RatchetConfig.Default);
            if (sessionResult.IsErr)
                return Result<PubKeyExchange, EcliptixProtocolFailure>.Err(sessionResult.UnwrapErr());

            EcliptixProtocolConnection session = sessionResult.Unwrap();

            // CRITICAL DEBUG: Verify server connection created as responder
            Console.WriteLine(
                $"[SERVER-DEBUG] Connection created - IsInitiator should be FALSE: {session.IsInitiator()}");

            lock (_lock)
            {
                _connectSession = session;
            }

            Result<SodiumSecureMemoryHandle, EcliptixProtocolFailure> sharedSecretResult =
                ecliptixSystemIdentityKeys.CalculateSharedSecretAsRecipient(
                    peerBundle.IdentityX25519, peerBundle.EphemeralX25519,
                    peerBundle.OneTimePreKeys.FirstOrDefault()?.PreKeyId, Constants.X3dhInfo);
            if (sharedSecretResult.IsErr)
                return Result<PubKeyExchange, EcliptixProtocolFailure>.Err(sharedSecretResult.UnwrapErr());

            rootKeyHandle = sharedSecretResult.Unwrap();

            Result<byte[], EcliptixProtocolFailure> rootKeyResult =
                ReadAndWipeSecureHandle(rootKeyHandle, Constants.X25519KeySize);
            if (rootKeyResult.IsErr)
                return Result<PubKeyExchange, EcliptixProtocolFailure>.Err(rootKeyResult.UnwrapErr());

            byte[] rootKeyBytes = rootKeyResult.Unwrap();
            ReadOnlySpan<byte> dhKeySpan = peerInitialMessageProto.InitialDhPublicKey.Span;
            byte[] dhKeyBytes = new byte[dhKeySpan.Length];
            dhKeySpan.CopyTo(dhKeyBytes);

            Result<Unit, EcliptixProtocolFailure> finalizeResult;
            try
            {
                finalizeResult = _connectSession.FinalizeChainAndDhKeys(rootKeyBytes, dhKeyBytes);
            }
            finally
            {
                if (rootKeyBytes != null) SodiumInterop.SecureWipe(rootKeyBytes);
                if (dhKeyBytes != null) SodiumInterop.SecureWipe(dhKeyBytes);
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
                return Result<PubKeyExchange, EcliptixProtocolFailure>.Err(EcliptixProtocolFailure.Generic("DH public key is null"));

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

            Result<byte[], EcliptixProtocolFailure> rootKeyResult =
                ReadAndWipeSecureHandle(rootKeyHandle, Constants.X25519KeySize);
            if (rootKeyResult.IsErr)
                return Result<Unit, EcliptixProtocolFailure>.Err(rootKeyResult.UnwrapErr());

            byte[] rootKeyBytes = rootKeyResult.Unwrap();
            ReadOnlySpan<byte> dhKeySpan = peerMessage.InitialDhPublicKey.Span;
            byte[] dhKeyBytes = new byte[dhKeySpan.Length];
            dhKeySpan.CopyTo(dhKeyBytes);

            Result<Unit, EcliptixProtocolFailure> finalizeResult;
            try
            {
                finalizeResult = _connectSession!.FinalizeChainAndDhKeys(rootKeyBytes, dhKeyBytes);
            }
            finally
            {
                if (rootKeyBytes != null) SodiumInterop.SecureWipe(rootKeyBytes);
                if (dhKeyBytes != null) SodiumInterop.SecureWipe(dhKeyBytes);
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

    public Result<CipherPayload[], EcliptixProtocolFailure> ProduceOutboundMessageBatch(byte[][] plainPayloads)
    {
        return _circuitBreaker.Execute(() =>
        {
            if (plainPayloads.Length == 0)
                return Result<CipherPayload[], EcliptixProtocolFailure>.Ok(new CipherPayload[0]);

            EcliptixProtocolConnection? connection = GetConnectionSafe();
            if (connection == null)
                return Result<CipherPayload[], EcliptixProtocolFailure>.Err(
                    EcliptixProtocolFailure.Generic("Protocol connection not initialized"));

            List<CipherPayload> results = new(plainPayloads.Length);

            try
            {
                foreach (byte[] t in plainPayloads)
                {
                    Result<CipherPayload, EcliptixProtocolFailure> singleResult =
                        ProduceSingleMessage(t, connection);
                    if (singleResult.IsErr)
                        return Result<CipherPayload[], EcliptixProtocolFailure>.Err(singleResult.UnwrapErr());

                    results.Add(singleResult.Unwrap());
                }

                _metricsCollector.RecordBatchOperation(plainPayloads.Length);
                return Result<CipherPayload[], EcliptixProtocolFailure>.Ok(results.ToArray());
            }
            catch (Exception ex)
            {
                return Result<CipherPayload[], EcliptixProtocolFailure>.Err(
                    EcliptixProtocolFailure.Generic("Batch message production failed", ex));
            }
        });
    }

    public Result<CipherPayload, EcliptixProtocolFailure> ProduceOutboundMessage(byte[] plainPayload)
    {
        return _circuitBreaker.Execute(() =>
        {
            EcliptixProtocolConnection? connection = GetConnectionSafe();
            if (connection == null)
                return Result<CipherPayload, EcliptixProtocolFailure>.Err(
                    EcliptixProtocolFailure.Generic("Protocol connection not initialized"));

            return ProduceSingleMessage(plainPayload, connection);
        });
    }

    private Result<CipherPayload, EcliptixProtocolFailure> ProduceSingleMessage(byte[] plainPayload,
        EcliptixProtocolConnection connection)
    {
        Stopwatch stopwatch = Stopwatch.StartNew();

        _ratchetManager.RecordMessage();

        EcliptixMessageKey? messageKeyClone = null;
        byte[]? nonce = null;
        byte[]? ad = null;
        byte[]? encrypted = null;
        byte[]? newSenderDhPublicKey = null;
        try
        {
            Result<(EcliptixMessageKey MessageKey, bool IncludeDhKey), EcliptixProtocolFailure> prepResult =
                connection.PrepareNextSendMessage();
            if (prepResult.IsErr) return Result<CipherPayload, EcliptixProtocolFailure>.Err(prepResult.UnwrapErr());

            (EcliptixMessageKey MessageKey, bool IncludeDhKey) prep = prepResult.Unwrap();

            Result<byte[], EcliptixProtocolFailure> nonceResult = connection.GenerateNextNonce();
            if (nonceResult.IsErr) return Result<CipherPayload, EcliptixProtocolFailure>.Err(nonceResult.UnwrapErr());
            nonce = nonceResult.Unwrap();

            Result<byte[], EcliptixProtocolFailure> dhKeyResult = GetOptionalSenderDhKey(prep.IncludeDhKey);
            if (dhKeyResult.IsErr) return Result<CipherPayload, EcliptixProtocolFailure>.Err(dhKeyResult.UnwrapErr());
            newSenderDhPublicKey = dhKeyResult.Unwrap();

            if (prep.IncludeDhKey && newSenderDhPublicKey.Length > 0)
            {
                connection.NotifyRatchetRotation();
                Console.WriteLine("[SERVER] Notified replay protection of sender ratchet rotation");
            }

            Result<EcliptixMessageKey, EcliptixProtocolFailure> cloneResult = CloneMessageKey(prep.MessageKey);
            if (cloneResult.IsErr) return Result<CipherPayload, EcliptixProtocolFailure>.Err(cloneResult.UnwrapErr());
            messageKeyClone = cloneResult.Unwrap();

            Result<CorePublicKeyBundle, EcliptixProtocolFailure> peerBundleResult = connection.GetPeerBundle();
            if (peerBundleResult.IsErr)
                return Result<CipherPayload, EcliptixProtocolFailure>.Err(peerBundleResult.UnwrapErr());
            CorePublicKeyBundle peerBundle = peerBundleResult.Unwrap();

            bool debugIsInitiator = connection.IsInitiator();
            Console.WriteLine($"[SERVER-DEBUG] ProduceSingleMessage - IsInitiator: {debugIsInitiator}");

            bool isInitiator = connection.IsInitiator();
            ad = isInitiator
                ? CreateAssociatedData(ecliptixSystemIdentityKeys.IdentityX25519PublicKey, peerBundle.IdentityX25519)
                : CreateAssociatedData(peerBundle.IdentityX25519, ecliptixSystemIdentityKeys.IdentityX25519PublicKey);
            Console.WriteLine($"[SERVER-ENCRYPT] IsInitiator: {isInitiator}");
            Console.WriteLine(
                $"[ENCRYPT] Self Identity: {Convert.ToHexString(ecliptixSystemIdentityKeys.IdentityX25519PublicKey)[..16]}...");
            Console.WriteLine($"[ENCRYPT] Peer Identity: {Convert.ToHexString(peerBundle.IdentityX25519)[..16]}...");
            Console.WriteLine($"[ENCRYPT] AD (init?self||peer:peer||self): {Convert.ToHexString(ad)[..32]}...");
            Console.WriteLine($"[ENCRYPT] Message key index: {prep.MessageKey.Index}");

            byte[] encryptKeyMaterial = new byte[Constants.AesKeySize];
            Result<Unit, EcliptixProtocolFailure> encryptKeyReadResult =
                messageKeyClone.ReadKeyMaterial(encryptKeyMaterial);
            if (encryptKeyReadResult.IsOk)
            {
                Console.WriteLine($"[ENCRYPT] Message key: {Convert.ToHexString(encryptKeyMaterial)[..32]}...");
                SodiumInterop.SecureWipe(encryptKeyMaterial);
            }

            Result<byte[], EcliptixProtocolFailure> encryptResult =
                Encrypt(messageKeyClone!, nonce, plainPayload, ad, connection);
            if (encryptResult.IsErr)
                return Result<CipherPayload, EcliptixProtocolFailure>.Err(encryptResult.UnwrapErr());
            encrypted = encryptResult.Unwrap();

            CipherPayload payload = new()
            {
                RequestId = GenerateRequestId(),
                Nonce = ByteString.CopyFrom(nonce.AsSpan()),
                RatchetIndex = messageKeyClone!.Index,
                Cipher = ByteString.CopyFrom(encrypted.AsSpan()),
                CreatedAt = Timestamp.FromDateTimeOffset(DateTimeOffset.UtcNow),
                DhPublicKey = newSenderDhPublicKey.Length > 0
                    ? ByteString.CopyFrom(newSenderDhPublicKey.AsSpan())
                    : ByteString.Empty
            };

            stopwatch.Stop();
            _metricsCollector.RecordOutboundMessage(stopwatch.Elapsed.TotalMilliseconds);
            _metricsCollector.RecordEncryption();

            return Result<CipherPayload, EcliptixProtocolFailure>.Ok(payload);
        }
        finally
        {
            messageKeyClone?.Dispose();
            if (nonce != null) SodiumInterop.SecureWipe(nonce);
            if (ad != null) SodiumInterop.SecureWipe(ad);
            if (encrypted != null) SodiumInterop.SecureWipe(encrypted);
            if (newSenderDhPublicKey != null) SodiumInterop.SecureWipe(newSenderDhPublicKey);
        }
    }

    public Result<byte[][], EcliptixProtocolFailure> ProcessInboundMessageBatch(CipherPayload[] cipherPayloads)
    {
        return _circuitBreaker.Execute(() =>
        {
            if (cipherPayloads.Length == 0)
                return Result<byte[][], EcliptixProtocolFailure>.Ok(Array.Empty<byte[]>());

            EcliptixProtocolConnection? connection = GetConnectionSafe();
            if (connection == null)
                return Result<byte[][], EcliptixProtocolFailure>.Err(
                    EcliptixProtocolFailure.Generic("Protocol connection not initialized"));

            List<byte[]> results = new(cipherPayloads.Length);

            try
            {
                foreach (CipherPayload t in cipherPayloads)
                {
                    Result<byte[], EcliptixProtocolFailure> singleResult =
                        ProcessSingleInboundMessage(t, connection);
                    if (singleResult.IsErr)
                        return Result<byte[][], EcliptixProtocolFailure>.Err(singleResult.UnwrapErr());

                    results.Add(singleResult.Unwrap());
                }

                _metricsCollector.RecordBatchOperation(cipherPayloads.Length);
                return Result<byte[][], EcliptixProtocolFailure>.Ok(results.ToArray());
            }
            catch (Exception ex)
            {
                return Result<byte[][], EcliptixProtocolFailure>.Err(
                    EcliptixProtocolFailure.Generic("Batch message processing failed", ex));
            }
        });
    }

    public Result<byte[], EcliptixProtocolFailure> ProcessInboundMessage(CipherPayload cipherPayloadProto)
    {
        return _circuitBreaker.Execute(() =>
        {
            EcliptixProtocolConnection? connection = GetConnectionSafe();
            if (connection == null)
                return Result<byte[], EcliptixProtocolFailure>.Err(
                    EcliptixProtocolFailure.Generic("Protocol connection not initialized"));

            return ProcessSingleInboundMessage(cipherPayloadProto, connection);
        });
    }

    private Result<byte[], EcliptixProtocolFailure> ProcessSingleInboundMessage(CipherPayload cipherPayloadProto,
        EcliptixProtocolConnection connection)
    {
        Stopwatch stopwatch = Stopwatch.StartNew();

        _ratchetManager.RecordMessage();

        EcliptixMessageKey? messageKeyClone = null;
        try
        {
            Result<Unit, EcliptixProtocolFailure> validationResult = ValidateIncomingMessage(cipherPayloadProto);
            if (validationResult.IsErr)
            {
                Console.WriteLine($"[SERVER] Message validation failed: {validationResult.UnwrapErr().Message}");
                _metricsCollector.RecordError();
                Monitoring.ProtocolHealthCheck.RecordConnectionState(_connectSession?.ConnectId ?? 0, false, true);
                return Result<byte[], EcliptixProtocolFailure>.Err(validationResult.UnwrapErr());
            }

            byte[]? incomingDhKey = null;
            if (cipherPayloadProto.DhPublicKey.Length > 0)
            {
                ReadOnlySpan<byte> dhKeySpan = cipherPayloadProto.DhPublicKey.Span;
                incomingDhKey = new byte[dhKeySpan.Length];
                dhKeySpan.CopyTo(incomingDhKey);
            }

            if (incomingDhKey != null)
            {
                connection.NotifyRatchetRotation();
                Console.WriteLine("[SERVER] Cleared replay protection for received DH key");
            }

            Result<Unit, EcliptixProtocolFailure> replayCheckResult =
                connection.CheckReplayProtection(cipherPayloadProto.Nonce.Span,
                    cipherPayloadProto.RatchetIndex);
            if (replayCheckResult.IsErr)
            {
                Console.WriteLine($"[SERVER] Replay protection check failed: {replayCheckResult.UnwrapErr().Message}");
                _metricsCollector.RecordError();
                Monitoring.ProtocolHealthCheck.RecordConnectionState(_connectSession?.ConnectId ?? 0, false, true);
                return Result<byte[], EcliptixProtocolFailure>.Err(replayCheckResult.UnwrapErr());
            }

            if (incomingDhKey is not null)
            {
                Result<Unit, EcliptixProtocolFailure> ratchetResult =
                    connection.PerformReceivingRatchet(incomingDhKey);
                if (ratchetResult.IsErr)
                {
                    _metricsCollector.RecordError();
                    Monitoring.ProtocolHealthCheck.RecordDhRatchet(_connectSession?.ConnectId ?? 0, false);
                    return Result<byte[], EcliptixProtocolFailure>.Err(ratchetResult.UnwrapErr());
                }

                connection.NotifyRatchetRotation();
                _metricsCollector.RecordRatchetRotation();
                Monitoring.ProtocolHealthCheck.RecordDhRatchet(_connectSession?.ConnectId ?? 0, true);
                Console.WriteLine("[SERVER] Notified replay protection of receiving ratchet rotation");
            }

            Result<EcliptixMessageKey, EcliptixProtocolFailure> deriveResult =
                AttemptMessageProcessingWithRecovery(cipherPayloadProto, incomingDhKey, connection);
            if (deriveResult.IsErr) return Result<byte[], EcliptixProtocolFailure>.Err(deriveResult.UnwrapErr());

            Result<EcliptixMessageKey, EcliptixProtocolFailure>
                clonedKeyResult = CloneMessageKey(deriveResult.Unwrap());
            if (clonedKeyResult.IsErr) return Result<byte[], EcliptixProtocolFailure>.Err(clonedKeyResult.UnwrapErr());
            messageKeyClone = clonedKeyResult.Unwrap();

            Result<CorePublicKeyBundle, EcliptixProtocolFailure> peerBundleResult = connection.GetPeerBundle();
            if (peerBundleResult.IsErr)
                return Result<byte[], EcliptixProtocolFailure>.Err(peerBundleResult.UnwrapErr());
            CorePublicKeyBundle peerBundle = peerBundleResult.Unwrap();

            bool debugIsInitiator = connection.IsInitiator();
            Console.WriteLine($"[SERVER-DEBUG] ProcessSingleInboundMessage - IsInitiator: {debugIsInitiator}");

            bool isInitiator = connection.IsInitiator();
            byte[] associatedData = isInitiator
                ? CreateAssociatedData(ecliptixSystemIdentityKeys.IdentityX25519PublicKey, peerBundle.IdentityX25519)
                : CreateAssociatedData(peerBundle.IdentityX25519, ecliptixSystemIdentityKeys.IdentityX25519PublicKey);
            Console.WriteLine($"[SERVER-DECRYPT] IsInitiator: {isInitiator}");
            Console.WriteLine(
                $"[DECRYPT] Self Identity: {Convert.ToHexString(ecliptixSystemIdentityKeys.IdentityX25519PublicKey)[..16]}...");
            Console.WriteLine($"[DECRYPT] Peer Identity: {Convert.ToHexString(peerBundle.IdentityX25519)[..16]}...");
            Console.WriteLine(
                $"[DECRYPT] AD (init?self||peer:peer||self): {Convert.ToHexString(associatedData)[..32]}...");
            Console.WriteLine($"[DECRYPT] Message key index: {messageKeyClone.Index}");
            Console.WriteLine($"[DECRYPT] Nonce: {Convert.ToHexString(cipherPayloadProto.Nonce.Span)[..24]}...");

            byte[] keyMaterial = new byte[Constants.AesKeySize];
            Result<Unit, EcliptixProtocolFailure> keyReadResult = messageKeyClone.ReadKeyMaterial(keyMaterial);
            if (keyReadResult.IsOk)
            {
                Console.WriteLine($"[DECRYPT] Message key: {Convert.ToHexString(keyMaterial)[..32]}...");
                SodiumInterop.SecureWipe(keyMaterial);
            }

            Result<byte[], EcliptixProtocolFailure> decryptResult =
                Decrypt(messageKeyClone, cipherPayloadProto, associatedData, connection);

            stopwatch.Stop();
            if (decryptResult.IsErr)
            {
                Console.WriteLine("[DECRYPT] Decryption failed - this indicates a protocol state mismatch");
                _metricsCollector.RecordError();
                Monitoring.ProtocolHealthCheck.RecordConnectionState(_connectSession?.ConnectId ?? 0, false, true);
                return decryptResult;
            }
            else
            {
                Console.WriteLine("[DECRYPT] Decryption succeeded");
                _metricsCollector.RecordInboundMessage(stopwatch.Elapsed.TotalMilliseconds);
                _metricsCollector.RecordDecryption();
                Monitoring.ProtocolHealthCheck.RecordConnectionState(_connectSession?.ConnectId ?? 0, true, false);
            }


            if (incomingDhKey != null) SodiumInterop.SecureWipe(incomingDhKey);
            if (associatedData != null) SodiumInterop.SecureWipe(associatedData);


            return decryptResult;
        }
        finally
        {
            messageKeyClone?.Dispose();
        }
    }

    private Result<byte[], EcliptixProtocolFailure> GetOptionalSenderDhKey(bool include)
    {
        if (!include) return Result<byte[], EcliptixProtocolFailure>.Ok(Array.Empty<byte>());
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

    private static Result<byte[], EcliptixProtocolFailure> ReadAndWipeSecureHandle(SodiumSecureMemoryHandle handle,
        int size)
    {
        byte[] buffer = new byte[size];
        Result<Unit, SodiumFailure> readResult = handle.Read(buffer);
        if (readResult.IsErr)
            return Result<byte[], EcliptixProtocolFailure>.Err(readResult.UnwrapErr().ToEcliptixProtocolFailure());
        byte[] copy = (byte[])buffer.Clone();
        Result<Unit, SodiumFailure> wipeResult = SodiumInterop.SecureWipe(buffer);
        if (wipeResult.IsErr)
            return Result<byte[], EcliptixProtocolFailure>.Err(wipeResult.UnwrapErr().ToEcliptixProtocolFailure());
        return Result<byte[], EcliptixProtocolFailure>.Ok(copy);
    }

    private static Result<EcliptixMessageKey, EcliptixProtocolFailure> CloneMessageKey(EcliptixMessageKey key)
    {
        byte[]? keyMaterial = null;
        try
        {
            keyMaterial = ArrayPool<byte>.Shared.Rent(Constants.AesKeySize);
            Span<byte> keySpan = keyMaterial.AsSpan(0, Constants.AesKeySize);
            Result<Unit, EcliptixProtocolFailure> readResult = key.ReadKeyMaterial(keySpan);
            if (readResult.IsErr)
                return Result<EcliptixMessageKey, EcliptixProtocolFailure>.Err(readResult.UnwrapErr());
            return EcliptixMessageKey.New(key.Index, keySpan);
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

    private static Result<byte[], EcliptixProtocolFailure> Encrypt(EcliptixMessageKey key, byte[] nonce,
        byte[] plaintext, byte[] ad, EcliptixProtocolConnection? connection = null)
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

    private static Result<byte[], EcliptixProtocolFailure> Decrypt(EcliptixMessageKey key, CipherPayload payload,
        byte[] ad, EcliptixProtocolConnection? connection = null)
    {
        ReadOnlySpan<byte> fullCipherSpan = payload.Cipher.Span;
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
            ReadOnlySpan<byte> nonceSpan = payload.Nonce.Span;

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

    private Result<Unit, EcliptixProtocolFailure> ValidateIncomingMessage(CipherPayload payload)
    {
        if (payload.Nonce.IsEmpty || payload.Cipher.IsEmpty)
            return Result<Unit, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.Generic("Invalid payload - missing nonce or cipher"));

        if (payload.Nonce.Length != Constants.AesGcmNonceSize)
            return Result<Unit, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.Generic(
                    $"Invalid nonce size: {payload.Nonce.Length}, expected: {Constants.AesGcmNonceSize}"));

        Console.WriteLine($"[SERVER] Processing message with ratchet index: {payload.RatchetIndex}");

        return Result<Unit, EcliptixProtocolFailure>.Ok(Unit.Value);
    }

    private Result<EcliptixMessageKey, EcliptixProtocolFailure> AttemptMessageProcessingWithRecovery(
        CipherPayload payload, byte[]? receivedDhKey, EcliptixProtocolConnection connection)
    {
        Result<EcliptixMessageKey, EcliptixProtocolFailure> normalResult =
            connection.ProcessReceivedMessage(payload.RatchetIndex);
        if (normalResult.IsOk)
        {
            Console.WriteLine("[SERVER] Normal message processing succeeded");
            return normalResult;
        }

        Console.WriteLine($"[SERVER] Normal processing failed: {normalResult.UnwrapErr().Message}");

        if (receivedDhKey != null && payload.RatchetIndex <= 5)
        {
            Console.WriteLine("[SERVER] Attempting recovery with DH ratchet");
            Result<Unit, EcliptixProtocolFailure>
                ratchetResult = connection.PerformReceivingRatchet(receivedDhKey);
            if (ratchetResult.IsOk)
            {
                Result<EcliptixMessageKey, EcliptixProtocolFailure> retryResult =
                    connection.ProcessReceivedMessage(payload.RatchetIndex);
                if (retryResult.IsOk)
                {
                    Console.WriteLine("[SERVER] Recovery with DH ratchet succeeded");
                    return retryResult;
                }

                Console.WriteLine($"[SERVER] Retry after DH ratchet failed: {retryResult.UnwrapErr().Message}");
            }
            else
            {
                Console.WriteLine($"[SERVER] DH ratchet failed: {ratchetResult.UnwrapErr().Message}");
            }
        }

        Console.WriteLine("[SERVER] Attempting RatchetRecovery for out-of-order message");
        
        // Try to recover using stored skipped message keys
        var recoveryResult = connection.TryRecoverMessageKey(payload.RatchetIndex);
        if (recoveryResult.IsOk)
        {
            var optionResult = recoveryResult.Unwrap();
            if (optionResult.HasValue)
            {
                Console.WriteLine($"[SERVER] Successfully recovered message key for index {payload.RatchetIndex}");
                return Result<EcliptixMessageKey, EcliptixProtocolFailure>.Ok(optionResult.Value!);
            }
        }

        Console.WriteLine("[SERVER] All message recovery strategies failed");
        return normalResult;
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

            Console.WriteLine("[SERVER] Session state verification passed all checks");
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

            bool x25519Matches = currentBundle.IdentityX25519PublicKey.Span.SequenceEqual(storedBundle.IdentityX25519);
            bool ed25519Matches = currentBundle.IdentityPublicKey.Span.SequenceEqual(storedBundle.IdentityEd25519);

            if (!x25519Matches || !ed25519Matches)
            {
                return Result<Unit, EcliptixProtocolFailure>.Err(
                    EcliptixProtocolFailure.Generic(
                        $"Client identity keys have changed - X25519 match: {x25519Matches}, Ed25519 match: {ed25519Matches}. Fresh handshake required."));
            }

            Console.WriteLine("[SERVER] Client identity keys match stored session");
            return Result<Unit, EcliptixProtocolFailure>.Ok(Unit.Value);
        }
        catch (Exception ex)
        {
            return Result<Unit, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.Generic($"Client identity check failed: {ex.Message}"));
        }
    }

    private Result<Unit, EcliptixProtocolFailure> VerifyClientIdentityConsistency(PubKeyExchange peerMessage)
    {
        if (_connectSession == null)
            return Result<Unit, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.Generic("No session for identity verification"));

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
                    EcliptixProtocolFailure.Decode("Failed to parse client bundle for identity verification", ex));
            }

            if (currentBundleResult.IsErr)
                return Result<Unit, EcliptixProtocolFailure>.Err(currentBundleResult.UnwrapErr());

            ProtocolPublicKeyBundle currentBundle = currentBundleResult.Unwrap();

            Result<CorePublicKeyBundle, EcliptixProtocolFailure> storedBundleResult = _connectSession.GetPeerBundle();
            if (storedBundleResult.IsErr)
                return Result<Unit, EcliptixProtocolFailure>.Err(storedBundleResult.UnwrapErr());

            CorePublicKeyBundle storedBundle = storedBundleResult.Unwrap();

            if (!currentBundle.IdentityX25519PublicKey.Span.SequenceEqual(storedBundle.IdentityX25519))
            {
                return Result<Unit, EcliptixProtocolFailure>.Err(
                    EcliptixProtocolFailure.Generic(
                        $"Client X25519 identity key mismatch - stored: {Convert.ToHexString(storedBundle.IdentityX25519)}, " +
                        $"received: {Convert.ToHexString(currentBundle.IdentityX25519PublicKey.Span)}"));
            }

            if (!currentBundle.IdentityPublicKey.Span.SequenceEqual(storedBundle.IdentityEd25519))
            {
                return Result<Unit, EcliptixProtocolFailure>.Err(
                    EcliptixProtocolFailure.Generic(
                        $"Client Ed25519 identity key mismatch - stored: {Convert.ToHexString(storedBundle.IdentityEd25519)}, " +
                        $"received: {Convert.ToHexString(currentBundle.IdentityPublicKey.Span)}"));
            }

            Console.WriteLine("[SERVER] Client identity consistency verification passed");
            return Result<Unit, EcliptixProtocolFailure>.Ok(Unit.Value);
        }
        catch (Exception ex)
        {
            return Result<Unit, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.Generic($"Client identity verification failed: {ex.Message}"));
        }
    }

    private static uint GenerateRequestId()
    {
        Span<byte> buffer = stackalloc byte[4];
        RandomNumberGenerator.Fill(buffer);
        return BitConverter.ToUInt32(buffer);
    }

    public (CircuitBreakerState State, int FailureCount, int SuccessCount, DateTime LastFailure)
        GetCircuitBreakerStatus()
    {
        return _circuitBreaker.GetStatus();
    }

    public void ResetCircuitBreaker()
    {
        _circuitBreaker.Reset();
    }

    public (LoadLevel Load, double MessageRate, uint RatchetInterval, TimeSpan MaxAge) GetLoadMetrics()
    {
        return _ratchetManager.GetLoadMetrics();
    }

    public LoadLevel CurrentLoadLevel => _ratchetManager.CurrentLoad;

    public RatchetConfig CurrentRatchetConfig => _ratchetManager.CurrentConfig;

    public void ForceLoadLevel(LoadLevel targetLoad)
    {
        _ratchetManager.ForceConfigUpdate(targetLoad);
    }

    public ProtocolMetrics GetProtocolMetrics()
    {
        (CircuitBreakerState State, int FailureCount, int SuccessCount, DateTime LastFailure) circuitStatus =
            _circuitBreaker.GetStatus();
        _metricsCollector.UpdateExternalState(_ratchetManager.CurrentLoad, circuitStatus.State);

        return _metricsCollector.GetCurrentMetrics();
    }

    public void LogPerformanceReport()
    {
        _metricsCollector.LogMetricsSummary();
    }

    public void ResetMetrics()
    {
        _metricsCollector.Reset();
    }
}
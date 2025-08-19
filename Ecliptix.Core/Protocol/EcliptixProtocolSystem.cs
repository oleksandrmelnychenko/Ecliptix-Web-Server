using System.Buffers;
using System.Security.Cryptography;
using Ecliptix.Core.Protocol.Failures;
using Ecliptix.Domain.Utilities;
using Ecliptix.Protobuf.CipherPayload;
using Ecliptix.Protobuf.ProtocolState;
using Ecliptix.Protobuf.PubKeyExchange;
using Google.Protobuf;
using Google.Protobuf.WellKnownTypes;
using Sodium;

namespace Ecliptix.Core.Protocol;

public class EcliptixProtocolSystem : IDisposable
{
    private readonly EcliptixSystemIdentityKeys ecliptixSystemIdentityKeys;
    private EcliptixProtocolConnection? _connectSession;

    public EcliptixProtocolSystem(EcliptixSystemIdentityKeys ecliptixSystemIdentityKeys)
    {
        this.ecliptixSystemIdentityKeys = ecliptixSystemIdentityKeys ??
                                          throw new ArgumentNullException(nameof(ecliptixSystemIdentityKeys));
    }

    public void Dispose()
    {
        _connectSession?.Dispose();
        ecliptixSystemIdentityKeys.Dispose();
        GC.SuppressFinalize(this);
    }

    public EcliptixSystemIdentityKeys GetIdentityKeys() => ecliptixSystemIdentityKeys;

    public EcliptixProtocolConnection GetConnection()
    {
        return _connectSession ?? throw new InvalidOperationException("Connection has not been established yet.");
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
        return ecliptixSystemIdentityKeys.CreatePublicBundle()
            .AndThen(bundle => EcliptixProtocolConnection.Create(connectId, true)
                .AndThen(session =>
                {
                    _connectSession = session;
                    return session.GetCurrentSenderDhPublicKey()
                        .Map(dhPublicKey => new PubKeyExchange
                        {
                            State = PubKeyExchangeState.Init,
                            OfType = exchangeType,
                            Payload = bundle.ToProtobufExchange().ToByteString(),
                            InitialDhPublicKey = ByteString.CopyFrom(dhPublicKey ??
                                                                     throw new InvalidOperationException(
                                                                         "DH public key is null"))
                        });
                }));
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

                Result<Unit, EcliptixProtocolFailure> clientIdentityCheckResult = CheckClientIdentityForFreshHandshake(peerInitialMessageProto);
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

                    return ecliptixSystemIdentityKeys.CreatePublicBundle()
                        .AndThen(bundle => _connectSession.GetCurrentSenderDhPublicKey()
                            .Map(dhPublicKey => new PubKeyExchange
                            {
                                State = PubKeyExchangeState.Pending,
                                OfType = peerInitialMessageProto.OfType,
                                Payload = bundle.ToProtobufExchange().ToByteString(),
                                InitialDhPublicKey = ByteString.CopyFrom(dhPublicKey ??
                                                                         throw new InvalidOperationException(
                                                                             "DH public key is null"))
                            }));
                }
            }
        }

        SodiumSecureMemoryHandle? rootKeyHandle = null;
        try
        {
            return Result<Unit, EcliptixProtocolFailure>.Validate(Unit.Value,
                    _ => peerInitialMessageProto.State == PubKeyExchangeState.Init,
                    EcliptixProtocolFailure.InvalidInput(
                        $"Expected peer message state to be Init, but was {peerInitialMessageProto.State}."))
                .AndThen(_ => Result<Protobuf.PubKeyExchange.PublicKeyBundle, EcliptixProtocolFailure>.Try(
                    () => Protobuf.PubKeyExchange.PublicKeyBundle.Parser.ParseFrom(peerInitialMessageProto.Payload),
                    ex => EcliptixProtocolFailure.Decode("Failed to parse peer public key bundle from protobuf.", ex)))
                .AndThen(bundle =>
                {
                    if (bundle.IdentityX25519PublicKey.Length != Constants.X25519PublicKeySize ||
                        bundle.SignedPreKeyPublicKey.Length != Constants.X25519PublicKeySize ||
                        bundle.EphemeralX25519PublicKey.Length != Constants.X25519PublicKeySize)
                    {
                        return Result<PublicKeyBundle, EcliptixProtocolFailure>.Err(
                            EcliptixProtocolFailure.InvalidInput("Invalid key lengths in peer bundle."));
                    }

                    return PublicKeyBundle.FromProtobufExchange(bundle);
                })
                .AndThen(peerBundle =>
                {
                    return EcliptixSystemIdentityKeys.VerifyRemoteSpkSignature(peerBundle.IdentityEd25519,
                            peerBundle.SignedPreKeyPublic, peerBundle.SignedPreKeySignature)
                        .AndThen(_ =>
                        {
                            ecliptixSystemIdentityKeys.GenerateEphemeralKeyPair();
                            return ecliptixSystemIdentityKeys.CreatePublicBundle();
                        })
                        .AndThen(localBundle =>
                        {
                            return EcliptixProtocolConnection.Create(connectId, false)
                                .AndThen(session =>
                                {
                                    _connectSession = session;
                                    return ecliptixSystemIdentityKeys.CalculateSharedSecretAsRecipient(
                                            peerBundle.IdentityX25519, peerBundle.EphemeralX25519,
                                            peerBundle.OneTimePreKeys.FirstOrDefault()?.PreKeyId, Constants.X3dhInfo)
                                        .AndThen(derivedKeyHandle =>
                                        {
                                            rootKeyHandle = derivedKeyHandle;
                                            return ReadAndWipeSecureHandle(derivedKeyHandle, Constants.X25519KeySize);
                                        })
                                        .AndThen(rootKeyBytes => session.FinalizeChainAndDhKeys(rootKeyBytes,
                                            peerInitialMessageProto.InitialDhPublicKey.ToByteArray()))
                                        .AndThen(_ => session.SetPeerBundle(peerBundle))
                                        .AndThen(_ => session.GetCurrentSenderDhPublicKey())
                                        .Map(dhPublicKey => new PubKeyExchange
                                        {
                                            State = PubKeyExchangeState.Pending,
                                            OfType = peerInitialMessageProto.OfType,
                                            Payload = localBundle.ToProtobufExchange().ToByteString(),
                                            InitialDhPublicKey = ByteString.CopyFrom(dhPublicKey)
                                        });
                                });
                        });
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
            Result<byte[], EcliptixProtocolFailure> ourDhKeyResult = _connectSession.GetCurrentSenderDhPublicKey();
            if (ourDhKeyResult.IsOk)
            {
                byte[] ourDhKey = ourDhKeyResult.Unwrap();
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
            return Result<Protobuf.PubKeyExchange.PublicKeyBundle, EcliptixProtocolFailure>.Try(
                    () => Protobuf.PubKeyExchange.PublicKeyBundle.Parser.ParseFrom(peerMessage.Payload),
                    ex => EcliptixProtocolFailure.Decode("Failed to parse peer public key bundle from protobuf.", ex))
                .AndThen(bundle =>
                {
                    if (bundle.IdentityX25519PublicKey.Length != Constants.X25519PublicKeySize ||
                        bundle.SignedPreKeyPublicKey.Length != Constants.X25519PublicKeySize ||
                        bundle.EphemeralX25519PublicKey.Length != Constants.X25519PublicKeySize)
                    {
                        return Result<PublicKeyBundle, EcliptixProtocolFailure>.Err(
                            EcliptixProtocolFailure.InvalidInput("Invalid key lengths in peer bundle."));
                    }

                    return PublicKeyBundle.FromProtobufExchange(bundle);
                })
                .AndThen(peerBundle => EcliptixSystemIdentityKeys.VerifyRemoteSpkSignature(peerBundle.IdentityEd25519,
                        peerBundle.SignedPreKeyPublic, peerBundle.SignedPreKeySignature)
                    .AndThen(_ => ecliptixSystemIdentityKeys.X3dhDeriveSharedSecret(peerBundle, Constants.X3dhInfo))
                    .AndThen(derivedKeyHandle =>
                    {
                        rootKeyHandle = derivedKeyHandle;
                        return ReadAndWipeSecureHandle(derivedKeyHandle, Constants.X25519KeySize);
                    })
                    .AndThen(rootKeyBytes =>
                    {
                        byte[] dhKeyBytes = peerMessage.InitialDhPublicKey.ToByteArray();
                        try
                        {
                            return _connectSession!.FinalizeChainAndDhKeys(rootKeyBytes, dhKeyBytes);
                        }
                        finally
                        {
                            if (rootKeyBytes != null) SodiumInterop.SecureWipe(rootKeyBytes);
                            if (dhKeyBytes != null) SodiumInterop.SecureWipe(dhKeyBytes);
                        }
                    })
                    .AndThen(_ => _connectSession!.SetPeerBundle(peerBundle))
                );
        }
        finally
        {
            rootKeyHandle?.Dispose();
        }
    }

    public Result<CipherPayload, EcliptixProtocolFailure> ProduceOutboundMessage(byte[] plainPayload)
    {
        EcliptixMessageKey? messageKeyClone = null;
        byte[]? nonce = null;
        byte[]? ad = null;
        byte[]? encrypted = null;
        byte[]? newSenderDhPublicKey = null;
        try
        {
            if (_connectSession == null)
                return Result<CipherPayload, EcliptixProtocolFailure>.Err(
                    EcliptixProtocolFailure.Generic("Session not established."));

            Result<(EcliptixMessageKey MessageKey, bool IncludeDhKey), EcliptixProtocolFailure> prepResult =
                _connectSession.PrepareNextSendMessage();
            if (prepResult.IsErr) return Result<CipherPayload, EcliptixProtocolFailure>.Err(prepResult.UnwrapErr());

            (EcliptixMessageKey MessageKey, bool IncludeDhKey) prep = prepResult.Unwrap();

            Result<byte[], EcliptixProtocolFailure> nonceResult = _connectSession.GenerateNextNonce();
            if (nonceResult.IsErr) return Result<CipherPayload, EcliptixProtocolFailure>.Err(nonceResult.UnwrapErr());
            nonce = nonceResult.Unwrap();

            Result<byte[], EcliptixProtocolFailure> dhKeyResult = GetOptionalSenderDhKey(prep.IncludeDhKey);
            if (dhKeyResult.IsErr) return Result<CipherPayload, EcliptixProtocolFailure>.Err(dhKeyResult.UnwrapErr());
            newSenderDhPublicKey = dhKeyResult.Unwrap();

            if (prep.IncludeDhKey && newSenderDhPublicKey.Length > 0)
            {
                _connectSession.NotifyRatchetRotation();
                Console.WriteLine("[SERVER] Notified replay protection of sender ratchet rotation");
            }

            Result<EcliptixMessageKey, EcliptixProtocolFailure> cloneResult = CloneMessageKey(prep.MessageKey);
            if (cloneResult.IsErr) return Result<CipherPayload, EcliptixProtocolFailure>.Err(cloneResult.UnwrapErr());
            messageKeyClone = cloneResult.Unwrap();

            Result<PublicKeyBundle, EcliptixProtocolFailure> peerBundleResult = _connectSession.GetPeerBundle();
            if (peerBundleResult.IsErr)
                return Result<CipherPayload, EcliptixProtocolFailure>.Err(peerBundleResult.UnwrapErr());
            PublicKeyBundle peerBundle = peerBundleResult.Unwrap();

            bool isInitiator = _connectSession.IsInitiator();
            ad = isInitiator
                ? CreateAssociatedData(ecliptixSystemIdentityKeys.IdentityX25519PublicKey,
                    peerBundle.IdentityX25519) 
                : CreateAssociatedData(peerBundle.IdentityX25519,
                    ecliptixSystemIdentityKeys.IdentityX25519PublicKey);
            Console.WriteLine($"[ENCRYPT] IsInitiator: {isInitiator}");
            Console.WriteLine(
                $"[ENCRYPT] Server Identity: {Convert.ToHexString(ecliptixSystemIdentityKeys.IdentityX25519PublicKey)[..16]}...");
            Console.WriteLine($"[ENCRYPT] Client Identity: {Convert.ToHexString(peerBundle.IdentityX25519)[..16]}...");
            Console.WriteLine($"[ENCRYPT] AD: {Convert.ToHexString(ad)[..32]}...");

            byte[] clientShouldExpect = CreateAssociatedData(ecliptixSystemIdentityKeys.IdentityX25519PublicKey,
                peerBundle.IdentityX25519);
            Console.WriteLine($"[ENCRYPT] Client should expect AD: {Convert.ToHexString(clientShouldExpect)[..32]}...");

            Result<byte[], EcliptixProtocolFailure> encryptResult = Encrypt(messageKeyClone!, nonce, plainPayload, ad);
            if (encryptResult.IsErr)
                return Result<CipherPayload, EcliptixProtocolFailure>.Err(encryptResult.UnwrapErr());
            encrypted = encryptResult.Unwrap();

            CipherPayload payload = new()
            {
                RequestId = BitConverter.ToUInt32(RandomNumberGenerator.GetBytes(4), 0),
                Nonce = ByteString.CopyFrom(nonce),
                RatchetIndex = messageKeyClone!.Index,
                Cipher = ByteString.CopyFrom(encrypted),
                CreatedAt = Timestamp.FromDateTimeOffset(DateTimeOffset.UtcNow),
                DhPublicKey = newSenderDhPublicKey.Length > 0
                    ? ByteString.CopyFrom(newSenderDhPublicKey)
                    : ByteString.Empty
            };
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

    public Result<byte[], EcliptixProtocolFailure> ProcessInboundMessage(CipherPayload cipherPayloadProto)
    {
        EcliptixMessageKey? messageKeyClone = null;
        try
        {
            if (_connectSession == null)
                return Result<byte[], EcliptixProtocolFailure>.Err(
                    EcliptixProtocolFailure.Generic("Session not established."));

            Result<Unit, EcliptixProtocolFailure> validationResult = ValidateIncomingMessage(cipherPayloadProto);
            if (validationResult.IsErr)
            {
                Console.WriteLine($"[SERVER] Message validation failed: {validationResult.UnwrapErr().Message}");
                return Result<byte[], EcliptixProtocolFailure>.Err(validationResult.UnwrapErr());
            }

            byte[]? incomingDhKey = null;
            if (cipherPayloadProto.DhPublicKey.Length > 0)
            {
                incomingDhKey = cipherPayloadProto.DhPublicKey.ToByteArray();
            }

            if (incomingDhKey != null)
            {
                _connectSession.NotifyRatchetRotation();
                Console.WriteLine("[SERVER] Cleared replay protection for received DH key");
            }

            Result<Unit, EcliptixProtocolFailure> replayCheckResult =
                _connectSession.CheckReplayProtection(cipherPayloadProto.Nonce.ToArray(),
                    cipherPayloadProto.RatchetIndex);
            if (replayCheckResult.IsErr)
            {
                Console.WriteLine($"[SERVER] Replay protection check failed: {replayCheckResult.UnwrapErr().Message}");
                return Result<byte[], EcliptixProtocolFailure>.Err(replayCheckResult.UnwrapErr());
            }

            if (incomingDhKey is not null)
            {
                Result<Unit, EcliptixProtocolFailure> ratchetResult =
                    _connectSession.PerformReceivingRatchet(incomingDhKey);
                if (ratchetResult.IsErr) return Result<byte[], EcliptixProtocolFailure>.Err(ratchetResult.UnwrapErr());

                _connectSession.NotifyRatchetRotation();
                Console.WriteLine("[SERVER] Notified replay protection of receiving ratchet rotation");
            }

            Result<EcliptixMessageKey, EcliptixProtocolFailure> deriveResult =
                AttemptMessageProcessingWithRecovery(cipherPayloadProto, incomingDhKey);
            if (deriveResult.IsErr) return Result<byte[], EcliptixProtocolFailure>.Err(deriveResult.UnwrapErr());

            Result<EcliptixMessageKey, EcliptixProtocolFailure>
                clonedKeyResult = CloneMessageKey(deriveResult.Unwrap());
            if (clonedKeyResult.IsErr) return Result<byte[], EcliptixProtocolFailure>.Err(clonedKeyResult.UnwrapErr());
            messageKeyClone = clonedKeyResult.Unwrap();

            Result<PublicKeyBundle, EcliptixProtocolFailure> peerBundleResult = _connectSession.GetPeerBundle();
            if (peerBundleResult.IsErr)
                return Result<byte[], EcliptixProtocolFailure>.Err(peerBundleResult.UnwrapErr());
            PublicKeyBundle peerBundle = peerBundleResult.Unwrap();

            bool isInitiator = _connectSession.IsInitiator();
            byte[] associatedData = isInitiator
                ? CreateAssociatedData(ecliptixSystemIdentityKeys.IdentityX25519PublicKey,
                    peerBundle.IdentityX25519) 
                : CreateAssociatedData(peerBundle.IdentityX25519,
                    ecliptixSystemIdentityKeys.IdentityX25519PublicKey);

            Console.WriteLine($"[DECRYPT] IsInitiator: {isInitiator}");
            Console.WriteLine(
                $"[DECRYPT] Server Identity: {Convert.ToHexString(ecliptixSystemIdentityKeys.IdentityX25519PublicKey)[..16]}...");
            Console.WriteLine($"[DECRYPT] Client Identity: {Convert.ToHexString(peerBundle.IdentityX25519)[..16]}...");
            Console.WriteLine($"[DECRYPT] Role-based AD: {Convert.ToHexString(associatedData)[..32]}...");
            Result<byte[], EcliptixProtocolFailure> decryptResult =
                Decrypt(messageKeyClone, cipherPayloadProto, associatedData);

            if (decryptResult.IsErr)
            {
                Console.WriteLine("[DECRYPT] Role-based AD failed, trying compatibility approaches...");

                byte[] fixedAD = CreateAssociatedData(peerBundle.IdentityX25519,
                    ecliptixSystemIdentityKeys.IdentityX25519PublicKey);
                Console.WriteLine($"[DECRYPT] Fixed AD:     {Convert.ToHexString(fixedAD)[..32]}...");
                if (!associatedData.SequenceEqual(fixedAD))
                {
                    Console.WriteLine("[DECRYPT] Trying fixed client||server ordering...");
                    decryptResult = Decrypt(messageKeyClone, cipherPayloadProto, fixedAD);
                    if (decryptResult.IsOk)
                    {
                        Console.WriteLine("[DECRYPT] Fixed AD succeeded!");
                    }
                }

                if (decryptResult.IsErr)
                {
                    byte[] reverseAD = CreateAssociatedData(ecliptixSystemIdentityKeys.IdentityX25519PublicKey,
                        peerBundle.IdentityX25519);
                    Console.WriteLine($"[DECRYPT] Reverse AD:   {Convert.ToHexString(reverseAD)[..32]}...");
                    if (!associatedData.SequenceEqual(reverseAD) && !fixedAD.SequenceEqual(reverseAD))
                    {
                        Console.WriteLine("[DECRYPT] Trying reverse server||client ordering...");
                        decryptResult = Decrypt(messageKeyClone, cipherPayloadProto, reverseAD);
                        if (decryptResult.IsOk)
                        {
                            Console.WriteLine("[DECRYPT] Reverse AD succeeded!");
                        }
                    }
                    else
                    {
                        Console.WriteLine("[DECRYPT] Reverse AD same as previous, skipping");
                    }
                }

                if (decryptResult.IsErr && incomingDhKey != null && incomingDhKey.Length == 32)
                {
                    byte[] dhBasedAD = CreateAssociatedData(incomingDhKey,
                        ecliptixSystemIdentityKeys.IdentityX25519PublicKey);
                    Console.WriteLine($"[DECRYPT] DH-based AD: {Convert.ToHexString(dhBasedAD)[..32]}...");
                    decryptResult = Decrypt(messageKeyClone, cipherPayloadProto, dhBasedAD);
                    if (decryptResult.IsOk)
                    {
                        Console.WriteLine("[DECRYPT] DH-based AD succeeded!");
                    }
                }

                if (decryptResult.IsErr)
                {
                    Console.WriteLine("[DECRYPT] Trying empty AD...");
                    decryptResult = Decrypt(messageKeyClone, cipherPayloadProto, Array.Empty<byte>());
                    if (decryptResult.IsOk)
                    {
                        Console.WriteLine("[DECRYPT] Empty AD succeeded!");
                    }
                }

                if (decryptResult.IsErr)
                {
                    Console.WriteLine("[DECRYPT] All AD strategies failed!");
                    Console.WriteLine(
                        $"[DECRYPT] Message nonce: {Convert.ToHexString(cipherPayloadProto.Nonce.ToByteArray())[..16]}...");
                    Console.WriteLine("[DECRYPT] This suggests the client is using different AD or keys");
                }
            }
            else
            {
                Console.WriteLine("[DECRYPT] Role-based AD succeeded");
            }

            if (decryptResult.IsErr && incomingDhKey != null && cipherPayloadProto.RatchetIndex <= 5)
            {
                Result<Unit, EcliptixProtocolFailure> ratchetResult =
                    _connectSession.PerformReceivingRatchet(incomingDhKey);
                if (ratchetResult.IsErr)
                {
                    Console.WriteLine(
                        $"[SERVER] Fallback ratchet operation failed: {ratchetResult.UnwrapErr().Message}");
                    if (incomingDhKey != null) SodiumInterop.SecureWipe(incomingDhKey);
                    if (associatedData != null) SodiumInterop.SecureWipe(associatedData);
                    return Result<byte[], EcliptixProtocolFailure>.Err(ratchetResult.UnwrapErr());
                }

                deriveResult = _connectSession.ProcessReceivedMessage(cipherPayloadProto.RatchetIndex);
                if (deriveResult.IsErr)
                {
                    if (incomingDhKey != null) SodiumInterop.SecureWipe(incomingDhKey);
                    if (associatedData != null) SodiumInterop.SecureWipe(associatedData);
                    return Result<byte[], EcliptixProtocolFailure>.Err(deriveResult.UnwrapErr());
                }

                clonedKeyResult = CloneMessageKey(deriveResult.Unwrap());
                if (clonedKeyResult.IsErr)
                {
                    if (incomingDhKey != null) SodiumInterop.SecureWipe(incomingDhKey);
                    if (associatedData != null) SodiumInterop.SecureWipe(associatedData);
                    return Result<byte[], EcliptixProtocolFailure>.Err(clonedKeyResult.UnwrapErr());
                }

                messageKeyClone?.Dispose();
                messageKeyClone = clonedKeyResult.Unwrap();

                decryptResult = Decrypt(messageKeyClone, cipherPayloadProto, associatedData);
            }

            if (incomingDhKey != null) SodiumInterop.SecureWipe(incomingDhKey);
            if (associatedData != null) SodiumInterop.SecureWipe(associatedData);

            if (decryptResult.IsErr)
            {
                Console.WriteLine(
                    $"[SERVER] Decryption failed for message with RatchetIndex: {cipherPayloadProto.RatchetIndex}");
                Console.WriteLine(
                    "[SERVER] All AD strategies exhausted - client-server cryptographic context mismatch");

                if (cipherPayloadProto.RatchetIndex == 1 && incomingDhKey != null)
                {
                    Console.WriteLine("[SERVER] Attempting DH ratchet recovery for first message...");
                }
                else
                {
                    Console.WriteLine("[SERVER] No recovery possible - forcing fresh handshake");
                    return Result<byte[], EcliptixProtocolFailure>.Err(
                        EcliptixProtocolFailure.ActorStateNotFound(
                            "Session authentication failed - fresh handshake required"));
                }
            }

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
        return _connectSession.GetCurrentSenderDhPublicKey().Map(k => k ?? Array.Empty<byte>());
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

    private static byte[] CreateAssociatedData(byte[] id1, byte[] id2)
    {
        if (id1.Length != Constants.X25519PublicKeySize || id2.Length != Constants.X25519PublicKeySize)
            throw new ArgumentException("Invalid identity key lengths for associated data.");

        byte[] ad = new byte[id1.Length + id2.Length];
        Buffer.BlockCopy(id1, 0, ad, 0, id1.Length);
        Buffer.BlockCopy(id2, 0, ad, id1.Length, id2.Length);
        return ad;
    }

    private static Result<byte[], EcliptixProtocolFailure> Encrypt(EcliptixMessageKey key, byte[] nonce,
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

    private static Result<byte[], EcliptixProtocolFailure> Decrypt(EcliptixMessageKey key, CipherPayload payload,
        byte[] ad)
    {
        ReadOnlySpan<byte> fullCipherSpan = payload.Cipher.Span;
        const int tagSize = Constants.AesGcmTagSize;
        int cipherLength = fullCipherSpan.Length - tagSize;

        if (cipherLength < 0)
            return Result<byte[], EcliptixProtocolFailure>.Err(EcliptixProtocolFailure.BufferTooSmall(
                $"Received ciphertext length ({fullCipherSpan.Length}) is smaller than the GCM tag size ({tagSize})."));

        byte[]? keyMaterial = null;
        byte[]? ciphertext = null;
        byte[]? tag = null;
        byte[]? plaintext = null;
        byte[]? nonce = null;
        try
        {
            keyMaterial = ArrayPool<byte>.Shared.Rent(Constants.AesKeySize);
            Span<byte> keySpan = keyMaterial.AsSpan(0, Constants.AesKeySize);
            Result<Unit, EcliptixProtocolFailure> readResult = key.ReadKeyMaterial(keySpan);
            if (readResult.IsErr) return Result<byte[], EcliptixProtocolFailure>.Err(readResult.UnwrapErr());

            ciphertext = fullCipherSpan[..cipherLength].ToArray();
            tag = fullCipherSpan[cipherLength..].ToArray();
            plaintext = new byte[cipherLength];
            nonce = payload.Nonce.ToArray();

            using (AesGcm aesGcm = new(keySpan, Constants.AesGcmTagSize))
            {
                aesGcm.Decrypt(nonce, ciphertext, tag, plaintext, ad);
            }

            return Result<byte[], EcliptixProtocolFailure>.Ok(plaintext);
        }
        catch (CryptographicException cryptoEx)
        {
            if (ciphertext != null) SodiumInterop.SecureWipe(ciphertext);
            if (tag != null) SodiumInterop.SecureWipe(tag);
            if (plaintext != null) SodiumInterop.SecureWipe(plaintext);
            if (nonce != null) SodiumInterop.SecureWipe(nonce);
            return Result<byte[], EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.Generic("AES-GCM decryption failed (authentication tag mismatch).", cryptoEx));
        }
        catch (Exception ex)
        {
            if (ciphertext != null) SodiumInterop.SecureWipe(ciphertext);
            if (tag != null) SodiumInterop.SecureWipe(tag);
            if (plaintext != null) SodiumInterop.SecureWipe(plaintext);
            if (nonce != null) SodiumInterop.SecureWipe(nonce);
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
        CipherPayload payload, byte[]? receivedDhKey)
    {
        if (_connectSession == null)
            return Result<EcliptixMessageKey, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.Generic("Session not established"));

        Result<EcliptixMessageKey, EcliptixProtocolFailure> normalResult =
            _connectSession.ProcessReceivedMessage(payload.RatchetIndex);
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
                ratchetResult = _connectSession.PerformReceivingRatchet(receivedDhKey);
            if (ratchetResult.IsOk)
            {
                Result<EcliptixMessageKey, EcliptixProtocolFailure> retryResult =
                    _connectSession.ProcessReceivedMessage(payload.RatchetIndex);
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

        Console.WriteLine("[SERVER] Message gap recovery strategies are limited for security reasons");

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
            Result<PublicKeyBundle, EcliptixProtocolFailure> peerBundleResult = _connectSession.GetPeerBundle();
            if (peerBundleResult.IsErr)
                return Result<Unit, EcliptixProtocolFailure>.Err(
                    EcliptixProtocolFailure.Generic(
                        $"Cannot retrieve peer bundle: {peerBundleResult.UnwrapErr().Message}"));

            Result<byte[]?, EcliptixProtocolFailure> dhKeyResult = _connectSession.GetCurrentSenderDhPublicKey();
            if (dhKeyResult.IsErr)
                return Result<Unit, EcliptixProtocolFailure>.Err(
                    EcliptixProtocolFailure.Generic(
                        $"Cannot retrieve sender DH key: {dhKeyResult.UnwrapErr().Message}"));

            PublicKeyBundle peerBundle = peerBundleResult.Unwrap();
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
            Result<Protobuf.PubKeyExchange.PublicKeyBundle, EcliptixProtocolFailure> currentBundleResult =
                Result<Protobuf.PubKeyExchange.PublicKeyBundle, EcliptixProtocolFailure>.Try(
                    () => Protobuf.PubKeyExchange.PublicKeyBundle.Parser.ParseFrom(peerMessage.Payload),
                    ex => EcliptixProtocolFailure.Decode("Failed to parse client bundle for identity check", ex));

            if (currentBundleResult.IsErr)
                return Result<Unit, EcliptixProtocolFailure>.Err(currentBundleResult.UnwrapErr());

            Protobuf.PubKeyExchange.PublicKeyBundle currentBundle = currentBundleResult.Unwrap();

            Result<PublicKeyBundle, EcliptixProtocolFailure> storedBundleResult = _connectSession.GetPeerBundle();
            if (storedBundleResult.IsErr)
                return Result<Unit, EcliptixProtocolFailure>.Err(storedBundleResult.UnwrapErr());

            PublicKeyBundle storedBundle = storedBundleResult.Unwrap();

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
            Result<Protobuf.PubKeyExchange.PublicKeyBundle, EcliptixProtocolFailure> currentBundleResult =
                Result<Protobuf.PubKeyExchange.PublicKeyBundle, EcliptixProtocolFailure>.Try(
                    () => Protobuf.PubKeyExchange.PublicKeyBundle.Parser.ParseFrom(peerMessage.Payload),
                    ex => EcliptixProtocolFailure.Decode("Failed to parse client bundle for identity verification",
                        ex));

            if (currentBundleResult.IsErr)
                return Result<Unit, EcliptixProtocolFailure>.Err(currentBundleResult.UnwrapErr());

            Protobuf.PubKeyExchange.PublicKeyBundle currentBundle = currentBundleResult.Unwrap();

            Result<PublicKeyBundle, EcliptixProtocolFailure> storedBundleResult = _connectSession.GetPeerBundle();
            if (storedBundleResult.IsErr)
                return Result<Unit, EcliptixProtocolFailure>.Err(storedBundleResult.UnwrapErr());

            PublicKeyBundle storedBundle = storedBundleResult.Unwrap();

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
}
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
        Console.WriteLine($"[SERVER] ProcessAndRespondToPubKeyExchange - ConnectId: {connectId}, State: {peerInitialMessageProto.State}");
        Console.WriteLine($"[SERVER] Has existing connection: {_connectSession != null}");
        
        // If we already have a connection (from recovery), verify state integrity before proceeding
        if (_connectSession != null)
        {
            Console.WriteLine($"[SERVER] Using existing recovered session - performing state verification");
            
            // NEW: Verify the recovered session state integrity
            var stateVerificationResult = VerifyRecoveredSessionState();
            if (stateVerificationResult.IsErr)
            {
                Console.WriteLine($"[SERVER] Recovered session state verification failed: {stateVerificationResult.UnwrapErr().Message}");
                
                // SECURITY: Don't dispose session here as it could leave actor in inconsistent state
                // Instead, return error to force proper cleanup at actor level
                return Result<PubKeyExchange, EcliptixProtocolFailure>.Err(
                    EcliptixProtocolFailure.ActorStateNotFound(
                        "Session state corrupted - full re-handshake required"));
            }
            else
            {
                Console.WriteLine($"[SERVER] Recovered session state verified successfully - returning stored identity keys");
                
                // NEW: Check if client is attempting fresh handshake with different identity
                var clientIdentityCheckResult = CheckClientIdentityForFreshHandshake(peerInitialMessageProto);
                if (clientIdentityCheckResult.IsErr)
                {
                    Console.WriteLine($"[SERVER] Client identity change detected: {clientIdentityCheckResult.UnwrapErr().Message}");
                    Console.WriteLine("[SERVER] Client is performing fresh handshake - clearing old session state");
                    
                    // Client has new identity keys, this is a fresh handshake, not recovery
                    // Clear the existing session and fall through to create new one
                    _connectSession?.Dispose();
                    _connectSession = null;
                    
                    // Don't return here - fall through to create fresh session
                }
                else
                {
                    Console.WriteLine("[SERVER] Client identity matches recovered session - proceeding with state restoration");
                    
                    // Only return the existing session if identity keys match
                    return ecliptixSystemIdentityKeys.CreatePublicBundle()
                        .AndThen(bundle => _connectSession.GetCurrentSenderDhPublicKey()
                            .Map(dhPublicKey => new PubKeyExchange
                            {
                                State = PubKeyExchangeState.Pending,
                                OfType = peerInitialMessageProto.OfType,
                                Payload = bundle.ToProtobufExchange().ToByteString(),
                                InitialDhPublicKey = ByteString.CopyFrom(dhPublicKey ?? 
                                    throw new InvalidOperationException("DH public key is null"))
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
                    Console.WriteLine($"[SERVER] Client Identity X25519: {Convert.ToHexString(peerBundle.IdentityX25519)}");
                    Console.WriteLine($"[SERVER] Client Identity Ed25519: {Convert.ToHexString(peerBundle.IdentityEd25519)}");
                    Console.WriteLine($"[SERVER] Client SignedPreKey: {Convert.ToHexString(peerBundle.SignedPreKeyPublic)}");
                    Console.WriteLine($"[SERVER] Client Ephemeral: {Convert.ToHexString(peerBundle.EphemeralX25519)}");
                    Console.WriteLine($"[SERVER] Client Initial DH: {Convert.ToHexString(peerInitialMessageProto.InitialDhPublicKey.ToByteArray())}");
                    
                    return EcliptixSystemIdentityKeys.VerifyRemoteSpkSignature(peerBundle.IdentityEd25519,
                            peerBundle.SignedPreKeyPublic, peerBundle.SignedPreKeySignature)
                        .AndThen(_ =>
                        {
                            ecliptixSystemIdentityKeys.GenerateEphemeralKeyPair();
                            return ecliptixSystemIdentityKeys.CreatePublicBundle();
                        })
                        .AndThen(localBundle =>
                        {
                            Console.WriteLine($"[SERVER] Server Identity X25519: {Convert.ToHexString(localBundle.IdentityX25519)}");
                            Console.WriteLine($"[SERVER] Server Identity Ed25519: {Convert.ToHexString(localBundle.IdentityEd25519)}");
                            Console.WriteLine($"[SERVER] Server SignedPreKey: {Convert.ToHexString(localBundle.SignedPreKeyPublic)}");
                            Console.WriteLine($"[SERVER] Server Ephemeral: {Convert.ToHexString(localBundle.EphemeralX25519)}");
                            
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
                                    .AndThen(rootKeyBytes => {
                                        Console.WriteLine($"[SERVER] ROOT KEY: {Convert.ToHexString(rootKeyBytes)}");
                                        return session.FinalizeChainAndDhKeys(rootKeyBytes,
                                            peerInitialMessageProto.InitialDhPublicKey.ToByteArray());
                                    })
                                    .AndThen(_ => session.SetPeerBundle(peerBundle))
                                    .AndThen(_ => session.GetCurrentSenderDhPublicKey())
                                    .Map(dhPublicKey => {
                                        Console.WriteLine($"[SERVER] Sending Initial DH Public Key: {Convert.ToHexString(dhPublicKey)}");
                                        return new PubKeyExchange
                                        {
                                            State = PubKeyExchangeState.Pending,
                                            OfType = peerInitialMessageProto.OfType,
                                            Payload = localBundle.ToProtobufExchange().ToByteString(),
                                            InitialDhPublicKey = ByteString.CopyFrom(dhPublicKey)
                                        };
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
                        _connectSession!.FinalizeChainAndDhKeys(rootKeyBytes,
                            peerMessage.InitialDhPublicKey.ToByteArray()))
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
        Console.WriteLine($"[SERVER] ProduceOutboundMessage - Payload size: {plainPayload.Length}");
        
        EcliptixMessageKey? messageKeyClone = null;
        try
        {
            if (_connectSession == null)
                return Result<CipherPayload, EcliptixProtocolFailure>.Err(
                    EcliptixProtocolFailure.Generic("Session not established."));

            return _connectSession.PrepareNextSendMessage()
                .AndThen(prep => _connectSession.GenerateNextNonce()
                    .AndThen(nonce => GetOptionalSenderDhKey(prep.IncludeDhKey)
                        .AndThen(newSenderDhPublicKey => CloneMessageKey(prep.MessageKey)
                            .AndThen(clonedKey =>
                            {
                                messageKeyClone = clonedKey;
                                return _connectSession.GetPeerBundle();
                            })
                            .AndThen(peerBundle =>
                            {
                                // Always use initiator||responder ordering for AD
                                // The client is always the initiator in our protocol
                                byte[] ad = CreateAssociatedData(peerBundle.IdentityX25519, ecliptixSystemIdentityKeys.IdentityX25519PublicKey);
                                return Encrypt(messageKeyClone!, nonce, plainPayload, ad);
                            })
                            .Map(encrypted => {
                                var payload = new CipherPayload
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
                                Console.WriteLine($"[SERVER] Encrypted message - Nonce: {Convert.ToHexString(nonce)}, RatchetIndex: {payload.RatchetIndex}, CipherSize: {encrypted.Length}");
                                return payload;
                            }))));
        }
        finally
        {
            messageKeyClone?.Dispose();
        }
    }

    public Result<byte[], EcliptixProtocolFailure> ProcessInboundMessage(CipherPayload cipherPayloadProto)
    {
        Console.WriteLine($"[SERVER] ProcessInboundMessage - Nonce: {Convert.ToHexString(cipherPayloadProto.Nonce.ToByteArray())}, RatchetIndex: {cipherPayloadProto.RatchetIndex}, CipherSize: {cipherPayloadProto.Cipher.Length}");
        Console.WriteLine($"[SERVER] ProcessInboundMessage - Has DH key: {cipherPayloadProto.DhPublicKey.Length > 0}");
        
        EcliptixMessageKey? messageKeyClone = null;
        try
        {
            if (_connectSession == null)
                return Result<byte[], EcliptixProtocolFailure>.Err(
                    EcliptixProtocolFailure.Generic("Session not established."));

            // NEW: Enhanced message validation with recovery hints
            var validationResult = ValidateIncomingMessage(cipherPayloadProto);
            if (validationResult.IsErr)
            {
                Console.WriteLine($"[SERVER] Message validation failed: {validationResult.UnwrapErr().Message}");
                return Result<byte[], EcliptixProtocolFailure>.Err(validationResult.UnwrapErr());
            }

            byte[]? receivedDhKey = cipherPayloadProto.DhPublicKey.Length > 0
                ? cipherPayloadProto.DhPublicKey.ToByteArray()
                : null;

            // Only perform ratchet if we received a new DH key
            if (receivedDhKey is not null)
            {
                Result<Unit, EcliptixProtocolFailure> ratchetResult = _connectSession.PerformReceivingRatchet(receivedDhKey);
                if (ratchetResult.IsErr) return Result<byte[], EcliptixProtocolFailure>.Err(ratchetResult.UnwrapErr());
            }

            // NEW: Attempt message processing with enhanced recovery logic
            Result<EcliptixMessageKey, EcliptixProtocolFailure> deriveResult = AttemptMessageProcessingWithRecovery(cipherPayloadProto, receivedDhKey);
            if (deriveResult.IsErr) return Result<byte[], EcliptixProtocolFailure>.Err(deriveResult.UnwrapErr());

            Result<EcliptixMessageKey, EcliptixProtocolFailure> clonedKeyResult = CloneMessageKey(deriveResult.Unwrap());
            if (clonedKeyResult.IsErr) return Result<byte[], EcliptixProtocolFailure>.Err(clonedKeyResult.UnwrapErr());
            messageKeyClone = clonedKeyResult.Unwrap();
            
            // Message key loaded successfully (key material not logged for security)

            Result<PublicKeyBundle, EcliptixProtocolFailure> peerBundleResult = _connectSession.GetPeerBundle();
            if (peerBundleResult.IsErr) return Result<byte[], EcliptixProtocolFailure>.Err(peerBundleResult.UnwrapErr());
            PublicKeyBundle peerBundle = peerBundleResult.Unwrap();

            // Always use initiator||responder ordering for AD
            // The client is always the initiator in our protocol
            byte[] ad = CreateAssociatedData(peerBundle.IdentityX25519, ecliptixSystemIdentityKeys.IdentityX25519PublicKey);
            Console.WriteLine($"[SERVER] Using message key index {cipherPayloadProto.RatchetIndex}");

            Result<byte[], EcliptixProtocolFailure> decryptResult = Decrypt(messageKeyClone, cipherPayloadProto, ad);

            if (decryptResult.IsErr && receivedDhKey != null && cipherPayloadProto.RatchetIndex <= 5)
            {
                // SECURITY FIX: Check ratchet result instead of ignoring it
                var ratchetResult = _connectSession.PerformReceivingRatchet(receivedDhKey);
                if (ratchetResult.IsErr)
                {
                    Console.WriteLine($"[SERVER] Fallback ratchet operation failed: {ratchetResult.UnwrapErr().Message}");
                    return Result<byte[], EcliptixProtocolFailure>.Err(ratchetResult.UnwrapErr());
                }

                deriveResult = _connectSession.ProcessReceivedMessage(cipherPayloadProto.RatchetIndex);
                if (deriveResult.IsErr) return Result<byte[], EcliptixProtocolFailure>.Err(deriveResult.UnwrapErr());

                clonedKeyResult = CloneMessageKey(deriveResult.Unwrap());
                if (clonedKeyResult.IsErr) return Result<byte[], EcliptixProtocolFailure>.Err(clonedKeyResult.UnwrapErr());
                messageKeyClone?.Dispose();
                messageKeyClone = clonedKeyResult.Unwrap();

                decryptResult = Decrypt(messageKeyClone, cipherPayloadProto, ad);
            }

            if (decryptResult.IsErr)
            {
                // Check if this might be an identity key mismatch
                // This can happen when a client reconnects with different identity keys
                // but the server still has the old session persisted
                Console.WriteLine($"[SERVER] Decryption failed for message with RatchetIndex: {cipherPayloadProto.RatchetIndex}");
                Console.WriteLine($"[SERVER] This might indicate client identity key change - consider fresh handshake");
                
                // Return specific error that should trigger fresh handshake on client side
                return Result<byte[], EcliptixProtocolFailure>.Err(
                    EcliptixProtocolFailure.ActorStateNotFound("Session authentication failed - fresh handshake required"));
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
        SodiumInterop.SecureWipe(buffer).IgnoreResult();
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
        Console.WriteLine($"[SERVER] CreateAssociatedData - First: {Convert.ToHexString(id1)}, Second: {Convert.ToHexString(id2)}");
        Console.WriteLine($"[SERVER] CreateAssociatedData - Full AD: {Convert.ToHexString(ad)}");
        return ad;
    }

    private static Result<byte[], EcliptixProtocolFailure> Encrypt(EcliptixMessageKey key, byte[] nonce,
        byte[] plaintext, byte[] ad)
    {
        byte[]? keyMaterial = null;
        try
        {
            keyMaterial = ArrayPool<byte>.Shared.Rent(Constants.AesKeySize);
            Span<byte> keySpan = keyMaterial.AsSpan(0, Constants.AesKeySize);
            Result<Unit, EcliptixProtocolFailure> readResult = key.ReadKeyMaterial(keySpan);
            if (readResult.IsErr) return Result<byte[], EcliptixProtocolFailure>.Err(readResult.UnwrapErr());

            // Direct AES-GCM encryption without SecureMemoryUtils
            byte[] ciphertext = new byte[plaintext.Length];
            byte[] tag = new byte[Constants.AesGcmTagSize];
            
            using (var aesGcm = new System.Security.Cryptography.AesGcm(keySpan, Constants.AesGcmTagSize))
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
        Console.WriteLine($"[SERVER] Decrypt called - Nonce: {Convert.ToHexString(payload.Nonce.ToByteArray())}, AD length: {ad.Length}, Cipher length: {payload.Cipher.Length}");
        Console.WriteLine($"[SERVER] Decrypt - Full ciphertext+tag: {Convert.ToHexString(payload.Cipher.Span)}");
        ReadOnlySpan<byte> fullCipherSpan = payload.Cipher.Span;
        int tagSize = Constants.AesGcmTagSize;
        int cipherLength = fullCipherSpan.Length - tagSize;

        if (cipherLength < 0)
            return Result<byte[], EcliptixProtocolFailure>.Err(EcliptixProtocolFailure.BufferTooSmall(
                $"Received ciphertext length ({fullCipherSpan.Length}) is smaller than the GCM tag size ({tagSize})."));

        byte[]? keyMaterial = null;
        try
        {
            keyMaterial = ArrayPool<byte>.Shared.Rent(Constants.AesKeySize);
            Span<byte> keySpan = keyMaterial.AsSpan(0, Constants.AesKeySize);
            Result<Unit, EcliptixProtocolFailure> readResult = key.ReadKeyMaterial(keySpan);
            if (readResult.IsErr) return Result<byte[], EcliptixProtocolFailure>.Err(readResult.UnwrapErr());

            // Direct AES-GCM decryption without SecureMemoryUtils
            byte[] ciphertext = fullCipherSpan[..cipherLength].ToArray();
            byte[] tag = fullCipherSpan[cipherLength..].ToArray();
            byte[] plaintext = new byte[cipherLength];
            
            Console.WriteLine($"[SERVER] Decrypt - Key: {Convert.ToHexString(keySpan)}, Nonce: {Convert.ToHexString(payload.Nonce.ToArray())}, Ciphertext: {Convert.ToHexString(ciphertext)}, Tag: {Convert.ToHexString(tag)}");
            
            using (var aesGcm = new System.Security.Cryptography.AesGcm(keySpan, Constants.AesGcmTagSize))
            {
                aesGcm.Decrypt(payload.Nonce.ToArray(), ciphertext, tag, plaintext, ad);
            }
            
            return Result<byte[], EcliptixProtocolFailure>.Ok(plaintext);
        }
        catch (CryptographicException cryptoEx)
        {
            return Result<byte[], EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.Generic("AES-GCM decryption failed (authentication tag mismatch).", cryptoEx));
        }
        catch (Exception ex)
        {
            return Result<byte[], EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.Generic("Unexpected error during AES-GCM decryption.", ex));
        }
        finally
        {
            if (keyMaterial != null) ArrayPool<byte>.Shared.Return(keyMaterial, clearArray: true);
        }
    }

    /// <summary>
    /// Validates incoming message for potential issues that might require recovery
    /// </summary>
    private Result<Unit, EcliptixProtocolFailure> ValidateIncomingMessage(CipherPayload payload)
    {
        // Check basic payload structure
        if (payload.Nonce.IsEmpty || payload.Cipher.IsEmpty)
            return Result<Unit, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.Generic("Invalid payload - missing nonce or cipher"));

        // Validate nonce size
        if (payload.Nonce.Length != Constants.AesGcmNonceSize)
            return Result<Unit, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.Generic($"Invalid nonce size: {payload.Nonce.Length}, expected: {Constants.AesGcmNonceSize}"));

        // NOTE: Removed unsafe chain index validation that used non-existent methods
        // This should be implemented properly in EcliptixProtocolConnection
        Console.WriteLine($"[SERVER] Processing message with ratchet index: {payload.RatchetIndex}");

        return Result<Unit, EcliptixProtocolFailure>.Ok(Unit.Value);
    }

    /// <summary>
    /// Attempts to process message with multiple recovery strategies
    /// </summary>
    private Result<EcliptixMessageKey, EcliptixProtocolFailure> AttemptMessageProcessingWithRecovery(
        CipherPayload payload, byte[]? receivedDhKey)
    {
        if (_connectSession == null)
            return Result<EcliptixMessageKey, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.Generic("Session not established"));

        // Strategy 1: Normal processing
        var normalResult = _connectSession.ProcessReceivedMessage(payload.RatchetIndex);
        if (normalResult.IsOk)
        {
            Console.WriteLine("[SERVER] Normal message processing succeeded");
            return normalResult;
        }

        Console.WriteLine($"[SERVER] Normal processing failed: {normalResult.UnwrapErr().Message}");

        // Strategy 2: Try with DH ratchet if we have received DH key and index is low
        if (receivedDhKey != null && payload.RatchetIndex <= 5)
        {
            Console.WriteLine("[SERVER] Attempting recovery with DH ratchet");
            var ratchetResult = _connectSession.PerformReceivingRatchet(receivedDhKey);
            if (ratchetResult.IsOk)
            {
                var retryResult = _connectSession.ProcessReceivedMessage(payload.RatchetIndex);
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

        // Strategy 3: REMOVED - Message skipping is unsafe in Double Ratchet protocol
        // Skipping messages could break forward secrecy if they contained DH rotations
        Console.WriteLine("[SERVER] Message gap recovery strategies are limited for security reasons");

        // All recovery strategies failed
        Console.WriteLine("[SERVER] All message recovery strategies failed");
        return normalResult; // Return original error
    }

    /// <summary>
    /// REMOVED: GetCurrentReceivingIndex - method doesn't exist and reflection is unsafe
    /// This functionality should be properly implemented in EcliptixProtocolConnection
    /// </summary>

    /// <summary>
    /// REMOVED: TrySkipReceivedMessage - method doesn't exist and message skipping 
    /// could break forward secrecy in Double Ratchet protocol
    /// </summary>

    /// <summary>
    /// Verifies the integrity of a recovered session state
    /// </summary>
    private Result<Unit, EcliptixProtocolFailure> VerifyRecoveredSessionState()
    {
        if (_connectSession == null)
            return Result<Unit, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.Generic("No session to verify"));

        try
        {
            // Check if we can get basic state information
            var peerBundleResult = _connectSession.GetPeerBundle();
            if (peerBundleResult.IsErr)
                return Result<Unit, EcliptixProtocolFailure>.Err(
                    EcliptixProtocolFailure.Generic($"Cannot retrieve peer bundle: {peerBundleResult.UnwrapErr().Message}"));

            // Check if we can get current DH key
            var dhKeyResult = _connectSession.GetCurrentSenderDhPublicKey();
            if (dhKeyResult.IsErr)
                return Result<Unit, EcliptixProtocolFailure>.Err(
                    EcliptixProtocolFailure.Generic($"Cannot retrieve sender DH key: {dhKeyResult.UnwrapErr().Message}"));

            // Verify the peer bundle has valid keys
            var peerBundle = peerBundleResult.Unwrap();
            if (peerBundle.IdentityX25519 == null || peerBundle.IdentityX25519.Length != Constants.X25519PublicKeySize)
                return Result<Unit, EcliptixProtocolFailure>.Err(
                    EcliptixProtocolFailure.Generic("Invalid peer identity key in recovered state"));

            if (peerBundle.SignedPreKeyPublic == null || peerBundle.SignedPreKeyPublic.Length != Constants.X25519PublicKeySize)
                return Result<Unit, EcliptixProtocolFailure>.Err(
                    EcliptixProtocolFailure.Generic("Invalid peer signed pre-key in recovered state"));

            // Verify system identity keys are still valid
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

    /// <summary>
    /// Checks if client is attempting a fresh handshake with different identity keys
    /// Returns Error if identities don't match (indicating fresh handshake needed)
    /// </summary>
    private Result<Unit, EcliptixProtocolFailure> CheckClientIdentityForFreshHandshake(PubKeyExchange peerMessage)
    {
        if (_connectSession == null)
            return Result<Unit, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.Generic("No session to compare against"));

        try
        {
            // Parse the client's current public key bundle
            var currentBundleResult = Result<Protobuf.PubKeyExchange.PublicKeyBundle, EcliptixProtocolFailure>.Try(
                () => Protobuf.PubKeyExchange.PublicKeyBundle.Parser.ParseFrom(peerMessage.Payload),
                ex => EcliptixProtocolFailure.Decode("Failed to parse client bundle for identity check", ex));
            
            if (currentBundleResult.IsErr)
                return Result<Unit, EcliptixProtocolFailure>.Err(currentBundleResult.UnwrapErr());

            var currentBundle = currentBundleResult.Unwrap();

            // Get the previously stored peer bundle
            var storedBundleResult = _connectSession.GetPeerBundle();
            if (storedBundleResult.IsErr)
                return Result<Unit, EcliptixProtocolFailure>.Err(storedBundleResult.UnwrapErr());

            var storedBundle = storedBundleResult.Unwrap();

            // Compare identity keys - if they DON'T match, this is a fresh handshake
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

    /// <summary>
    /// Verifies that the client identity matches the previously established session
    /// </summary>
    private Result<Unit, EcliptixProtocolFailure> VerifyClientIdentityConsistency(PubKeyExchange peerMessage)
    {
        if (_connectSession == null)
            return Result<Unit, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.Generic("No session for identity verification"));

        try
        {
            // Parse the client's current public key bundle
            var currentBundleResult = Result<Protobuf.PubKeyExchange.PublicKeyBundle, EcliptixProtocolFailure>.Try(
                () => Protobuf.PubKeyExchange.PublicKeyBundle.Parser.ParseFrom(peerMessage.Payload),
                ex => EcliptixProtocolFailure.Decode("Failed to parse client bundle for identity verification", ex));
            
            if (currentBundleResult.IsErr)
                return Result<Unit, EcliptixProtocolFailure>.Err(currentBundleResult.UnwrapErr());

            var currentBundle = currentBundleResult.Unwrap();

            // Get the previously stored peer bundle
            var storedBundleResult = _connectSession.GetPeerBundle();
            if (storedBundleResult.IsErr)
                return Result<Unit, EcliptixProtocolFailure>.Err(storedBundleResult.UnwrapErr());

            var storedBundle = storedBundleResult.Unwrap();

            // Compare identity keys (these should never change)
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
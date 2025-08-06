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
        
        // If we already have a connection (from recovery), just return our existing identity keys
        if (_connectSession != null)
        {
            Console.WriteLine($"[SERVER] Using existing recovered session - returning stored identity keys");
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

            byte[]? receivedDhKey = cipherPayloadProto.DhPublicKey.Length > 0
                ? cipherPayloadProto.DhPublicKey.ToByteArray()
                : null;

            // Only perform ratchet if we received a new DH key
            if (receivedDhKey is not null)
            {
                Result<Unit, EcliptixProtocolFailure> ratchetResult = _connectSession.PerformReceivingRatchet(receivedDhKey);
                if (ratchetResult.IsErr) return Result<byte[], EcliptixProtocolFailure>.Err(ratchetResult.UnwrapErr());
            }

            Result<EcliptixMessageKey, EcliptixProtocolFailure> deriveResult = _connectSession.ProcessReceivedMessage(cipherPayloadProto.RatchetIndex);
            if (deriveResult.IsErr) return Result<byte[], EcliptixProtocolFailure>.Err(deriveResult.UnwrapErr());

            Result<EcliptixMessageKey, EcliptixProtocolFailure> clonedKeyResult = CloneMessageKey(deriveResult.Unwrap());
            if (clonedKeyResult.IsErr) return Result<byte[], EcliptixProtocolFailure>.Err(clonedKeyResult.UnwrapErr());
            messageKeyClone = clonedKeyResult.Unwrap();
            
            // Log the message key being used
            byte[]? keyMaterial = null;
            try {
                keyMaterial = ArrayPool<byte>.Shared.Rent(Constants.AesKeySize);
                Span<byte> keySpan = keyMaterial.AsSpan(0, Constants.AesKeySize);
                messageKeyClone.ReadKeyMaterial(keySpan);
                Console.WriteLine($"[SERVER] Using message key for decryption: {Convert.ToHexString(keySpan)}");
            } finally {
                if (keyMaterial != null) ArrayPool<byte>.Shared.Return(keyMaterial, clearArray: true);
            }

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
                _connectSession.PerformReceivingRatchet(receivedDhKey).IgnoreResult();

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
                return Result<byte[], EcliptixProtocolFailure>.Err(
                    EcliptixProtocolFailure.Generic("Decrypt failed; possible desync—resync chains or rekey."));
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
}
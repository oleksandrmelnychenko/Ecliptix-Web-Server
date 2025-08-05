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
                    EcliptixSystemIdentityKeys.VerifyRemoteSpkSignature(peerBundle.IdentityEd25519,
                            peerBundle.SignedPreKeyPublic, peerBundle.SignedPreKeySignature)
                        .AndThen(_ =>
                        {
                            ecliptixSystemIdentityKeys.GenerateEphemeralKeyPair();
                            return ecliptixSystemIdentityKeys.CreatePublicBundle();
                        })
                        .AndThen(localBundle => EcliptixProtocolConnection.Create(connectId, false)
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
                            })));
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
                                byte[] ad = CreateAssociatedData(ecliptixSystemIdentityKeys.IdentityX25519PublicKey,
                                    peerBundle.IdentityX25519);
                                return Encrypt(messageKeyClone!, nonce, plainPayload, ad);
                            })
                            .Map(encrypted => new CipherPayload
                            {
                                RequestId = BitConverter.ToUInt32(RandomNumberGenerator.GetBytes(4), 0),
                                Nonce = ByteString.CopyFrom(nonce),
                                RatchetIndex = messageKeyClone!.Index,
                                Cipher = ByteString.CopyFrom(encrypted),
                                CreatedAt = Timestamp.FromDateTimeOffset(DateTimeOffset.UtcNow),
                                DhPublicKey = newSenderDhPublicKey.Length > 0
                                    ? ByteString.CopyFrom(newSenderDhPublicKey)
                                    : ByteString.Empty
                            }))));
        }
        finally
        {
            messageKeyClone?.Dispose();
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

            byte[]? receivedDhKey = cipherPayloadProto.DhPublicKey.Length > 0
                ? cipherPayloadProto.DhPublicKey.ToByteArray()
                : null;

            if (receivedDhKey is not null)
            {
                
            }

            Result<Unit, EcliptixProtocolFailure>
                ratchetResult = _connectSession.PerformReceivingRatchet(receivedDhKey);
            if (ratchetResult.IsErr) return Result<byte[], EcliptixProtocolFailure>.Err(ratchetResult.UnwrapErr());

            Result<EcliptixMessageKey, EcliptixProtocolFailure> deriveResult = _connectSession.ProcessReceivedMessage(cipherPayloadProto.RatchetIndex);
            if (deriveResult.IsErr) return Result<byte[], EcliptixProtocolFailure>.Err(ratchetResult.UnwrapErr());

            Result<EcliptixMessageKey, EcliptixProtocolFailure> clonedKeyResult = CloneMessageKey(deriveResult.Unwrap());
            if (clonedKeyResult.IsErr) return Result<byte[], EcliptixProtocolFailure>.Err(ratchetResult.UnwrapErr());
            messageKeyClone = clonedKeyResult.Unwrap();

            Result<PublicKeyBundle, EcliptixProtocolFailure> peerBundleResult = _connectSession.GetPeerBundle();
            if (peerBundleResult.IsErr) return Result<byte[], EcliptixProtocolFailure>.Err(ratchetResult.UnwrapErr());
            PublicKeyBundle peerBundle = peerBundleResult.Unwrap();

            byte[] ad = CreateAssociatedData(peerBundle.IdentityX25519,
                ecliptixSystemIdentityKeys.IdentityX25519PublicKey);

            Result<byte[], EcliptixProtocolFailure> decryptResult = Decrypt(messageKeyClone, cipherPayloadProto, ad);

            if (decryptResult.IsErr && receivedDhKey != null && cipherPayloadProto.RatchetIndex <= 5)
            {
                _connectSession.PerformReceivingRatchet(receivedDhKey).IgnoreResult();

                deriveResult = _connectSession.ProcessReceivedMessage(cipherPayloadProto.RatchetIndex);
                if (deriveResult.IsErr) return Result<byte[], EcliptixProtocolFailure>.Err(ratchetResult.UnwrapErr());

                clonedKeyResult = CloneMessageKey(deriveResult.Unwrap());
                if (clonedKeyResult.IsErr) return Result<byte[], EcliptixProtocolFailure>.Err(ratchetResult.UnwrapErr());
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

            (byte[] ciphertext, byte[] tag) = AesGcmService.EncryptAllocating(keySpan, nonce, plaintext, ad);
            byte[] ciphertextAndTag = new byte[ciphertext.Length + tag.Length];
            Buffer.BlockCopy(ciphertext, 0, ciphertextAndTag, 0, ciphertext.Length);
            Buffer.BlockCopy(tag, 0, ciphertextAndTag, ciphertext.Length, tag.Length);

            SodiumInterop.SecureWipe(ciphertext).IgnoreResult();
            SodiumInterop.SecureWipe(tag).IgnoreResult();
            return Result<byte[], EcliptixProtocolFailure>.Ok(ciphertextAndTag);
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
        ReadOnlySpan<byte> fullCipherSpan = payload.Cipher.Span;
        int tagSize = Constants.AesGcmTagSize;
        int cipherLength = fullCipherSpan.Length - tagSize;

        if (cipherLength < 0)
            return Result<byte[], EcliptixProtocolFailure>.Err(EcliptixProtocolFailure.BufferTooSmall(
                $"Received ciphertext length ({fullCipherSpan.Length}) is smaller than the GCM tag size ({tagSize})."));

        byte[]? keyMaterial = null;
        byte[]? cipherOnlyBytes = null;
        byte[]? tagBytes = null;
        try
        {
            keyMaterial = ArrayPool<byte>.Shared.Rent(Constants.AesKeySize);
            Span<byte> keySpan = keyMaterial.AsSpan(0, Constants.AesKeySize);
            Result<Unit, EcliptixProtocolFailure> readResult = key.ReadKeyMaterial(keySpan);
            if (readResult.IsErr) return Result<byte[], EcliptixProtocolFailure>.Err(readResult.UnwrapErr());

            cipherOnlyBytes = ArrayPool<byte>.Shared.Rent(cipherLength);
            Span<byte> cipherSpan = cipherOnlyBytes.AsSpan(0, cipherLength);
            fullCipherSpan[..cipherLength].CopyTo(cipherSpan);

            tagBytes = ArrayPool<byte>.Shared.Rent(tagSize);
            Span<byte> tagSpan = tagBytes.AsSpan(0, tagSize);
            fullCipherSpan[cipherLength..].CopyTo(tagSpan);

            byte[] result = AesGcmService.DecryptAllocating(keySpan, payload.Nonce.ToArray(), cipherSpan, tagSpan, ad);

            return Result<byte[], EcliptixProtocolFailure>.Ok(result);
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
            if (cipherOnlyBytes != null) ArrayPool<byte>.Shared.Return(cipherOnlyBytes, clearArray: true);
            if (tagBytes != null) ArrayPool<byte>.Shared.Return(tagBytes, clearArray: true);
        }
    }
}
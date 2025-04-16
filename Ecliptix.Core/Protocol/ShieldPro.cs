using Ecliptix.Core.Protocol.Utilities;
using Ecliptix.Protobuf.CipherPayload;
using Ecliptix.Protobuf.PubKeyExchange;
using Google.Protobuf;
using Google.Protobuf.WellKnownTypes;

namespace Ecliptix.Core.Protocol;

public sealed class ShieldPro(
    LocalKeyMaterial localKeyMaterial,
    HashAlgorithmType hashAlgorithmType,
    ShieldSessionManager? sessionManager = null)
    : IDataCenterPubKeyExchange, IOutboundMessageService, IInboundMessageService,
        IAsyncDisposable
{
    public static ReadOnlySpan<byte> X3dhInfo => "Ecliptix_X3DH"u8;
    private readonly LocalKeyMaterial _localKeyMaterial = localKeyMaterial ?? throw new ArgumentNullException(nameof(localKeyMaterial));
    private readonly ShieldSessionManager _sessionManager = sessionManager ?? ShieldSessionManager.Create();
    private bool _disposed;

    private static uint GenerateRequestId()
    {
        return (uint)Interlocked.Increment(ref _requestIdCounter);
    }

    private static long _requestIdCounter;
    private static Timestamp GetProtoTimestamp() => Timestamp.FromDateTimeOffset(DateTimeOffset.UtcNow);

    private async ValueTask<T> ExecuteUnderSessionLockAsync<T>(
        uint sessionId, PubKeyExchangeOfType exchangeType, Func<ShieldSession, ValueTask<T>> action,
        bool allowInitOrPending = false)
    {
        Result<ShieldSession, string> holderResult = await _sessionManager.FindSession(sessionId, exchangeType);
        if (!holderResult.IsOk)
            throw new ShieldChainStepException(holderResult.UnwrapErr());

        ShieldSession session = holderResult.Unwrap();
        bool acquiredLock = false;
        try
        {
            acquiredLock = await session.Lock.WaitAsync(TimeSpan.FromSeconds(5));
            if (!acquiredLock)
                throw new ShieldChainStepException($"Failed to acquire lock for session {sessionId}.");

            Result<PubKeyExchangeState, ShieldFailure> stateResult = session.GetState();
            if (!stateResult.IsOk)
                throw new ShieldChainStepException($"Failed to get session state: {stateResult.UnwrapErr()}");
            PubKeyExchangeState state = stateResult.Unwrap();
            if (state != PubKeyExchangeState.Complete && (!allowInitOrPending ||
                                                          (state != PubKeyExchangeState.Init &&
                                                           state != PubKeyExchangeState.Pending)))
                throw new ShieldChainStepException(
                    $"Session {sessionId} (Type: {exchangeType}) is not {(allowInitOrPending ? "Init, Pending, or Complete" : "Complete")}. State: {state}");

            var expirationResult = session.EnsureNotExpired();
            if (!expirationResult.IsOk)
                throw new ShieldChainStepException($"Session expired: {expirationResult.UnwrapErr()}");

            return await action(session);
        }
        finally
        {
            if (acquiredLock)
            {
                    session.Lock.Release();
            }
        }
    }

    public async Task<(uint SessionId, PubKeyExchange InitialMessage)> BeginDataCenterPubKeyExchangeAsync(
        PubKeyExchangeOfType exchangeType)
    {
        if (_disposed)
        {
            throw new ObjectDisposedException(nameof(ShieldPro));
        }

        uint sessionId = GenerateRequestId();
        _localKeyMaterial.GenerateEphemeralKeyPair();

        Result<LocalPublicKeyBundle, ShieldFailure> localBundleResult = _localKeyMaterial.CreatePublicBundle();
        if (!localBundleResult.IsOk)
            throw new ShieldChainStepException(
                $"Failed to create local public bundle: {localBundleResult.UnwrapErr()}");
        LocalPublicKeyBundle localBundle = localBundleResult.Unwrap();

        PublicKeyBundle protoBundle = localBundle.ToProtobufExchange()
                                      ?? throw new ShieldChainStepException("Failed to convert local public bundle to protobuf.");

        Result<ShieldSession, ShieldFailure> sessionResult = ShieldSession.Create(sessionId, localBundle, true,hashAlgorithmType);
        if (!sessionResult.IsOk)
            throw new ShieldChainStepException($"Failed to create session: {sessionResult.UnwrapErr()}");
        var session = sessionResult.Unwrap();

        Result<Unit, string> insertResult = await _sessionManager.InsertSession(sessionId, exchangeType, session);
        if (!insertResult.IsOk)
            throw new ShieldChainStepException($"Failed to insert session: {insertResult.UnwrapErr()}");

        Result<byte[]?, ShieldFailure> dhPublicKeyResult = session.GetCurrentSenderDhPublicKey();
        if (!dhPublicKeyResult.IsOk)
            throw new ShieldChainStepException($"Sender DH key not initialized: {dhPublicKeyResult.UnwrapErr()}");
        byte[]? dhPublicKey = dhPublicKeyResult.Unwrap();

        PubKeyExchange pubKeyExchange = new()
        {
            RequestId = GenerateRequestId(),
            State = PubKeyExchangeState.Init,
            OfType = exchangeType,
            Payload = protoBundle.ToByteString(),
            CreatedAt = GetProtoTimestamp(),
            InitialDhPublicKey = ByteString.CopyFrom(dhPublicKey)
        };

        return (sessionId, pubKeyExchange);
    }

    public async Task<(uint SessionId, PubKeyExchange ResponseMessage)> ProcessAndRespondToPubKeyExchangeAsync(
        PubKeyExchange peerInitialMessageProto)
    {
        if (_disposed)
        {
            throw new ObjectDisposedException(nameof(ShieldPro));
        }

        if (peerInitialMessageProto == null)
        {
            throw new ArgumentNullException(nameof(peerInitialMessageProto));
        }

        if (peerInitialMessageProto.State != PubKeyExchangeState.Init)
        {
            throw new ArgumentException("Expected peer message state to be Init.", nameof(peerInitialMessageProto));
        }

        PubKeyExchangeOfType exchangeType = peerInitialMessageProto.OfType;
        uint sessionId = GenerateRequestId();

        SodiumSecureMemoryHandle? rootKeyHandle = null;
        try
        {
            _localKeyMaterial.GenerateEphemeralKeyPair();

            Result<LocalPublicKeyBundle, ShieldFailure> localBundleResult = _localKeyMaterial.CreatePublicBundle();
            if (!localBundleResult.IsOk)
                throw new ShieldChainStepException(
                    $"Failed to create local public bundle: {localBundleResult.UnwrapErr()}");
            LocalPublicKeyBundle localBundle = localBundleResult.Unwrap();

            PublicKeyBundle protoBundle = localBundle.ToProtobufExchange()
                                          ?? throw new ShieldChainStepException(
                                              "Failed to convert local public bundle to protobuf.");

            Result<ShieldSession, ShieldFailure> sessionResult = ShieldSession.Create(sessionId, localBundle, false,hashAlgorithmType);
            if (!sessionResult.IsOk)
                throw new ShieldChainStepException($"Failed to create session: {sessionResult.UnwrapErr()}");
            ShieldSession session = sessionResult.Unwrap();

            Result<Unit, string> insertResult = await _sessionManager.InsertSession(sessionId, exchangeType, session);
            if (!insertResult.IsOk)
                throw new ShieldChainStepException($"Failed to insert session: {insertResult.UnwrapErr()}");

            PublicKeyBundle peerBundleProto =
                Helpers.ParseFromBytes<PublicKeyBundle>(peerInitialMessageProto.Payload.ToByteArray());
            Result<LocalPublicKeyBundle, ShieldFailure> peerBundleResult = LocalPublicKeyBundle.FromProtobufExchange(peerBundleProto);
            if (!peerBundleResult.IsOk)
                throw new ShieldChainStepException($"Failed to convert peer bundle: {peerBundleResult.UnwrapErr()}");
            LocalPublicKeyBundle peerBundle = peerBundleResult.Unwrap();

            Result<bool, ShieldFailure> spkValidResult = LocalKeyMaterial.VerifyRemoteSpkSignature(
                peerBundle.IdentityEd25519,
                peerBundle.SignedPreKeyPublic,
                peerBundle.SignedPreKeySignature);
            if (!spkValidResult.IsOk || !spkValidResult.Unwrap())
            {
                throw new ShieldChainStepException(
                    $"SPK signature validation failed: {(spkValidResult.IsOk ? "Invalid signature" : spkValidResult.UnwrapErr())}");
            }

            Result<SodiumSecureMemoryHandle, ShieldFailure> deriveResult = _localKeyMaterial.CalculateSharedSecretAsRecipient(
                peerBundle.IdentityX25519,
                peerBundle.EphemeralX25519,
                peerBundle.OneTimePreKeys?.FirstOrDefault()?.PreKeyId,
                X3dhInfo);
            if (!deriveResult.IsOk)
                throw new ShieldChainStepException($"Shared secret derivation failed: {deriveResult.UnwrapErr()}");
            rootKeyHandle = deriveResult.Unwrap();

            byte[] rootKeyBytes = new byte[Constants.X25519KeySize];
            rootKeyHandle.Read(rootKeyBytes.AsSpan());

            session.SetPeerBundle(peerBundle);
            session.SetConnectionState(PubKeyExchangeState.Pending);

            byte[]? peerDhKey = peerInitialMessageProto.InitialDhPublicKey.ToByteArray();

            Result<Unit, ShieldFailure> finalizeResult = session.FinalizeChainAndDhKeys(rootKeyBytes, peerDhKey);
            if (!finalizeResult.IsOk)
                throw new ShieldChainStepException($"Failed to finalize chain keys: {finalizeResult.UnwrapErr()}");

            var stateResult = session.SetConnectionState(PubKeyExchangeState.Complete);
            if (!stateResult.IsOk)
                throw new ShieldChainStepException($"Failed to set Complete state: {stateResult.UnwrapErr()}");

            SodiumInterop.SecureWipe(rootKeyBytes);

            Result<byte[]?, ShieldFailure> dhPublicKeyResult = session.GetCurrentSenderDhPublicKey();
            if (!dhPublicKeyResult.IsOk)
                throw new ShieldChainStepException($"Failed to get sender DH key: {dhPublicKeyResult.UnwrapErr()}");
            byte[]? dhPublicKey = dhPublicKeyResult.Unwrap();

            var response = new PubKeyExchange
            {
                RequestId = GenerateRequestId(),
                State = PubKeyExchangeState.Pending,
                OfType = exchangeType,
                Payload = protoBundle.ToByteString(),
                CreatedAt = GetProtoTimestamp(),
                InitialDhPublicKey = ByteString.CopyFrom(dhPublicKey)
            };

            return (sessionId, response);
        }
        catch
        {
            (await _sessionManager.RemoveSessionAsync(sessionId, exchangeType)).IgnoreResult();
            throw;
        }
        finally
        {
            rootKeyHandle?.Dispose();
        }
    }

    public async Task<(uint SessionId, SodiumSecureMemoryHandle RootKeyHandle)> CompleteDataCenterPubKeyExchangeAsync(
        uint sessionId, PubKeyExchangeOfType exchangeType, PubKeyExchange peerMessage)
    {
        if (_disposed)
            throw new ObjectDisposedException(nameof(ShieldPro));
        if (peerMessage == null)
            throw new ArgumentNullException(nameof(peerMessage));

        return await ExecuteUnderSessionLockAsync(sessionId, exchangeType, async session =>
        {
            var peerBundleProto = Helpers.ParseFromBytes<PublicKeyBundle>(peerMessage.Payload.ToByteArray());
            var peerBundleResult = LocalPublicKeyBundle.FromProtobufExchange(peerBundleProto);
            if (!peerBundleResult.IsOk)
                throw new ShieldChainStepException($"Failed to convert peer bundle: {peerBundleResult.UnwrapErr()}");
            var peerBundle = peerBundleResult.Unwrap();

            var spkValidResult = LocalKeyMaterial.VerifyRemoteSpkSignature(
                peerBundle.IdentityEd25519,
                peerBundle.SignedPreKeyPublic,
                peerBundle.SignedPreKeySignature);
            if (!spkValidResult.IsOk || !spkValidResult.Unwrap())
                throw new ShieldChainStepException(
                    $"SPK signature validation failed: {(spkValidResult.IsOk ? "Invalid signature" : spkValidResult.UnwrapErr())}");

            var deriveResult = _localKeyMaterial.X3dhDeriveSharedSecret(peerBundle, X3dhInfo);
            if (!deriveResult.IsOk)
                throw new ShieldChainStepException($"Shared secret derivation failed: {deriveResult.UnwrapErr()}");
            var rootKeyHandle = deriveResult.Unwrap();

            byte[] rootKeyBytes = new byte[Constants.X25519KeySize];
            rootKeyHandle.Read(rootKeyBytes.AsSpan());

            var finalizeResult =
                session.FinalizeChainAndDhKeys(rootKeyBytes, peerMessage.InitialDhPublicKey.ToByteArray());
            if (!finalizeResult.IsOk)
                throw new ShieldChainStepException($"Failed to finalize chain keys: {finalizeResult.UnwrapErr()}");

            session.SetPeerBundle(peerBundle);
            var stateResult = session.SetConnectionState(PubKeyExchangeState.Complete);
            if (!stateResult.IsOk)
                throw new ShieldChainStepException($"Failed to set Complete state: {stateResult.UnwrapErr()}");

            SodiumInterop.SecureWipe(rootKeyBytes);
            return (session.SessionId, rootKeyHandle);
        }, allowInitOrPending: true);
    }

    public async Task<CipherPayload> ProduceOutboundMessageAsync(
        uint sessionId, PubKeyExchangeOfType exchangeType, byte[] plainPayload)
    {
        if (_disposed)
            throw new ObjectDisposedException(nameof(ShieldPro));
        if (plainPayload == null)
            throw new ArgumentNullException(nameof(plainPayload));

        return await ExecuteUnderSessionLockAsync(sessionId, exchangeType, async session =>
        {
            byte[]? ciphertext = null;
            byte[]? tag = null;
            ShieldMessageKey? messageKeyClone = null;
            try
            {
                var prepResult = session.PrepareNextSendMessage();
                if (!prepResult.IsOk)
                    throw new ShieldChainStepException(
                        $"Failed to prepare outgoing message key: {prepResult.UnwrapErr()}");
                var (messageKey, includeDhKey) = prepResult.Unwrap();

                var nonceResult = session.GenerateNextNonce();
                if (!nonceResult.IsOk)
                    throw new ShieldChainStepException($"Failed to generate nonce: {nonceResult.UnwrapErr()}");
                var nonce = nonceResult.Unwrap();

                byte[]? newSenderDhPublicKey = includeDhKey
                    ? session.GetCurrentSenderDhPublicKey().Match(ok => ok,
                        err => throw new ShieldChainStepException($"Failed to get sender DH key: {err.Message}"))
                    : null;

                byte[] messageKeyBytes = new byte[Constants.AesKeySize];
                messageKey.ReadKeyMaterial(messageKeyBytes);

                var cloneResult = ShieldMessageKey.New(messageKey.Index, messageKeyBytes);
                if (!cloneResult.IsOk)
                    throw new ShieldChainStepException($"Failed to clone message key: {cloneResult.UnwrapErr()}");
                messageKeyClone = cloneResult.Unwrap();

                SodiumInterop.SecureWipe(messageKeyBytes);

                var peerBundleResult = session.GetPeerBundle();
                if (!peerBundleResult.IsOk)
                    throw new ShieldChainStepException($"Failed to get peer bundle: {peerBundleResult.UnwrapErr()}");
                var peerBundle = peerBundleResult.Unwrap();

                byte[] localId = _localKeyMaterial.IdentityX25519PublicKey;
                byte[] peerId = peerBundle.IdentityX25519;
                byte[] ad = new byte[localId.Length + peerId.Length];
                Buffer.BlockCopy(localId, 0, ad, 0, localId.Length);
                Buffer.BlockCopy(peerId, 0, ad, localId.Length, peerId.Length);

                byte[] clonedKeyMaterial = new byte[Constants.AesKeySize];
                try
                {
                    messageKeyClone.ReadKeyMaterial(clonedKeyMaterial);
                    (ciphertext, tag) = AesGcmService.EncryptAllocating(clonedKeyMaterial, nonce, plainPayload, ad);
                }
                finally
                {
                    SodiumInterop.SecureWipe(clonedKeyMaterial);
                }

                byte[] ciphertextAndTag = new byte[ciphertext.Length + tag.Length];
                Buffer.BlockCopy(ciphertext, 0, ciphertextAndTag, 0, ciphertext.Length);
                Buffer.BlockCopy(tag, 0, ciphertextAndTag, ciphertext.Length, tag.Length);

                var payload = new CipherPayload
                {
                    RequestId = GenerateRequestId(),
                    Nonce = ByteString.CopyFrom(nonce),
                    RatchetIndex = messageKeyClone.Index,
                    Cipher = ByteString.CopyFrom(ciphertextAndTag),
                    CreatedAt = GetProtoTimestamp(),
                    DhPublicKey = newSenderDhPublicKey != null
                        ? ByteString.CopyFrom(newSenderDhPublicKey)
                        : ByteString.Empty
                };

                return payload;
            }
            finally
            {
                messageKeyClone?.Dispose();
                SodiumInterop.SecureWipe(ciphertext);
                SodiumInterop.SecureWipe(tag);
            }
        });
    }

    public async Task<byte[]> ProcessInboundMessageAsync(
        uint sessionId, PubKeyExchangeOfType exchangeType, CipherPayload cipherPayloadProto)
    {
        if (_disposed)
            throw new ObjectDisposedException(nameof(ShieldPro));
        if (cipherPayloadProto == null)
            throw new ArgumentNullException(nameof(cipherPayloadProto));
        if (cipherPayloadProto.Cipher.Length < Constants.AesGcmTagSize)
            throw new ArgumentException("Ciphertext invalid.", nameof(cipherPayloadProto));
        if (cipherPayloadProto.Nonce.Length != Constants.AesGcmNonceSize)
            throw new ArgumentException("Nonce invalid.", nameof(cipherPayloadProto));

        return await ExecuteUnderSessionLockAsync(sessionId, exchangeType, async session =>
        {
            byte[]? messageKeyBytes = null;
            byte[]? plaintext = null;
            byte[]? ad = null;
            ShieldMessageKey? messageKeyClone = null;
            try
            {
                byte[]? receivedDhKey = cipherPayloadProto.DhPublicKey.Length > 0
                    ? cipherPayloadProto.DhPublicKey.ToByteArray()
                    : null;
                if (receivedDhKey != null)
                {
                    var currentPeerDhResult = session.GetCurrentPeerDhPublicKey();
                    if (currentPeerDhResult.IsOk)
                    {
                        byte[] currentPeerDh = currentPeerDhResult.Unwrap();
                        if (!receivedDhKey.SequenceEqual(currentPeerDh))
                        {
                            var ratchetResult = session.PerformReceivingRatchet(receivedDhKey);
                            if (!ratchetResult.IsOk)
                                throw new ShieldChainStepException(
                                    $"Failed to perform DH ratchet: {ratchetResult.UnwrapErr()}");
                        }
                    }
                }

                var messageKeyResult = session.ProcessReceivedMessage(cipherPayloadProto.RatchetIndex, receivedDhKey);
                if (!messageKeyResult.IsOk)
                    throw new ShieldChainStepException($"Failed to process message: {messageKeyResult.UnwrapErr()}");
                var originalMessageKey = messageKeyResult.Unwrap();

                messageKeyBytes = new byte[Constants.AesKeySize];
                originalMessageKey.ReadKeyMaterial(messageKeyBytes);

                var cloneResult = ShieldMessageKey.New(originalMessageKey.Index, messageKeyBytes);
                if (!cloneResult.IsOk)
                    throw new ShieldChainStepException(
                        $"Failed to clone message key for decryption: {cloneResult.UnwrapErr()}");
                messageKeyClone = cloneResult.Unwrap();

                var peerBundleResult = session.GetPeerBundle();
                if (!peerBundleResult.IsOk)
                    throw new ShieldChainStepException($"Failed to get peer bundle: {peerBundleResult.UnwrapErr()}");
                var peerBundle = peerBundleResult.Unwrap();

                byte[] senderId = peerBundle.IdentityX25519;
                byte[] receiverId = _localKeyMaterial.IdentityX25519PublicKey;
                ad = new byte[senderId.Length + receiverId.Length];
                Buffer.BlockCopy(senderId, 0, ad, 0, senderId.Length);
                Buffer.BlockCopy(receiverId, 0, ad, senderId.Length, receiverId.Length);

                byte[] clonedKeyMaterial = new byte[Constants.AesKeySize];
                try
                {
                    messageKeyClone.ReadKeyMaterial(clonedKeyMaterial);

                    ReadOnlySpan<byte> fullCipherSpan = cipherPayloadProto.Cipher.Span;
                    int cipherLength = fullCipherSpan.Length - Constants.AesGcmTagSize;
                    ReadOnlySpan<byte> cipherOnly = fullCipherSpan[..cipherLength];
                    ReadOnlySpan<byte> tagSpan = fullCipherSpan[cipherLength..];

                    plaintext = AesGcmService.DecryptAllocating(
                        clonedKeyMaterial,
                        cipherPayloadProto.Nonce.ToByteArray(),
                        cipherOnly.ToArray(),
                        tagSpan.ToArray(),
                        ad);

                    byte[] plaintextCopy = (byte[])plaintext.Clone();
                    return plaintextCopy;
                }
                finally
                {
                    SodiumInterop.SecureWipe(clonedKeyMaterial);
                    SodiumInterop.SecureWipe(plaintext);
                    SodiumInterop.SecureWipe(ad);
                }
            }
            finally
            {
                SodiumInterop.SecureWipe(messageKeyBytes);
                messageKeyClone?.Dispose();
            }
        });
    }

    public async ValueTask DisposeAsync()
    {
        if (_disposed) return;
        _disposed = true;
        await _sessionManager.DisposeAsync();
        GC.SuppressFinalize(this);
    }
}
using System;
using System.Buffers.Binary;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;
using Ecliptix.Core.Protocol.Utilities;
using Ecliptix.Protobuf.CipherPayload;
using Ecliptix.Protobuf.PubKeyExchange;
using Google.Protobuf;
using Google.Protobuf.WellKnownTypes;
using Sodium;

namespace Ecliptix.Core.Protocol;

public sealed class EcliptixProtocolSystem : IDataCenterPubKeyExchange, IOutboundMessageService, IInboundMessageService,
    IAsyncDisposable
{
    public static ReadOnlySpan<byte> X3dhInfo => "Ecliptix_X3DH"u8;
    private readonly EcliptixSystemIdentityKeys _ecliptixSystemIdentityKeys;
    private readonly ShieldSessionManager _sessionManager;
    private bool _disposed;

    private static uint GenerateRequestId()
    {
        return (uint)Interlocked.Increment(ref _requestIdCounter);
    }

    private static long _requestIdCounter = 0;
    private static Timestamp GetProtoTimestamp() => Timestamp.FromDateTimeOffset(DateTimeOffset.UtcNow);

    public EcliptixProtocolSystem(EcliptixSystemIdentityKeys ecliptixSystemIdentityKeys, ShieldSessionManager? sessionManager = null)
    {
        _ecliptixSystemIdentityKeys = ecliptixSystemIdentityKeys ?? throw new ArgumentNullException(nameof(ecliptixSystemIdentityKeys));
        _sessionManager = sessionManager ?? ShieldSessionManager.Create();
        Logger.WriteLine("[ShieldPro] Initialized ShieldPro instance.");
    }

    private async ValueTask<T> ExecuteUnderSessionLockAsync<T>(
        uint sessionId, PubKeyExchangeType exchangeType, Func<ShieldSession, ValueTask<T>> action,
        bool allowInitOrPending = false)
    {
        var holderResult = await _sessionManager.FindSession(sessionId, exchangeType);
        if (!holderResult.IsOk)
            throw new ShieldChainStepException(holderResult.UnwrapErr());

        var session = holderResult.Unwrap();
        Logger.WriteLine($"[ShieldPro] Acquiring lock for session {sessionId} ({exchangeType}).");
        bool acquiredLock = false;
        try
        {
            acquiredLock = await session.Lock.WaitAsync(TimeSpan.FromSeconds(5));
            if (!acquiredLock)
                throw new ShieldChainStepException($"Failed to acquire lock for session {sessionId}.");

            var stateResult = session.GetState();
            if (!stateResult.IsOk)
                throw new ShieldChainStepException($"Failed to get session state: {stateResult.UnwrapErr()}");
            var state = stateResult.Unwrap();
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
                try
                {
                    session.Lock.Release();
                    Logger.WriteLine($"[ShieldPro] Released lock for session {sessionId} ({exchangeType}).");
                }
                catch (ObjectDisposedException)
                {
                    Logger.WriteLine($"[ShieldPro] Lock for session {sessionId} was already disposed.");
                }
            }
        }
    }

    public async Task<(uint SessionId, PubKeyExchange InitialMessage)> BeginDataCenterPubKeyExchangeAsync(
        PubKeyExchangeType exchangeType)
    {
        if (_disposed)
            throw new ObjectDisposedException(nameof(EcliptixProtocolSystem));

        uint sessionId = GenerateRequestId();
        Logger.WriteLine($"[ShieldPro] Beginning exchange {exchangeType}, generated Session ID: {sessionId}");

        Logger.WriteLine("[ShieldPro] Generating ephemeral key pair.");
        _ecliptixSystemIdentityKeys.GenerateEphemeralKeyPair();

        var localBundleResult = _ecliptixSystemIdentityKeys.CreatePublicBundle();
        if (!localBundleResult.IsOk)
            throw new ShieldChainStepException(
                $"Failed to create local public bundle: {localBundleResult.UnwrapErr()}");
        var localBundle = localBundleResult.Unwrap();

        var protoBundle = localBundle.ToProtobufExchange()
                          ?? throw new ShieldChainStepException("Failed to convert local public bundle to protobuf.");

        var sessionResult = ShieldSession.Create(sessionId, localBundle, true);
        if (!sessionResult.IsOk)
            throw new ShieldChainStepException($"Failed to create session: {sessionResult.UnwrapErr()}");
        var session = sessionResult.Unwrap();

        var insertResult = await _sessionManager.InsertSession(sessionId, exchangeType, session);
        if (!insertResult.IsOk)
            throw new ShieldChainStepException($"Failed to insert session: {insertResult.UnwrapErr()}");

        var dhPublicKeyResult = session.GetCurrentSenderDhPublicKey();
        if (!dhPublicKeyResult.IsOk)
            throw new ShieldChainStepException($"Sender DH key not initialized: {dhPublicKeyResult.UnwrapErr()}");
        var dhPublicKey = dhPublicKeyResult.Unwrap();

        Logger.WriteLine($"[ShieldPro] Initial DH Public Key: {Convert.ToHexString(dhPublicKey)}");

        var pubKeyExchange = new PubKeyExchange
        {
            State = PubKeyExchangeState.Init,
            OfType = exchangeType,
            Payload = protoBundle.ToByteString(),
            InitialDhPublicKey = ByteString.CopyFrom(dhPublicKey)
        };

        return (sessionId, pubKeyExchange);
    }

    public async Task<(uint SessionId, PubKeyExchange ResponseMessage)> ProcessAndRespondToPubKeyExchangeAsync(
        PubKeyExchange peerInitialMessageProto)
    {
        if (_disposed)
            throw new ObjectDisposedException(nameof(EcliptixProtocolSystem));
        if (peerInitialMessageProto == null)
            throw new ArgumentNullException(nameof(peerInitialMessageProto));
        if (peerInitialMessageProto.State != PubKeyExchangeState.Init)
            throw new ArgumentException("Expected peer message state to be Init.", nameof(peerInitialMessageProto));

        PubKeyExchangeType exchangeType = peerInitialMessageProto.OfType;
        uint sessionId = GenerateRequestId();
        Logger.WriteLine($"[ShieldPro] Processing exchange request {exchangeType}, generated Session ID: {sessionId}");

        SodiumSecureMemoryHandle? rootKeyHandle = null;
        try
        {
            Logger.WriteLine("[ShieldPro] Generating ephemeral key for response.");
            _ecliptixSystemIdentityKeys.GenerateEphemeralKeyPair();

            var localBundleResult = _ecliptixSystemIdentityKeys.CreatePublicBundle();
            if (!localBundleResult.IsOk)
                throw new ShieldChainStepException(
                    $"Failed to create local public bundle: {localBundleResult.UnwrapErr()}");
            var localBundle = localBundleResult.Unwrap();

            var protoBundle = localBundle.ToProtobufExchange()
                              ?? throw new ShieldChainStepException(
                                  "Failed to convert local public bundle to protobuf.");

            var sessionResult = ShieldSession.Create(sessionId, localBundle, false);
            if (!sessionResult.IsOk)
                throw new ShieldChainStepException($"Failed to create session: {sessionResult.UnwrapErr()}");
            var session = sessionResult.Unwrap();

            var insertResult = await _sessionManager.InsertSession(sessionId, exchangeType, session);
            if (!insertResult.IsOk)
                throw new ShieldChainStepException($"Failed to insert session: {insertResult.UnwrapErr()}");

            var peerBundleProto =
                Helpers.ParseFromBytes<PublicKeyBundle>(peerInitialMessageProto.Payload.ToByteArray());
            var peerBundleResult = LocalPublicKeyBundle.FromProtobufExchange(peerBundleProto);
            if (!peerBundleResult.IsOk)
                throw new ShieldChainStepException($"Failed to convert peer bundle: {peerBundleResult.UnwrapErr()}");
            var peerBundle = peerBundleResult.Unwrap();

            Logger.WriteLine("[ShieldPro] Verifying remote SPK signature.");
            var spkValidResult = EcliptixSystemIdentityKeys.VerifyRemoteSpkSignature(
                peerBundle.IdentityEd25519,
                peerBundle.SignedPreKeyPublic,
                peerBundle.SignedPreKeySignature);
            if (!spkValidResult.IsOk || !spkValidResult.Unwrap())
                throw new ShieldChainStepException(
                    $"SPK signature validation failed: {(spkValidResult.IsOk ? "Invalid signature" : spkValidResult.UnwrapErr())}");

            Logger.WriteLine("[ShieldPro] Deriving shared secret as recipient.");
            var deriveResult = _ecliptixSystemIdentityKeys.CalculateSharedSecretAsRecipient(
                peerBundle.IdentityX25519,
                peerBundle.EphemeralX25519,
                peerBundle.OneTimePreKeys?.FirstOrDefault()?.PreKeyId,
                X3dhInfo);
            if (!deriveResult.IsOk)
                throw new ShieldChainStepException($"Shared secret derivation failed: {deriveResult.UnwrapErr()}");
            rootKeyHandle = deriveResult.Unwrap();

            byte[] rootKeyBytes = new byte[Constants.X25519KeySize];
            rootKeyHandle.Read(rootKeyBytes.AsSpan());
            Logger.WriteLine($"[ShieldPro] Root Key: {Convert.ToHexString(rootKeyBytes)}");

            session.SetPeerBundle(peerBundle);
            session.SetConnectionState(PubKeyExchangeState.Pending);

            var peerDhKey = peerInitialMessageProto.InitialDhPublicKey.ToByteArray();
            Logger.WriteLine($"[ShieldPro] Peer Initial DH Public Key: {Convert.ToHexString(peerDhKey)}");

            var finalizeResult = session.FinalizeChainAndDhKeys(rootKeyBytes, peerDhKey);
            if (!finalizeResult.IsOk)
                throw new ShieldChainStepException($"Failed to finalize chain keys: {finalizeResult.UnwrapErr()}");

            var stateResult = session.SetConnectionState(PubKeyExchangeState.Complete);
            if (!stateResult.IsOk)
                throw new ShieldChainStepException($"Failed to set Complete state: {stateResult.UnwrapErr()}");

            SodiumInterop.SecureWipe(rootKeyBytes);

            var dhPublicKeyResult = session.GetCurrentSenderDhPublicKey();
            if (!dhPublicKeyResult.IsOk)
                throw new ShieldChainStepException($"Failed to get sender DH key: {dhPublicKeyResult.UnwrapErr()}");
            var dhPublicKey = dhPublicKeyResult.Unwrap();

            Logger.WriteLine($"[ShieldPro] Sender DH Public Key: {Convert.ToHexString(dhPublicKey)}");
            var response = new PubKeyExchange
            {
                State = PubKeyExchangeState.Pending,
                OfType = exchangeType,
                Payload = protoBundle.ToByteString(),
                InitialDhPublicKey = ByteString.CopyFrom(dhPublicKey)
            };

            return (sessionId, response);
        }
        catch
        {
            Logger.WriteLine($"[ShieldPro] Error in ProcessAndRespondToPubKeyExchangeAsync for session {sessionId}.");
            (await _sessionManager.RemoveSessionAsync(sessionId, exchangeType)).IgnoreResult();
            throw;
        }
        finally
        {
            rootKeyHandle?.Dispose();
        }
    }

    public async Task<(uint SessionId, SodiumSecureMemoryHandle RootKeyHandle)> CompleteDataCenterPubKeyExchangeAsync(
        uint sessionId, PubKeyExchangeType exchangeType, PubKeyExchange peerMessage)
    {
        if (_disposed)
            throw new ObjectDisposedException(nameof(EcliptixProtocolSystem));
        if (peerMessage == null)
            throw new ArgumentNullException(nameof(peerMessage));

        Logger.WriteLine($"[ShieldPro] Completing exchange for session {sessionId} ({exchangeType}).");

        return await ExecuteUnderSessionLockAsync(sessionId, exchangeType, async session =>
        {
            var peerBundleProto = Helpers.ParseFromBytes<PublicKeyBundle>(peerMessage.Payload.ToByteArray());
            var peerBundleResult = LocalPublicKeyBundle.FromProtobufExchange(peerBundleProto);
            if (!peerBundleResult.IsOk)
                throw new ShieldChainStepException($"Failed to convert peer bundle: {peerBundleResult.UnwrapErr()}");
            var peerBundle = peerBundleResult.Unwrap();

            Logger.WriteLine("[ShieldPro] Verifying remote SPK signature for completion.");
            var spkValidResult = EcliptixSystemIdentityKeys.VerifyRemoteSpkSignature(
                peerBundle.IdentityEd25519,
                peerBundle.SignedPreKeyPublic,
                peerBundle.SignedPreKeySignature);
            if (!spkValidResult.IsOk || !spkValidResult.Unwrap())
                throw new ShieldChainStepException(
                    $"SPK signature validation failed: {(spkValidResult.IsOk ? "Invalid signature" : spkValidResult.UnwrapErr())}");

            Logger.WriteLine("[ShieldPro] Deriving X3DH shared secret.");
            var deriveResult = _ecliptixSystemIdentityKeys.X3dhDeriveSharedSecret(peerBundle, X3dhInfo);
            if (!deriveResult.IsOk)
                throw new ShieldChainStepException($"Shared secret derivation failed: {deriveResult.UnwrapErr()}");
            var rootKeyHandle = deriveResult.Unwrap();

            byte[] rootKeyBytes = new byte[Constants.X25519KeySize];
            rootKeyHandle.Read(rootKeyBytes.AsSpan());
            Logger.WriteLine($"[ShieldPro] Derived Root Key: {Convert.ToHexString(rootKeyBytes)}");

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
        uint sessionId, PubKeyExchangeType exchangeType, byte[] plainPayload)
    {
        if (_disposed)
            throw new ObjectDisposedException(nameof(EcliptixProtocolSystem));
        if (plainPayload == null)
            throw new ArgumentNullException(nameof(plainPayload));

        Logger.WriteLine($"[ShieldPro] Producing outbound message for session {sessionId} ({exchangeType}).");

        return await ExecuteUnderSessionLockAsync(sessionId, exchangeType, async session =>
        {
            byte[]? messageKeyBytes = null;
            byte[]? ciphertext = null;
            byte[]? tag = null;
            ShieldMessageKey? messageKeyClone = null;
            try
            {
                Logger.WriteLine("[ShieldPro] Preparing next send message.");
                var prepResult = session.PrepareNextSendMessage();
                if (!prepResult.IsOk)
                    throw new ShieldChainStepException(
                        $"Failed to prepare outgoing message key: {prepResult.UnwrapErr()}");
                var (messageKey, includeDhKey) = prepResult.Unwrap();

                var nonceResult = session.GenerateNextNonce();
                if (!nonceResult.IsOk)
                    throw new ShieldChainStepException($"Failed to generate nonce: {nonceResult.UnwrapErr()}");
                var nonce = nonceResult.Unwrap();

                Logger.WriteLine($"[ShieldPro][Encrypt] Nonce: {Convert.ToHexString(nonce)}");
                Logger.WriteLine($"[ShieldPro][Encrypt] Plaintext: {Convert.ToHexString(plainPayload)}");

                byte[]? newSenderDhPublicKey = includeDhKey
                    ? session.GetCurrentSenderDhPublicKey().Match(ok => ok,
                        err => throw new ShieldChainStepException($"Failed to get sender DH key: {err.Message}"))
                    : null;
                if (newSenderDhPublicKey != null)
                    Logger.WriteLine(
                        $"[ShieldPro] Including new DH Public Key: {Convert.ToHexString(newSenderDhPublicKey)}");

                messageKeyBytes = new byte[Constants.AesKeySize];
                messageKey.ReadKeyMaterial(messageKeyBytes);
                Logger.WriteLine($"[ShieldPro][Encrypt] Message Key: {Convert.ToHexString(messageKeyBytes)}");

                var cloneResult = ShieldMessageKey.New(messageKey.Index, messageKeyBytes);
                if (!cloneResult.IsOk)
                    throw new ShieldChainStepException($"Failed to clone message key: {cloneResult.UnwrapErr()}");
                messageKeyClone = cloneResult.Unwrap();

                SodiumInterop.SecureWipe(messageKeyBytes);
                messageKeyBytes = null;

                var peerBundleResult = session.GetPeerBundle();
                if (!peerBundleResult.IsOk)
                    throw new ShieldChainStepException($"Failed to get peer bundle: {peerBundleResult.UnwrapErr()}");
                var peerBundle = peerBundleResult.Unwrap();

                byte[] localId = _ecliptixSystemIdentityKeys.IdentityX25519PublicKey;
                byte[] peerId = peerBundle.IdentityX25519;
                byte[] ad = new byte[localId.Length + peerId.Length];
                Buffer.BlockCopy(localId, 0, ad, 0, localId.Length);
                Buffer.BlockCopy(peerId, 0, ad, localId.Length, peerId.Length);
                Logger.WriteLine($"[ShieldPro][Encrypt] Associated Data: {Convert.ToHexString(ad)}");

                byte[] clonedKeyMaterial = new byte[Constants.AesKeySize];
                try
                {
                    messageKeyClone.ReadKeyMaterial(clonedKeyMaterial);
                    (ciphertext, tag) = AesGcmService.EncryptAllocating(clonedKeyMaterial, nonce, plainPayload, ad);
                    Logger.WriteLine($"[ShieldPro][Encrypt] Ciphertext: {Convert.ToHexString(ciphertext)}");
                    Logger.WriteLine($"[ShieldPro][Encrypt] Tag: {Convert.ToHexString(tag)}");
                }
                finally
                {
                    SodiumInterop.SecureWipe(clonedKeyMaterial);
                }

                byte[] ciphertextAndTag = new byte[ciphertext.Length + tag.Length];
                Buffer.BlockCopy(ciphertext, 0, ciphertextAndTag, 0, ciphertext.Length);
                Buffer.BlockCopy(tag, 0, ciphertextAndTag, ciphertext.Length, tag.Length);
                Logger.WriteLine($"[ShieldPro][Encrypt] Ciphertext+Tag: {Convert.ToHexString(ciphertextAndTag)}");

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

                Logger.WriteLine($"[ShieldPro] Outbound message prepared with Ratchet Index: {messageKeyClone.Index}");
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
        uint sessionId, PubKeyExchangeType exchangeType, CipherPayload cipherPayloadProto)
    {
        if (_disposed)
            throw new ObjectDisposedException(nameof(EcliptixProtocolSystem));
        if (cipherPayloadProto == null)
            throw new ArgumentNullException(nameof(cipherPayloadProto));
        if (cipherPayloadProto.Cipher.Length < Constants.AesGcmTagSize)
            throw new ArgumentException("Ciphertext invalid.", nameof(cipherPayloadProto));
        if (cipherPayloadProto.Nonce.Length != Constants.AesGcmNonceSize)
            throw new ArgumentException("Nonce invalid.", nameof(cipherPayloadProto));

        Logger.WriteLine(
            $"[ShieldPro] Processing inbound message for session {sessionId} ({exchangeType}), Ratchet Index: {cipherPayloadProto.RatchetIndex}");

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
                        Logger.WriteLine($"[ShieldPro][Decrypt] Received DH Key: {Convert.ToHexString(receivedDhKey)}");
                        Logger.WriteLine(
                            $"[ShieldPro][Decrypt] Current Peer DH Key: {Convert.ToHexString(currentPeerDh)}");
                        if (!receivedDhKey.SequenceEqual(currentPeerDh))
                        {
                            Logger.WriteLine("[ShieldPro] Performing DH ratchet due to new peer DH key.");
                            var ratchetResult = session.PerformReceivingRatchet(receivedDhKey);
                            if (!ratchetResult.IsOk)
                                throw new ShieldChainStepException(
                                    $"Failed to perform DH ratchet: {ratchetResult.UnwrapErr()}");
                        }
                    }
                }

                Logger.WriteLine(
                    $"[ShieldPro][Decrypt] Ciphertext+Tag: {Convert.ToHexString(cipherPayloadProto.Cipher.ToByteArray())}");
                Logger.WriteLine(
                    $"[ShieldPro][Decrypt] Nonce: {Convert.ToHexString(cipherPayloadProto.Nonce.ToByteArray())}");

                var messageKeyResult = session.ProcessReceivedMessage(cipherPayloadProto.RatchetIndex, receivedDhKey);
                if (!messageKeyResult.IsOk)
                    throw new ShieldChainStepException($"Failed to process message: {messageKeyResult.UnwrapErr()}");
                var originalMessageKey = messageKeyResult.Unwrap();

                messageKeyBytes = new byte[Constants.AesKeySize];
                originalMessageKey.ReadKeyMaterial(messageKeyBytes);
                Logger.WriteLine($"[ShieldPro][Decrypt] Message Key: {Convert.ToHexString(messageKeyBytes)}");

                var cloneResult = ShieldMessageKey.New(originalMessageKey.Index, messageKeyBytes);
                if (!cloneResult.IsOk)
                    throw new ShieldChainStepException(
                        $"Failed to clone message key for decryption: {cloneResult.UnwrapErr()}");
                messageKeyClone = cloneResult.Unwrap();

                Logger.WriteLine($"[ShieldPro] Processed Key Index: {messageKeyClone.Index}");

                var peerBundleResult = session.GetPeerBundle();
                if (!peerBundleResult.IsOk)
                    throw new ShieldChainStepException($"Failed to get peer bundle: {peerBundleResult.UnwrapErr()}");
                var peerBundle = peerBundleResult.Unwrap();

                byte[] senderId = peerBundle.IdentityX25519;
                byte[] receiverId = _ecliptixSystemIdentityKeys.IdentityX25519PublicKey;
                ad = new byte[senderId.Length + receiverId.Length];
                Buffer.BlockCopy(senderId, 0, ad, 0, senderId.Length);
                Buffer.BlockCopy(receiverId, 0, ad, senderId.Length, receiverId.Length);
                Logger.WriteLine($"[ShieldPro][Decrypt] Associated Data: {Convert.ToHexString(ad)}");

                byte[] clonedKeyMaterial = new byte[Constants.AesKeySize];
                try
                {
                    messageKeyClone.ReadKeyMaterial(clonedKeyMaterial);
                    Logger.WriteLine($"[ShieldPro][Decrypt] Decryption Key: {Convert.ToHexString(clonedKeyMaterial)}");

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
                    Logger.WriteLine($"[ShieldPro][Decrypt] Plaintext: {Convert.ToHexString(plaintext)}");

                    byte[] plaintextCopy = (byte[])plaintext.Clone();
                    Logger.WriteLine(
                        $"[ShieldPro][Decrypt] Returning plaintext copy: {Convert.ToHexString(plaintextCopy)}");
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
        Logger.WriteLine("[ShieldPro] Disposing...");
        await _sessionManager.DisposeAsync();
        Logger.WriteLine("[ShieldPro] Disposed.");
        GC.SuppressFinalize(this);
    }

    private static class Logger
    {
        private static readonly object Lock = new();

        public static void WriteLine(string message)
        {
            lock (Lock)
            {
                Debug.WriteLine($"[{DateTime.UtcNow:HH:mm:ss.fff}] {message}");
            }
        }
    }
}
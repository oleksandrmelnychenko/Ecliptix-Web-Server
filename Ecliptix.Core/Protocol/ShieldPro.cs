using Ecliptix.Core.Protocol.Utilities;
using Ecliptix.Protobuf.CipherPayload;
using Ecliptix.Protobuf.PubKeyExchange;
using Google.Protobuf;
using Google.Protobuf.WellKnownTypes;
using Sodium;
using System.Security.Cryptography;
using System.Threading.Tasks;

namespace Ecliptix.Core.Protocol;

public sealed class ShieldPro : IDataCenterPubKeyExchange, IOutboundMessageService, IInboundMessageService,
    IAsyncDisposable
{
    private const uint DefaultOneTimePreKeyCount = 3;

    public static ReadOnlySpan<byte> X3dhInfo => "Ecliptix_X3DH"u8;
    public static ReadOnlySpan<byte> InitialSenderChainInfo => Constants.InitialSenderChainInfo;
    public static ReadOnlySpan<byte> InitialReceiverChainInfo => Constants.InitialReceiverChainInfo;

    private readonly LocalKeyMaterial _localKeyMaterial;
    private readonly ShieldSessionManager _sessionManager;
    private bool _disposed = false;

    public ShieldPro(LocalKeyMaterial localKeyMaterial, ShieldSessionManager? sessionManager = null)
    {
        _localKeyMaterial = localKeyMaterial ?? throw new ArgumentNullException(nameof(localKeyMaterial));
        _sessionManager = sessionManager ?? ShieldSessionManager.CreateWithCleanupTask();
    }

    private static uint GenerateRequestId() => Helpers.GenerateRandomUInt32(true);
    private static Timestamp GetProtoTimestamp() => Timestamp.FromDateTimeOffset(DateTimeOffset.UtcNow);

    // Locking Helpers (unchanged)
    private async ValueTask ExecuteUnderSessionLockAsync(uint sessionId, PubKeyExchangeOfType exchangeType,
        Func<ShieldSession, ValueTask> action)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        SessionHolder holder = _sessionManager.GetSessionHolderOrThrow(sessionId, exchangeType);
        await holder.Lock.WaitAsync().ConfigureAwait(false);
        try
        {
            if (holder.Session.State != PubKeyExchangeState.Complete)
                throw new ShieldChainStepException($"Session {sessionId} (Type: {exchangeType}) not Complete.");
            holder.Session.EnsureNotExpired();
            await action(holder.Session).ConfigureAwait(false);
        }
        finally
        {
            holder.Lock.Release();
        }
    }

    private async Task<TResult> ExecuteUnderSessionLockAsync<TResult>(uint sessionId, PubKeyExchangeOfType exchangeType,
        Func<ShieldSession, Task<TResult>> action)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        SessionHolder holder = _sessionManager.GetSessionHolderOrThrow(sessionId, exchangeType);
        await holder.Lock.WaitAsync().ConfigureAwait(false);
        try
        {
            if (holder.Session.State != PubKeyExchangeState.Complete)
                throw new ShieldChainStepException($"Session {sessionId} (Type: {exchangeType}) not Complete.");
            holder.Session.EnsureNotExpired();
            return await action(holder.Session).ConfigureAwait(false);
        }
        finally
        {
            holder.Lock.Release();
        }
    }

    // IDataCenterPubKeyExchange Implementation
    public async Task<(uint SessionId, PubKeyExchange InitialMessage)> BeginDataCenterPubKeyExchangeAsync(
        PubKeyExchangeOfType exchangeType)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        uint sessionId = GenerateRequestId();
        Console.WriteLine($"[ShieldPro] Beginning exchange {exchangeType}, generated Session ID: {sessionId}");

        try
        {
            _localKeyMaterial.GenerateEphemeralKeyPair();
            PublicKeyBundle localPublicBundleProto = _localKeyMaterial.CreatePublicBundle().ToProtobufExchange()
                                                     ?? throw new ShieldChainStepException(
                                                         "Failed to create local public bundle for handshake.");

            ShieldSession session = new(sessionId, localPublicBundleProto, true); // Alice is initiator
            _sessionManager.InsertSessionOrThrow(sessionId, exchangeType, session);
            Console.WriteLine($"[ShieldPro] Session {sessionId} inserted into manager.");

            PubKeyExchange pubKeyExchangeProto = new()
            {
                RequestId = GenerateRequestId(),
                State = PubKeyExchangeState.Init,
                OfType = exchangeType,
                Payload = localPublicBundleProto.ToByteString(),
                CreatedAt = GetProtoTimestamp()
            };
            return (sessionId, pubKeyExchangeProto);
        }
        catch (Exception ex)
        {
            throw new ShieldChainStepException($"Begin key exchange failed: {ex.Message}", ex);
        }
    }

    public Task<(uint SessionId, SodiumSecureMemoryHandle RootKeyHandle)> CompleteDataCenterPubKeyExchangeAsync(
        uint sessionId, PubKeyExchangeOfType exchangeType,
        PubKeyExchange peerMessage)
    {
        throw new NotImplementedException();
    }

    public async Task<(uint SessionId, PubKeyExchange ResponseMessage)> ProcessAndRespondToPubKeyExchangeAsync(
        PubKeyExchange peerInitialMessageProto)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(peerInitialMessageProto);
        if (peerInitialMessageProto.State != PubKeyExchangeState.Init)
            throw new ArgumentException("Expected peer message state to be Init.", nameof(peerInitialMessageProto));

        PubKeyExchangeOfType exchangeType = peerInitialMessageProto.OfType;
        uint sessionId = GenerateRequestId();
        Console.WriteLine($"[ShieldPro] Processing exchange request {exchangeType}, generated Session ID: {sessionId}");

        SodiumSecureMemoryHandle? rootKeyHandle = null;
        try
        {
            _localKeyMaterial.GenerateEphemeralKeyPair();
            Console.WriteLine("[ShieldPro Bob] Generated EK for response.");

            PublicKeyBundle localPublicBundleProto = _localKeyMaterial.CreatePublicBundle().ToProtobufExchange()
                                                     ?? throw new ShieldChainStepException(
                                                         "Failed to create local public bundle for response.");

            ShieldSession session = new(sessionId, localPublicBundleProto, false); // Bob is responder
            _sessionManager.InsertSessionOrThrow(sessionId, exchangeType, session);

            PublicKeyBundle peerBundleProto =
                Helpers.ParseFromBytes<PublicKeyBundle>(peerInitialMessageProto.Payload.ToByteArray());
            Result<LocalPublicKeyBundle, ShieldError> conversionResult =
                LocalPublicKeyBundle.FromProtobufExchange(peerBundleProto);
            if (conversionResult.IsErr) throw conversionResult.UnwrapErr();
            LocalPublicKeyBundle peerBundleInternal = conversionResult.Unwrap();

            Result<bool, ShieldFailure> verificationResult = LocalKeyMaterial.VerifyRemoteSpkSignature(
                peerBundleInternal.IdentityEd25519, peerBundleInternal.SignedPreKeyPublic,
                peerBundleInternal.SignedPreKeySignature);
            if (!verificationResult.Unwrap()) throw new ShieldChainStepException("SPK signature validation failed.");

            Result<SodiumSecureMemoryHandle, ShieldFailure> deriveResult =
                _localKeyMaterial.CalculateSharedSecretAsRecipient(
                    peerBundleInternal.IdentityX25519,
                    peerBundleInternal.EphemeralX25519,
                    peerBundleInternal.OneTimePreKeys?.FirstOrDefault()?.PreKeyId,
                    X3dhInfo);
            if (deriveResult.IsErr) throw deriveResult.UnwrapErr();
            rootKeyHandle = deriveResult.Unwrap();

            byte[] rootKeyBytes = new byte[Constants.X25519KeySize];
            rootKeyHandle.Read(rootKeyBytes.AsSpan());

            session.SetPeerBundle(peerBundleProto);
            session.SetConnectionState(PubKeyExchangeState.Pending);
            session.FinalizeChainAndDhKeys(rootKeyBytes, peerBundleInternal.EphemeralX25519);
            session.SetConnectionState(PubKeyExchangeState.Complete);

            SodiumInterop.SecureWipe(rootKeyBytes);
            rootKeyHandle.Dispose();
            rootKeyHandle = null;

            Console.WriteLine($"[ShieldPro] Session {sessionId} finalized and ready.");

            PubKeyExchange responseMessageProto = new()
            {
                RequestId = GenerateRequestId(),
                State = PubKeyExchangeState.Pending,
                OfType = exchangeType,
                Payload = localPublicBundleProto.ToByteString(),
                CreatedAt = GetProtoTimestamp()
            };
            return (sessionId, responseMessageProto);
        }
        catch (Exception ex)
        {
            rootKeyHandle?.Dispose();
            await _sessionManager.RemoveSessionAsync(sessionId, exchangeType);
            throw new ShieldChainStepException($"Processing/Responding to key exchange failed: {ex.Message}", ex);
        }
    }

    public async Task CompletePubKeyExchangeAsync(uint sessionId, PubKeyExchangeOfType exchangeType,
        PubKeyExchange peerResponseMessageProto)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(peerResponseMessageProto);
        if (peerResponseMessageProto.State != PubKeyExchangeState.Pending)
            throw new ArgumentException("Expected peer message state to be Pending.", nameof(peerResponseMessageProto));
        if (peerResponseMessageProto.OfType != exchangeType)
            throw new ArgumentException("Exchange type mismatch.", nameof(peerResponseMessageProto));

        Console.WriteLine($"[ShieldPro] Completing exchange for Session {sessionId} ({exchangeType})");
        SessionHolder holder = _sessionManager.GetSessionHolderOrThrow(sessionId, exchangeType);
        SodiumSecureMemoryHandle? rootKeyHandle = null;

        await holder.Lock.WaitAsync().ConfigureAwait(false);
        try
        {
            ShieldSession session = holder.Session;
            if (session.State != PubKeyExchangeState.Init)
                throw new ShieldChainStepException($"Session {sessionId} not in Init state.");

            PublicKeyBundle peerBundleProto =
                Helpers.ParseFromBytes<PublicKeyBundle>(peerResponseMessageProto.Payload.ToByteArray());
            Result<LocalPublicKeyBundle, ShieldError> conversionResult =
                LocalPublicKeyBundle.FromProtobufExchange(peerBundleProto);
            if (conversionResult.IsErr) throw conversionResult.UnwrapErr();
            LocalPublicKeyBundle peerBundleInternal = conversionResult.Unwrap();

            Result<bool, ShieldFailure> verificationResult = LocalKeyMaterial.VerifyRemoteSpkSignature(
                peerBundleInternal.IdentityEd25519, peerBundleInternal.SignedPreKeyPublic,
                peerBundleInternal.SignedPreKeySignature);
            if (!verificationResult.Unwrap()) throw new ShieldChainStepException("SPK signature validation failed.");

            Result<SodiumSecureMemoryHandle, ShieldFailure> deriveResult =
                _localKeyMaterial.X3dhDeriveSharedSecret(peerBundleInternal, X3dhInfo);
            if (deriveResult.IsErr) throw deriveResult.UnwrapErr();
            rootKeyHandle = deriveResult.Unwrap();

            byte[] rootKeyBytes = new byte[Constants.X25519KeySize];
            try
            {
                rootKeyHandle.Read(rootKeyBytes.AsSpan());
                session.SetPeerBundle(peerBundleProto);
                session.FinalizeChainAndDhKeys(rootKeyBytes, peerBundleInternal.EphemeralX25519);
                session.SetConnectionState(PubKeyExchangeState.Complete);
            }
            finally
            {
                SodiumInterop.SecureWipe(rootKeyBytes);
            }

            rootKeyHandle.Dispose();
            rootKeyHandle = null;

            Console.WriteLine($"[ShieldPro] Session {sessionId} finalized and ready.");
        }
        finally
        {
            holder.Lock.Release();
            if (rootKeyHandle != null) rootKeyHandle.Dispose();
        }
    }

    public async Task<CipherPayload> ProduceOutboundMessageAsync(uint sessionId, PubKeyExchangeOfType exchangeType,
        byte[] plainPayload)
    {
        ArgumentNullException.ThrowIfNull(plainPayload);
        ObjectDisposedException.ThrowIf(_disposed, this);

        return await ExecuteUnderSessionLockAsync(sessionId, exchangeType, async session =>
        {
            byte[]? messageKeyBytes = null;
            byte[]? ad = null;
            byte[]? ciphertext = null;
            byte[]? tag = null;
            ShieldMessageKey? messageKeyClone = null;

            try
            {
                var (messageKey, includeDhKey) = session.PrepareNextSendMessage();
                byte[] nonce = session.GenerateNextNonce(ChainStepType.Sender);
                byte[]? newSenderDhPublicKey = includeDhKey ? session.GetCurrentSenderDhPublicKey() : null;

                messageKeyBytes = new byte[Constants.AesKeySize];
                messageKey.ReadKeyMaterial(messageKeyBytes);
                Console.WriteLine($"[ProduceOutbound] Encryption Key: {Convert.ToHexString(messageKeyBytes)}");
                messageKeyClone = new ShieldMessageKey(messageKey.Index, messageKeyBytes);
                SodiumInterop.SecureWipe(messageKeyBytes);
                messageKeyBytes = null;

                byte[] initiatorIdPub = exchangeType == PubKeyExchangeOfType.AppDeviceEphemeralConnect
                    ? _localKeyMaterial.IdentityX25519PublicKey
                    : session.PeerBundle.IdentityX25519PublicKey.ToByteArray();
                byte[] responderIdPub = exchangeType == PubKeyExchangeOfType.AppDeviceEphemeralConnect
                    ? session.PeerBundle.IdentityX25519PublicKey.ToByteArray()
                    : _localKeyMaterial.IdentityX25519PublicKey;
                ad = new byte[initiatorIdPub.Length + responderIdPub.Length];
                Buffer.BlockCopy(initiatorIdPub, 0, ad, 0, initiatorIdPub.Length);
                Buffer.BlockCopy(responderIdPub, 0, ad, initiatorIdPub.Length, responderIdPub.Length);

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

                var protoPayload = new CipherPayload
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

                return protoPayload;
            }
            finally
            {
                messageKeyClone?.Dispose();
                SodiumInterop.SecureWipe(ad);
                SodiumInterop.SecureWipe(ciphertext);
                SodiumInterop.SecureWipe(tag);
            }
        });
    }

    // IInboundMessageService Implementation
    public async Task<byte[]> ProcessInboundMessageAsync(uint sessionId, PubKeyExchangeOfType exchangeType,
        CipherPayload cipherPayloadProto)
    {
        ArgumentNullException.ThrowIfNull(cipherPayloadProto);
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (cipherPayloadProto.Cipher.Length < Constants.AesGcmTagSize)
            throw new ArgumentException("Ciphertext invalid.", nameof(cipherPayloadProto));
        if (cipherPayloadProto.Nonce.Length != Constants.AesGcmNonceSize)
            throw new ArgumentException("Nonce invalid.", nameof(cipherPayloadProto));

        return await ExecuteUnderSessionLockAsync(sessionId, exchangeType, async session =>
        {
            byte[]? messageKeyBytes = null;
            byte[]? ad = null;
            byte[]? plaintext = null;
            ShieldMessageKey? messageKeyClone = null;

            try
            {
                byte[]? receivedDhKey = cipherPayloadProto.DhPublicKey.Length > 0
                    ? cipherPayloadProto.DhPublicKey.ToByteArray()
                    : null;
                ShieldMessageKey originalMessageKey =
                    session.ProcessReceivedMessage(cipherPayloadProto.RatchetIndex, receivedDhKey);

                messageKeyBytes = new byte[Constants.AesKeySize];
                originalMessageKey.ReadKeyMaterial(messageKeyBytes);
                messageKeyClone = new ShieldMessageKey(originalMessageKey.Index, messageKeyBytes);
                SodiumInterop.SecureWipe(messageKeyBytes);
                messageKeyBytes = null;

                Console.WriteLine(
                    $"[ProcessInbound] Session: {sessionId}, Received Index: {cipherPayloadProto.RatchetIndex}, Processed Key Index: {messageKeyClone.Index}");

                byte[] initiatorIdPub = exchangeType == PubKeyExchangeOfType.AppDeviceEphemeralConnect
                    ? session.PeerBundle.IdentityX25519PublicKey.ToByteArray()
                    : _localKeyMaterial.IdentityX25519PublicKey;
                byte[] responderIdPub = exchangeType == PubKeyExchangeOfType.AppDeviceEphemeralConnect
                    ? _localKeyMaterial.IdentityX25519PublicKey
                    : session.PeerBundle.IdentityX25519PublicKey.ToByteArray();
                ad = new byte[initiatorIdPub.Length + responderIdPub.Length];
                Buffer.BlockCopy(initiatorIdPub, 0, ad, 0, initiatorIdPub.Length);
                Buffer.BlockCopy(responderIdPub, 0, ad, initiatorIdPub.Length, responderIdPub.Length);

                byte[] clonedKeyMaterial = new byte[Constants.AesKeySize];
                try
                {
                    messageKeyClone.ReadKeyMaterial(clonedKeyMaterial);
                    Console.WriteLine($"[ProcessInbound] Decryption Key: {Convert.ToHexString(clonedKeyMaterial)}");

                    ReadOnlySpan<byte> cipherWithTagSpan = cipherPayloadProto.Cipher.Span;
                    int cipherLength = cipherWithTagSpan.Length - Constants.AesGcmTagSize;
                    ReadOnlySpan<byte> cipherOnlySpan = cipherWithTagSpan[..cipherLength];
                    ReadOnlySpan<byte> tagSpan = cipherWithTagSpan[cipherLength..];

                    plaintext = AesGcmService.DecryptAllocating(
                        clonedKeyMaterial,
                        cipherPayloadProto.Nonce.ToByteArray(),
                        cipherOnlySpan.ToArray(),
                        tagSpan.ToArray(),
                        ad);
                }
                catch (AuthenticationTagMismatchException authEx)
                {
                    throw new ShieldChainStepException($"Decryption failed session {sessionId} (MAC mismatch).",
                        authEx);
                }
                finally
                {
                    SodiumInterop.SecureWipe(clonedKeyMaterial);
                }

                var returnPlaintext = plaintext;
                plaintext = null;
                return returnPlaintext;
            }
            finally
            {
                messageKeyClone?.Dispose();
                SodiumInterop.SecureWipe(ad);
                SodiumInterop.SecureWipe(plaintext);
            }
        });
    }

    // IAsyncDisposable Implementation
    public async ValueTask DisposeAsync()
    {
        if (!_disposed)
        {
            _disposed = true;
            Console.WriteLine("[ShieldPro] Disposing...");
            await _sessionManager.DisposeAsync().ConfigureAwait(false);
            Console.WriteLine("[ShieldPro] Disposed.");
            GC.SuppressFinalize(this);
        }
    }
}
using Ecliptix.Core.Protocol.Utilities; // For Constants, ShieldChainStepException, Helpers, ShieldFailure, Result etc.
using Sodium; // For SodiumCore, SodiumInterop, etc.
using System.Security.Cryptography; // For AuthenticationTagMismatchException
using Ecliptix.Protobuf.CipherPayload; // Protobuf generated class
using Ecliptix.Protobuf.PubKeyExchange; // Protobuf generated classes
using Google.Protobuf; // For ByteString
using Google.Protobuf.WellKnownTypes; // For Timestamp

namespace Ecliptix.Core.Protocol;
// Assuming supporting types (LocalKeyMaterial, ShieldSessionManager, ShieldSession, etc.)
// and interfaces (IDataCenterPubKeyExchange, etc.) are correctly defined in accessible namespaces.
// Assuming internal LocalPublicKeyBundle record is defined correctly.

public sealed class ShieldPro : IDataCenterPubKeyExchange, IOutboundMessageService, IInboundMessageService,
    IAsyncDisposable
{
    // --- Constants ---
    private const uint DefaultOneTimePreKeyCount = 3;
    public static ReadOnlySpan<byte> X3dhInfo => "WhisperText"u8;
    private static ReadOnlySpan<byte> SenderChainInfo => [0x01];
    private static ReadOnlySpan<byte> ReceiverChainInfo => [0x02];

    // --- Fields ---
    private readonly LocalKeyMaterial _localKeyMaterial;
    private readonly ShieldSessionManager _sessionManager;
    private bool _disposed = false;

    public ShieldPro(LocalKeyMaterial localKeyMaterial, ShieldSessionManager? sessionManager = null)
    {
        SodiumCore.Init(); // Call once at app startup elsewhere ideally
        _localKeyMaterial = localKeyMaterial ?? throw new ArgumentNullException(nameof(localKeyMaterial));
        _sessionManager = sessionManager ?? ShieldSessionManager.CreateWithCleanupTask();
    }

    // --- Helper Methods ---
    private static uint GenerateRequestId() => Helpers.GenerateRandomUInt32(true);
    private static Timestamp GetProtoTimestamp() => Timestamp.FromDateTimeOffset(DateTimeOffset.UtcNow);

    // --- Locking Helpers (Revised for ConfigureAwait) ---
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
        catch (Exception ex) when (ex is not ShieldChainStepException and not ObjectDisposedException)
        {
            throw new ShieldChainStepException($"Locked operation failed session {sessionId}: {ex.Message}", ex);
        }
        finally
        {
            holder.Lock.Release();
        }
    }

    private async ValueTask ExecuteUnderSessionLockAsync(uint sessionId, PubKeyExchangeOfType exchangeType,
        Action<ShieldSession> action)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        SessionHolder holder = _sessionManager.GetSessionHolderOrThrow(sessionId, exchangeType);
        await holder.Lock.WaitAsync().ConfigureAwait(false);
        try
        {
            if (holder.Session.State != PubKeyExchangeState.Complete)
                throw new ShieldChainStepException($"Session {sessionId} (Type: {exchangeType}) not Complete.");
            holder.Session.EnsureNotExpired();
            action(holder.Session);
        }
        catch (Exception ex) when (ex is not ShieldChainStepException and not ObjectDisposedException)
        {
            throw new ShieldChainStepException($"Locked operation failed session {sessionId}: {ex.Message}", ex);
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
        catch (Exception ex) when (ex is not ShieldChainStepException and not ObjectDisposedException)
        {
            throw new ShieldChainStepException($"Locked operation failed session {sessionId}: {ex.Message}", ex);
        }
        finally
        {
            holder.Lock.Release();
        }
    }

    private async Task<TResult> ExecuteUnderSessionLockAsync<TResult>(uint sessionId, PubKeyExchangeOfType exchangeType,
        Func<ShieldSession, TResult> action) // Sync lambda overload
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        SessionHolder holder = _sessionManager.GetSessionHolderOrThrow(sessionId, exchangeType);
        await holder.Lock.WaitAsync().ConfigureAwait(false);
        try
        {
            if (holder.Session.State != PubKeyExchangeState.Complete)
                throw new ShieldChainStepException($"Session {sessionId} (Type: {exchangeType}) not Complete.");
            holder.Session.EnsureNotExpired();
            return action(holder.Session);
        }
        catch (Exception ex) when (ex is not ShieldChainStepException and not ObjectDisposedException)
        {
            throw new ShieldChainStepException($"Locked operation failed session {sessionId}: {ex.Message}", ex);
        }
        finally
        {
            holder.Lock.Release();
        }
    }


    // --- IDataCenterPubKeyExchange Implementation ---

    public async Task<(uint SessionId, PubKeyExchange InitialMessage)> BeginDataCenterPubKeyExchangeAsync(
        PubKeyExchangeOfType exchangeType)
    {
        // ... (checks) ...
        uint sessionId = Helpers.GenerateRandomUInt32(excludeZero: true);

        try
        {
            _localKeyMaterial.GenerateEphemeralKeyPair();

            LocalPublicKeyBundle localBundleInternal = _localKeyMaterial.CreatePublicBundle();

            PublicKeyBundle? localPublicBundleProto = localBundleInternal.ToProtobufExchange();
            if (localPublicBundleProto == null) throw new ShieldChainStepException("Failed bundle conversion.");

            ShieldSession session = new(sessionId, localPublicBundleProto);

            _sessionManager.InsertSessionOrThrow(sessionId, exchangeType, session);

            PubKeyExchange pubKeyExchangeProto = new()
            {
                RequestId = GenerateRequestId(), State = PubKeyExchangeState.Init, OfType = exchangeType,
                Payload = localPublicBundleProto.ToByteString(), CreatedAt = GetProtoTimestamp()
            };
            return (sessionId, pubKeyExchangeProto);
        }
        catch (Exception ex)
        {
            throw new ShieldChainStepException($"Begin key exchange failed: {ex.Message}", ex);
        }
    }

    public async Task<(uint SessionId, SodiumSecureMemoryHandle RootKeyHandle)> CompleteDataCenterPubKeyExchangeAsync(
        uint sessionId, PubKeyExchangeOfType exchangeType, PubKeyExchange peerMessageProto)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(peerMessageProto);

        SessionHolder holder = _sessionManager.GetSessionHolderOrThrow(sessionId, exchangeType);
        SodiumSecureMemoryHandle? rootKeyHandle = null; // Declare handle here

        // Declare spans INSIDE the try block AFTER the await
        // Span<byte> rootKeyBytes = stackalloc byte[Constants.X25519KeySize];
        // Span<byte> senderKeyBytes = stackalloc byte[Constants.X25519KeySize];
        // Span<byte> receiverKeyBytes = stackalloc byte[Constants.X25519KeySize];

        await holder.Lock.WaitAsync().ConfigureAwait(false);
        // --- Lock Acquired ---
        Span<byte> rootKeyBytes = stackalloc byte[Constants.X25519KeySize]; // OK to declare here
        Span<byte> senderKeyBytes = stackalloc byte[Constants.X25519KeySize]; // OK to declare here
        Span<byte> receiverKeyBytes = stackalloc byte[Constants.X25519KeySize]; // OK to declare here

        try
        {
            if (holder.Session.State != PubKeyExchangeState.Init)
                throw new ShieldChainStepException($"Session {sessionId} not in Init state.");

            PublicKeyBundle peerBundleProto =
                Helpers.ParseFromBytes<PublicKeyBundle>(peerMessageProto.Payload
                    .ToByteArray());

            Result<LocalPublicKeyBundle, ShieldError> conversionResult =
                LocalPublicKeyBundle.FromProtobufExchange(peerBundleProto);

            if (conversionResult.IsErr) throw conversionResult.UnwrapErr();
            LocalPublicKeyBundle peerBundleInternal = conversionResult.Unwrap();

            Result<bool, ShieldFailure> verificationResult = LocalKeyMaterial.VerifyRemoteSpkSignature(
                peerBundleInternal.IdentityEd25519,
                peerBundleInternal.SignedPreKeyPublic,
                peerBundleInternal.SignedPreKeySignature);

            if (verificationResult.IsErr) throw verificationResult.UnwrapErr();
            if (!verificationResult.Unwrap()) throw new ShieldChainStepException("SPK signature validation failed.");

            holder.Session.SetPeerBundle(peerBundleInternal.ToProtobufExchange());

            Result<SodiumSecureMemoryHandle, ShieldFailure> deriveResult =
                _localKeyMaterial.X3dhDeriveSharedSecret(peerBundleInternal, X3dhInfo);

            if (deriveResult.IsErr) throw deriveResult.UnwrapErr();
            rootKeyHandle = deriveResult.Unwrap();

            rootKeyHandle.Read(rootKeyBytes);
            using (HkdfSha256 hkdfSender = new(rootKeyBytes))
            {
                hkdfSender.Expand(SenderChainInfo, senderKeyBytes);
            }

            using (HkdfSha256 hkdfReceiver = new(rootKeyBytes))
            {
                hkdfReceiver.Expand(ReceiverChainInfo, receiverKeyBytes);
            }

            rootKeyBytes.Clear();

            holder.Session.FinalizeChainKey(senderKeyBytes.ToArray(), receiverKeyBytes.ToArray());
            senderKeyBytes.Clear();
            receiverKeyBytes.Clear();

            holder.Session.SetConnectionState(PubKeyExchangeState.Complete);

            SodiumSecureMemoryHandle returnHandle = rootKeyHandle;
            rootKeyHandle = null; // Transfer ownership
            return (sessionId, returnHandle);
        }
        // --- Catch specific protocol exceptions first if needed (e.g., for logging/specific handling) ---
        catch (ShieldChainStepException)
        {
            throw;
        } // Let specific protocol exceptions propagate
        catch (ShieldFailure)
        {
            throw;
        } // Let specific protocol exceptions propagate
        catch (Exception ex)
        {
            rootKeyHandle?.Dispose(); // Dispose if created before unexpected error
            // Wrap the unexpected exception
            throw new ShieldChainStepException(
                $"Unexpected error during complete key exchange for session {sessionId}: {ex.Message}", ex);
        }
        finally
        {
            // Ensure stack buffers cleared IN ALL CASES after try block execution
            rootKeyBytes.Clear();
            senderKeyBytes.Clear();
            receiverKeyBytes.Clear();
            holder.Lock.Release(); // Release the lock
        }
    }

    // --- IOutboundMessageService Implementation ---

    public async Task<CipherPayload> ProduceOutboundMessageAsync(
        uint sessionId, PubKeyExchangeOfType exchangeType, byte[] plainPayload)
    {
        ArgumentNullException.ThrowIfNull(plainPayload);

        // FIX: ExecuteUnderSessionLockAsync needs Func<ShieldSession, TResult> returning the Protobuf type
        var cipherPayloadProto = await ExecuteUnderSessionLockAsync(sessionId, exchangeType, (session) =>
        {
            byte[]? messageKeyBytes = null;
            byte[]? ad = null;
            byte[]? ciphertext = null;
            byte[]? tag = null;
            byte[]? newSenderDhPublicKey = null;
            byte[]? peerReceiverPubKey = null;

            try
            {
                bool shouldRotateDh = false; // TODO: Implement real rotation logic
                if (shouldRotateDh)
                {
                    try
                    {
                        // FIX: Ensure ShieldSession has GetReceiverStepPublicKeyBytes
                        peerReceiverPubKey = session.GetReceiverStepPublicKeyBytes();
                        newSenderDhPublicKey = session.RotateSenderDh(peerReceiverPubKey);
                    }
                    catch (Exception ex)
                    {
                        throw new ShieldChainStepException($"Sender DH rotation failed session {sessionId}.", ex);
                    }
                    finally
                    {
                        if (peerReceiverPubKey != null) SodiumInterop.SecureWipe(peerReceiverPubKey);
                    }
                }

                (ShieldMessageKey messageKey, byte[] nonce) =
                    session.RotateSenderKey(); // Nonce must be Constants.AesGcmNonceSize

                messageKeyBytes = new byte[Constants.AesKeySize];
                try
                {
                    messageKey.ReadKeyMaterial(messageKeyBytes);

                    byte[] localId = _localKeyMaterial.IdentityX25519PublicKey;
                    // FIX: Use correct property from internal PublicKeyBundle record
                    byte[] peerId = session.PeerBundle.IdentityX25519PublicKey.ToByteArray();
                    ad = new byte[localId.Length + peerId.Length];
                    Buffer.BlockCopy(localId, 0, ad, 0, localId.Length);
                    Buffer.BlockCopy(peerId, 0, ad, localId.Length, peerId.Length);

                    (ciphertext, tag) = AesGcmService.EncryptAllocating(messageKeyBytes, nonce, plainPayload, ad);
                }
                finally
                {
                    if (messageKeyBytes != null) SodiumInterop.SecureWipe(messageKeyBytes);
                    if (ad != null) SodiumInterop.SecureWipe(ad);
                }

                byte[] ciphertextAndTag = new byte[ciphertext.Length + tag.Length];
                Buffer.BlockCopy(ciphertext, 0, ciphertextAndTag, 0, ciphertext.Length);
                Buffer.BlockCopy(tag, 0, ciphertextAndTag, ciphertext.Length, tag.Length);

                // FIX: Construct and return Protobuf CipherPayload
                var protoPayload = new CipherPayload
                {
                    RequestId = GenerateRequestId(),
                    Nonce = ByteString.CopyFrom(nonce),
                    RatchetIndex = messageKey.Index,
                    Cipher = ByteString.CopyFrom(ciphertextAndTag),
                    CreatedAt = GetProtoTimestamp(),
                    DhPublicKey = newSenderDhPublicKey != null ? ByteString.CopyFrom(newSenderDhPublicKey) : null
                };
                return protoPayload; // Return Protobuf type directly
            }
            finally
            {
                if (ciphertext != null) SodiumInterop.SecureWipe(ciphertext);
                if (tag != null) SodiumInterop.SecureWipe(tag);
            }
        }); // End ExecuteUnderSessionLockAsync

        return cipherPayloadProto;
    }

    // --- IInboundMessageService Implementation ---

    public async Task<byte[]> ProcessInboundMessageAsync(
        uint sessionId, PubKeyExchangeOfType exchangeType, CipherPayload cipherPayloadProto) // Takes Protobuf
    {
        ArgumentNullException.ThrowIfNull(cipherPayloadProto);
        if (cipherPayloadProto.Cipher == null || cipherPayloadProto.Cipher.IsEmpty ||
            cipherPayloadProto.Cipher.Length < Constants.AesGcmTagSize)
            throw new ArgumentException("Cipher invalid.", nameof(cipherPayloadProto.Cipher));
        if (cipherPayloadProto.Nonce == null || cipherPayloadProto.Nonce.IsEmpty ||
            cipherPayloadProto.Nonce.Length != Constants.AesGcmNonceSize)
            throw new ArgumentException("Nonce invalid.", nameof(cipherPayloadProto.Nonce));

        // FIX: ExecuteUnderSessionLockAsync needs Func<ShieldSession, byte[]>
        var plaintextResult = await ExecuteUnderSessionLockAsync(sessionId, exchangeType, (session) =>
        {
            byte[]? messageKeyBytes = null;
            byte[]? ad = null;
            byte[]? plaintext = null;

            try
            {
                session.CheckReplay(cipherPayloadProto.RequestId);

                byte[]? receivedDhKey = cipherPayloadProto.DhPublicKey?.ToByteArray();

                ShieldMessageKey messageKey = session.RotateReceiverKey(cipherPayloadProto.RatchetIndex, receivedDhKey);

                messageKeyBytes = new byte[Constants.AesKeySize];
                try
                {
                    messageKey.ReadKeyMaterial(messageKeyBytes);

                    byte[] localId = _localKeyMaterial.IdentityX25519PublicKey;
                    // FIX: Use correct property from internal PublicKeyBundle record
                    byte[] peerId = session.PeerBundle.IdentityX25519PublicKey.ToByteArray();
                    ad = new byte[localId.Length + peerId.Length];
                    Buffer.BlockCopy(localId, 0, ad, 0, localId.Length);
                    Buffer.BlockCopy(peerId, 0, ad, localId.Length, peerId.Length);

                    ReadOnlySpan<byte> cipherWithTagSpan = cipherPayloadProto.Cipher.Span;
                    int cipherLength = cipherWithTagSpan.Length - Constants.AesGcmTagSize;
                    ReadOnlySpan<byte> cipherOnlySpan = cipherWithTagSpan[..cipherLength];
                    ReadOnlySpan<byte> tagSpan = cipherWithTagSpan[cipherLength..];

                    plaintext = AesGcmService.DecryptAllocating(
                        messageKeyBytes, cipherPayloadProto.Nonce.ToByteArray(),
                        cipherOnlySpan.ToArray(), tagSpan.ToArray(), ad);
                }
                catch (ShieldChainStepException ex) when (ex.InnerException is AuthenticationTagMismatchException)
                {
                    throw new ShieldChainStepException($"Decryption failed session {sessionId} (MAC mismatch).", ex);
                }
                finally
                {
                    if (messageKeyBytes != null) SodiumInterop.SecureWipe(messageKeyBytes);
                    if (ad != null) SodiumInterop.SecureWipe(ad);
                }

                // session.RequestMissedMessages();

                var returnPlaintext = plaintext;
                plaintext = null;
                return returnPlaintext; // Return byte[] directly
            }
            finally
            {
                if (plaintext != null) SodiumInterop.SecureWipe(plaintext);
            }
        }); // End ExecuteUnderSessionLockAsync

        return plaintextResult;
    }

    // --- IAsyncDisposable Implementation ---
    public async ValueTask DisposeAsync()
    {
        if (!_disposed)
        {
            await _sessionManager.DisposeAsync().ConfigureAwait(false);
            if (_localKeyMaterial is IDisposable d)
            {
                d.Dispose();
            }

            _disposed = true;
            GC.SuppressFinalize(this);
        }
    }
}

// End namespace
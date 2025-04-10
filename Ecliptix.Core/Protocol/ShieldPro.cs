using Ecliptix.Core.Protocol.Utilities; // For Constants, ShieldChainStepException, Helpers, ShieldFailure, Result etc.
// For SodiumCore, SodiumInterop, etc.
using System.Security.Cryptography; // For AuthenticationTagMismatchException
using Ecliptix.Protobuf.CipherPayload; // Protobuf generated class
using Ecliptix.Protobuf.PubKeyExchange; // Protobuf generated classes
using Google.Protobuf; // For ByteString
using Google.Protobuf.WellKnownTypes; // For Timestamp
// Added for ArgumentNullException, Exception, etc.
// For BinaryPrimitives if used for AD
// Added for Task/ValueTask

// Added for Debug.WriteLine (optional)

namespace Ecliptix.Core.Protocol;

// Assuming supporting types (LocalKeyMaterial, ShieldSessionManager, ShieldSession, etc.)
// and interfaces are correctly defined in accessible namespaces.
// Assuming internal LocalPublicKeyBundle record is defined correctly.
// Assuming Constants class is defined with necessary values (AesGcmKeySize, AesGcmNonceSize, AesGcmTagSize)

public sealed class ShieldPro : IDataCenterPubKeyExchange, IOutboundMessageService, IInboundMessageService,
    IAsyncDisposable
{
    // --- Constants ---
    private const uint DefaultOneTimePreKeyCount = 3;

    // Ensure these are defined correctly, potentially in a shared Constants class
    public static ReadOnlySpan<byte> X3dhInfo => "Ecliptix_X3DH"u8; // Example, ensure it matches usage
    public static ReadOnlySpan<byte> InitialSenderChainInfo => Constants.InitialSenderChainInfo; // Use shared constant

    public static ReadOnlySpan<byte> InitialReceiverChainInfo =>
        Constants.InitialReceiverChainInfo; // Use shared constant

    // --- Fields ---
    private readonly LocalKeyMaterial _localKeyMaterial;
    private readonly ShieldSessionManager _sessionManager;
    private bool _disposed = false;

    public ShieldPro(LocalKeyMaterial localKeyMaterial, ShieldSessionManager? sessionManager = null)
    {
        // SodiumCore.Init(); // Call once at app startup elsewhere ideally
        _localKeyMaterial = localKeyMaterial ?? throw new ArgumentNullException(nameof(localKeyMaterial));
        _sessionManager = sessionManager ?? ShieldSessionManager.CreateWithCleanupTask();
    }

    // --- Helper Methods ---
    private static uint GenerateRequestId() => Helpers.GenerateRandomUInt32(true);
    private static Timestamp GetProtoTimestamp() => Timestamp.FromDateTimeOffset(DateTimeOffset.UtcNow);

    // --- Locking Helpers (Unchanged) ---
    private async ValueTask ExecuteUnderSessionLockAsync(uint sessionId, PubKeyExchangeOfType exchangeType,
        Func<ShieldSession, ValueTask> action)
    {
        // ... as before ...
        ObjectDisposedException.ThrowIf(_disposed, this);
        SessionHolder holder = _sessionManager.GetSessionHolderOrThrow(sessionId, exchangeType);
        await holder.Lock.WaitAsync().ConfigureAwait(false);
        try
        {
            // Check state *after* acquiring lock
            if (holder.Session.State != PubKeyExchangeState.Complete)
                throw new ShieldChainStepException($"Session {sessionId} (Type: {exchangeType}) not Complete.");
            holder.Session.EnsureNotExpired();
            await action(holder.Session).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not ShieldChainStepException and not ObjectDisposedException)
        {
            // Wrap unexpected exceptions
            throw new ShieldChainStepException(
                $"Locked async ValueTask operation failed session {sessionId}: {ex.Message}", ex);
        }
        finally
        {
            holder.Lock.Release();
        }
    }

    private async ValueTask ExecuteUnderSessionLockAsync(uint sessionId, PubKeyExchangeOfType exchangeType,
        Action<ShieldSession> action)
    {
        // ... as before ...
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
            throw new ShieldChainStepException($"Locked sync Action operation failed session {sessionId}: {ex.Message}",
                ex);
        }
        finally
        {
            holder.Lock.Release();
        }
    }

    private async Task<TResult> ExecuteUnderSessionLockAsync<TResult>(uint sessionId, PubKeyExchangeOfType exchangeType,
        Func<ShieldSession, Task<TResult>> action)
    {
        // ... as before ...
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
            throw new ShieldChainStepException(
                $"Locked async Task<TResult> operation failed session {sessionId}: {ex.Message}", ex);
        }
        finally
        {
            holder.Lock.Release();
        }
    }

    private async Task<TResult> ExecuteUnderSessionLockAsync<TResult>(uint sessionId, PubKeyExchangeOfType exchangeType,
        Func<ShieldSession, TResult> action) // Sync lambda overload
    {
        // ... as before ...
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
            throw new ShieldChainStepException(
                $"Locked sync Func<TResult> operation failed session {sessionId}: {ex.Message}", ex);
        }
        finally
        {
            holder.Lock.Release();
        }
    }


    // --- IDataCenterPubKeyExchange Implementation (Using Corrected Session Methods) ---

    public async Task<(uint SessionId, PubKeyExchange InitialMessage)> BeginDataCenterPubKeyExchangeAsync(
        PubKeyExchangeOfType exchangeType)
    {
        // This method seems okay - it creates the session but doesn't finalize it yet.
        // Uses ShieldSession constructor which is fine.
        ObjectDisposedException.ThrowIf(_disposed, this); // Check disposal state
        uint sessionId = Helpers.GenerateRandomUInt32(excludeZero: true);
        Console.WriteLine($"[ShieldPro] Beginning exchange {exchangeType}, generated Session ID: {sessionId}");

        try
        {
            _localKeyMaterial.GenerateEphemeralKeyPair(); // Ensure fresh EK
            PublicKeyBundle localPublicBundleProto = _localKeyMaterial.CreatePublicBundle().ToProtobufExchange()
                                                     ?? throw new ShieldChainStepException(
                                                         "Failed to create local public bundle for handshake.");

            ShieldSession session = new(sessionId, localPublicBundleProto); // Create session

            // Add session to manager BEFORE sending message
            _sessionManager.InsertSessionOrThrow(sessionId, exchangeType, session);
            Console.WriteLine($"[ShieldPro] Session {sessionId} inserted into manager.");


            PubKeyExchange pubKeyExchangeProto = new()
            {
                RequestId = GenerateRequestId(),
                State = PubKeyExchangeState.Init, // Sent by initiator
                OfType = exchangeType,
                Payload = localPublicBundleProto.ToByteString(), // Contains IK, EK, SPK, OPKs
                CreatedAt = GetProtoTimestamp()
            };
            return (sessionId, pubKeyExchangeProto);
        }
        catch (Exception ex) when (ex is not ShieldChainStepException) // Don't wrap our specific exceptions
        {
            // Consider removing session if insertion succeeded but something else failed? Needs careful thought.
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
        uint sessionId = Helpers.GenerateRandomUInt32(excludeZero: true);
        Console.WriteLine($"[ShieldPro] Processing exchange request {exchangeType}, generated Session ID: {sessionId}");

        SessionHolder? holder = null;
        SodiumSecureMemoryHandle? rootKeyHandle = null;

        try
        {
            _localKeyMaterial.GenerateEphemeralKeyPair();
            Console.WriteLine("[ShieldPro Bob] Generated EK for response.");

            PublicKeyBundle localPublicBundleProto = _localKeyMaterial.CreatePublicBundle().ToProtobufExchange()
                                                     ?? throw new ShieldChainStepException(
                                                         "Failed to create local public bundle for response.");

            ShieldSession session = new(sessionId, localPublicBundleProto);
            _sessionManager.InsertSessionOrThrow(sessionId, exchangeType, session);
            holder = _sessionManager.GetSessionHolderOrThrow(sessionId, exchangeType);

            PublicKeyBundle peerBundleProto =
                Helpers.ParseFromBytes<PublicKeyBundle>(peerInitialMessageProto.Payload.ToByteArray());
            Result<LocalPublicKeyBundle, ShieldError> conversionResult =
                LocalPublicKeyBundle.FromProtobufExchange(peerBundleProto);
            if (conversionResult.IsErr) throw conversionResult.UnwrapErr();
            LocalPublicKeyBundle peerBundleInternal = conversionResult.Unwrap();

            Result<bool, ShieldFailure> verificationResult = LocalKeyMaterial.VerifyRemoteSpkSignature(
                peerBundleInternal.IdentityEd25519, peerBundleInternal.SignedPreKeyPublic,
                peerBundleInternal.SignedPreKeySignature);
            if (verificationResult.IsErr) throw verificationResult.UnwrapErr();
            if (!verificationResult.Unwrap()) throw new ShieldChainStepException("SPK signature validation failed.");

            Result<SodiumSecureMemoryHandle, ShieldFailure> deriveResult =
                _localKeyMaterial.CalculateSharedSecretAsRecipient(
                    peerBundleInternal.IdentityX25519,
                    peerBundleInternal.EphemeralX25519,
                    peerBundleInternal.OneTimePreKeys?.FirstOrDefault()?.PreKeyId,
                    X3dhInfo);
            if (deriveResult.IsErr) throw deriveResult.UnwrapErr();
            rootKeyHandle = deriveResult.Unwrap();

            await holder.Lock.WaitAsync().ConfigureAwait(false);
            try
            {
                byte[] rootKeyBytes = new byte[Constants.X25519KeySize];
                rootKeyHandle.Read(rootKeyBytes.AsSpan());

                session.SetPeerBundle(peerBundleProto);
                session.SetConnectionState(PubKeyExchangeState.Pending); // Set state before finalization
                session.FinalizeChainAndDhKeys(rootKeyBytes, peerBundleInternal.EphemeralX25519);
                session.SetConnectionState(PubKeyExchangeState.Complete);

                SodiumInterop.SecureWipe(rootKeyBytes);
                Console.WriteLine($"[ShieldPro] Session {sessionId} finalized and ready.");
            }
            finally
            {
                holder.Lock.Release();
            }

            rootKeyHandle.Dispose();
            rootKeyHandle = null;

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
            if (holder != null)
            {
                await _sessionManager.RemoveSessionAsync(sessionId, exchangeType);
            }

            Console.WriteLine($"[ShieldPro] Error processing/responding to exchange: {ex.Message}");
            throw new ShieldChainStepException($"Processing/Responding to key exchange failed: {ex.Message}", ex);
        }
    }


    // Renamed method for clarity (Alice's side)
    public async Task CompletePubKeyExchangeAsync(uint sessionId, PubKeyExchangeOfType exchangeType,
        PubKeyExchange peerResponseMessageProto)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(peerResponseMessageProto);
        if (peerResponseMessageProto.State != PubKeyExchangeState.Pending)
            throw new ArgumentException("Expected peer message state to be Resp.", nameof(peerResponseMessageProto));
        if (peerResponseMessageProto.OfType != exchangeType)
            throw new ArgumentException("Exchange type mismatch.", nameof(peerResponseMessageProto));


        Console.WriteLine($"[ShieldPro] Completing exchange for Session {sessionId} ({exchangeType})");
        SessionHolder holder = _sessionManager.GetSessionHolderOrThrow(sessionId, exchangeType);
        SodiumSecureMemoryHandle? rootKeyHandle = null; // Declare handle for cleanup

        await holder.Lock.WaitAsync().ConfigureAwait(false);
        try
        {
            ShieldSession session = holder.Session;
            if (session.State != PubKeyExchangeState.Init)
                throw new ShieldChainStepException($"Session {sessionId} not in Init state.");

            // 1. Parse Peer Bundle & Validate SPK
            PublicKeyBundle peerBundleProto =
                Helpers.ParseFromBytes<PublicKeyBundle>(peerResponseMessageProto.Payload.ToByteArray());
            Result<LocalPublicKeyBundle, ShieldError> conversionResult =
                LocalPublicKeyBundle.FromProtobufExchange(peerBundleProto);
            if (conversionResult.IsErr) throw conversionResult.UnwrapErr();
            LocalPublicKeyBundle peerBundleInternal = conversionResult.Unwrap();

            Result<bool, ShieldFailure> verificationResult = LocalKeyMaterial.VerifyRemoteSpkSignature(
                peerBundleInternal.IdentityEd25519, peerBundleInternal.SignedPreKeyPublic,
                peerBundleInternal.SignedPreKeySignature);
            if (verificationResult.IsErr) throw verificationResult.UnwrapErr();
            if (!verificationResult.Unwrap()) throw new ShieldChainStepException("SPK signature validation failed.");

            // 2. Derive Shared Secret (as Initiator)
            Result<SodiumSecureMemoryHandle, ShieldFailure> deriveResult =
                _localKeyMaterial.X3dhDeriveSharedSecret(peerBundleInternal, X3dhInfo);
            if (deriveResult.IsErr) throw deriveResult.UnwrapErr();
            rootKeyHandle = deriveResult.Unwrap(); // Assign for cleanup

            // 3. Finalize Session
            byte[] rootKeyBytes = new byte[Constants.X25519KeySize];
            try
            {
                rootKeyHandle.Read(rootKeyBytes.AsSpan());

                // Use the corrected Finalize method in ShieldSession
                session.SetPeerBundle(peerBundleProto); // Store peer's full bundle
                // Finalize needs the root key and the *peer's initial* DH key (their Ephemeral key)
                session.FinalizeChainAndDhKeys(rootKeyBytes, peerBundleInternal.EphemeralX25519!);
            }
            finally
            {
                SodiumInterop.SecureWipe(rootKeyBytes); // Wipe intermediate key
            }

            rootKeyHandle.Dispose(); // Dispose after use
            rootKeyHandle = null; // Clear reference

            session.SetConnectionState(PubKeyExchangeState.Complete); // Mark Alice's session as ready
            Console.WriteLine($"[ShieldPro] Session {sessionId} finalized and ready.");
        }
        catch (Exception ex) // Catch broader exceptions
        {
            rootKeyHandle?.Dispose(); // Ensure handle is disposed on error
            // Consider removing session on failure?
            // await _sessionManager.RemoveSessionAsync(sessionId, exchangeType);
            Console.WriteLine($"[ShieldPro] Error completing exchange for Session {sessionId}: {ex.Message}");
            throw new ShieldChainStepException($"Complete key exchange failed for session {sessionId}: {ex.Message}",
                ex);
        }
        finally
        {
            holder.Lock.Release();
        }
    }


    // --- IOutboundMessageService Implementation ---
    public async Task<CipherPayload> ProduceOutboundMessageAsync(uint sessionId, PubKeyExchangeOfType exchangeType,
        byte[] plainPayload)
    {
        ArgumentNullException.ThrowIfNull(plainPayload);
        ObjectDisposedException.ThrowIf(_disposed, this); // Check disposal state

        // Use ExecuteUnderSessionLockAsync to handle locking, state checks, and expiry checks
        return await ExecuteUnderSessionLockAsync(sessionId, exchangeType, (session) =>
        {
            // --- Inside Locked Action ---
            byte[]? messageKeyBytes = null;
            byte[]? ad = null;
            byte[]? ciphertext = null;
            byte[]? tag = null;
            ShieldMessageKey? messageKeyClone = null; // Hold the cloned key

            try
            {
                // 1. Prepare the next send message (gets key, nonce, potentially new DH PK)
                (ShieldMessageKey originalMessageKey, byte[] nonce, byte[]? newSenderDhPublicKey) =
                    session.PrepareNextSendMessage(); // Use the corrected session method


                // Clone the key immediately before using it
                messageKeyBytes = new byte[Constants.AesKeySize];
                originalMessageKey.ReadKeyMaterial(messageKeyBytes);
                Console.WriteLine($"[ProduceOutbound] Encryption Key: {Convert.ToHexString(messageKeyBytes)}");
                messageKeyClone = new ShieldMessageKey(originalMessageKey.Index, messageKeyBytes); // Create clone

                // Wipe the temporary buffer used for cloning
                SodiumInterop.SecureWipe(messageKeyBytes);
                messageKeyBytes = null; // Clear reference


                byte[] initiatorIdPub = exchangeType == PubKeyExchangeOfType.AppDeviceEphemeralConnect 
                    ? _localKeyMaterial.IdentityX25519PublicKey 
                    : session.PeerBundle.IdentityX25519PublicKey.ToByteArray();
                byte[] responderIdPub = exchangeType == PubKeyExchangeOfType.AppDeviceEphemeralConnect 
                    ? session.PeerBundle.IdentityX25519PublicKey.ToByteArray() 
                    : _localKeyMaterial.IdentityX25519PublicKey;
                ad = new byte[initiatorIdPub.Length + responderIdPub.Length];
                Buffer.BlockCopy(initiatorIdPub, 0, ad, 0, initiatorIdPub.Length);
                Buffer.BlockCopy(responderIdPub, 0, ad, initiatorIdPub.Length, responderIdPub.Length);


                // 3. Encrypt using the CLONED key material
                byte[] clonedKeyMaterial = new byte[Constants.AesKeySize];
                try
                {
                    messageKeyClone.ReadKeyMaterial(clonedKeyMaterial); // Read from clone
                    (ciphertext, tag) = AesGcmService.EncryptAllocating(clonedKeyMaterial, nonce, plainPayload, ad);
                }
                finally
                {
                    SodiumInterop.SecureWipe(clonedKeyMaterial); // Wipe material read from clone
                }


                // 4. Construct CipherPayload Protobuf
                // Combine ciphertext and tag
                byte[] ciphertextAndTag = new byte[ciphertext.Length + tag.Length];
                Buffer.BlockCopy(ciphertext, 0, ciphertextAndTag, 0, ciphertext.Length);
                Buffer.BlockCopy(tag, 0, ciphertextAndTag, ciphertext.Length, tag.Length);


                var protoPayload = new CipherPayload
                {
                    RequestId = GenerateRequestId(), // Or use a sequence number if needed
                    Nonce = ByteString.CopyFrom(nonce),
                    RatchetIndex = messageKeyClone.Index, // Use index from clone
                    // Rename 'Cipher' field in proto if possible, e.g., to CiphertextAndTag
                    Cipher = ByteString.CopyFrom(ciphertextAndTag), // Store combined CT+Tag
                    CreatedAt = GetProtoTimestamp(),
                    DhPublicKey = newSenderDhPublicKey != null
                        ? ByteString.CopyFrom(newSenderDhPublicKey)
                        : ByteString.Empty
                };


                // Note: originalMessageKey from PrepareNextSendMessage is NOT disposed here,
                // it might still be in the session cache. Only the clone is used and disposed below.

                return Task.FromResult(protoPayload); // Return Task<CipherPayload>
            }
            finally // Ensure cleanup of sensitive byte arrays and the cloned key
            {
                messageKeyClone?.Dispose(); // Dispose the cloned key
                if (ad != null) SodiumInterop.SecureWipe(ad);
                // ciphertext and tag are part of ciphertextAndTag now, which goes into proto
                // Wiping them separately isn't strictly needed if ciphertextAndTag is handled correctly.
                // if (ciphertext != null) SodiumInterop.SecureWipe(ciphertext);
                // if (tag != null) SodiumInterop.SecureWipe(tag);
                // messageKeyBytes was wiped earlier or nulled
            }
            // --- End Locked Action ---
        });
    }


    // --- IInboundMessageService Implementation ---
    public async Task<byte[]> ProcessInboundMessageAsync(uint sessionId, PubKeyExchangeOfType exchangeType,
        CipherPayload cipherPayloadProto)
    {
        ArgumentNullException.ThrowIfNull(cipherPayloadProto);
        ObjectDisposedException.ThrowIf(_disposed, this);

        // Basic structural validation
        if (cipherPayloadProto.Cipher == null || cipherPayloadProto.Cipher.IsEmpty || // Use correct field name
            cipherPayloadProto.Cipher.Length < Constants.AesGcmTagSize)
            throw new ArgumentException("Ciphertext invalid.", nameof(cipherPayloadProto.Cipher));
        if (cipherPayloadProto.Nonce == null || cipherPayloadProto.Nonce.IsEmpty ||
            cipherPayloadProto.Nonce.Length != Constants.AesGcmNonceSize)
            throw new ArgumentException("Nonce invalid.", nameof(cipherPayloadProto.Nonce));


        // Use ExecuteUnderSessionLockAsync for locking and checks
        return await ExecuteUnderSessionLockAsync(sessionId, exchangeType, (session) =>
        {
            // --- Inside Locked Action ---
            byte[]? messageKeyBytes = null;
            byte[]? ad = null;
            byte[]? plaintext = null;
            ShieldMessageKey? messageKeyClone = null; // Hold the cloned key

            try
            {
                // 1. Application-level Anti-Replay Check (Optional, if RequestId is reliable)
                // session.CheckReplay(cipherPayloadProto.RequestId);

                // 2. Process Ratchet/Keys (handles DH, skips, gets key)
                byte[]? receivedDhKey = cipherPayloadProto.DhPublicKey.Length > 0
                    ? cipherPayloadProto.DhPublicKey.ToByteArray()
                    : null;
                ShieldMessageKey originalMessageKey =
                    session.ProcessReceivedMessage(cipherPayloadProto.RatchetIndex,
                        receivedDhKey); // Use corrected session method

                // Clone the key immediately before using it
                messageKeyBytes = new byte[Constants.AesKeySize];
                originalMessageKey.ReadKeyMaterial(messageKeyBytes);
                messageKeyClone = new ShieldMessageKey(originalMessageKey.Index, messageKeyBytes);

                // Wipe the temporary buffer used for cloning
                SodiumInterop.SecureWipe(messageKeyBytes);
                messageKeyBytes = null; // Clear reference

                Console.WriteLine(
                    $"[ProcessInbound] Session: {sessionId}, Received Index: {cipherPayloadProto.RatchetIndex}, Processed Key Index: {messageKeyClone.Index}"); // Use clone's index

                byte[] initiatorIdPub = exchangeType == PubKeyExchangeOfType.AppDeviceEphemeralConnect 
                    ? session.PeerBundle.IdentityX25519PublicKey.ToByteArray() 
                    : _localKeyMaterial.IdentityX25519PublicKey;
                byte[] responderIdPub = exchangeType == PubKeyExchangeOfType.AppDeviceEphemeralConnect 
                    ? _localKeyMaterial.IdentityX25519PublicKey 
                    : session.PeerBundle.IdentityX25519PublicKey.ToByteArray();
                ad = new byte[initiatorIdPub.Length + responderIdPub.Length];
                Buffer.BlockCopy(initiatorIdPub, 0, ad, 0, initiatorIdPub.Length);
                Buffer.BlockCopy(responderIdPub, 0, ad, initiatorIdPub.Length, responderIdPub.Length);

                // 4. Decrypt using the CLONED key material
                byte[] clonedKeyMaterial = new byte[Constants.AesKeySize];
                try
                {
                    messageKeyClone.ReadKeyMaterial(clonedKeyMaterial); // Read from clone
                    Console.WriteLine(
                        $"[ProcessInbound] Decryption Key: {Convert.ToHexString(clonedKeyMaterial)}"); // DEBUG ONLY

                    // Extract Ciphertext and Tag from the combined field
                    ReadOnlySpan<byte> cipherWithTagSpan = cipherPayloadProto.Cipher.Span;
                    if (cipherWithTagSpan.Length < Constants.AesGcmTagSize)
                        throw new ArgumentException("Ciphertext field too short to contain tag.");

                    int cipherLength = cipherWithTagSpan.Length - Constants.AesGcmTagSize;
                    ReadOnlySpan<byte> cipherOnlySpan = cipherWithTagSpan[..cipherLength];
                    ReadOnlySpan<byte> tagSpan = cipherWithTagSpan[cipherLength..];

                    // Use DecryptAllocating which returns byte[]
                    plaintext = AesGcmService.DecryptAllocating(
                        clonedKeyMaterial,
                        cipherPayloadProto.Nonce.ToByteArray(),
                        cipherOnlySpan.ToArray(), // Convert spans back to arrays if needed by service
                        tagSpan.ToArray(),
                        ad);
                }
                catch (AuthenticationTagMismatchException authEx) // Catch specific exception from AesGcmService
                {
                    Console.WriteLine(
                        $"[ProcessInbound] MAC Mismatch for RatchetIndex: {cipherPayloadProto.RatchetIndex}");
                    // Wrap in our specific exception type
                    throw new ShieldChainStepException($"Decryption failed session {sessionId} (MAC mismatch).",
                        authEx);
                }
                finally
                {
                    SodiumInterop.SecureWipe(clonedKeyMaterial); // Wipe material read from clone
                }

                // Transfer ownership of plaintext if successful
                var returnPlaintext = plaintext;
                plaintext = null; // Prevent disposal in finally block if returning
                return Task.FromResult(returnPlaintext); // Return Task<byte[]>
            }
            finally // Ensure cleanup
            {
                messageKeyClone?.Dispose(); // Dispose the cloned key
                if (ad != null) SodiumInterop.SecureWipe(ad);
                // messageKeyBytes was wiped or nulled earlier
                if (plaintext != null) SodiumInterop.SecureWipe(plaintext); // Wipe if not returned
            }
            // --- End Locked Action ---
        });
    }


    // --- IAsyncDisposable Implementation ---
    public async ValueTask DisposeAsync()
    {
        if (!_disposed)
        {
            _disposed = true; // Mark early
            Console.WriteLine("[ShieldPro] Disposing...");
            await _sessionManager.DisposeAsync().ConfigureAwait(false);
            // Dispose LocalKeyMaterial only if ShieldPro owns it (depends on DI setup)
            // if (_localKeyMaterial is IDisposable d)
            // {
            //     d.Dispose();
            // }
            Console.WriteLine("[ShieldPro] Disposed.");
            GC.SuppressFinalize(this);
        }
    }
}

// End namespace
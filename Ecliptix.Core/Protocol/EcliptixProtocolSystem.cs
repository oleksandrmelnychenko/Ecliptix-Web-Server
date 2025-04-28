using System.Diagnostics;
using Ecliptix.Core.Protocol.Utilities;
using Ecliptix.Protobuf.CipherPayload;
using Ecliptix.Protobuf.PubKeyExchange;
using Google.Protobuf;
using Google.Protobuf.WellKnownTypes;

namespace Ecliptix.Core.Protocol;

public sealed class EcliptixProtocolSystem
{
    public static ReadOnlySpan<byte> X3dhInfo => "Ecliptix_X3DH"u8;
    private readonly EcliptixSystemIdentityKeys _ecliptixSystemIdentityKeys;

    private ConnectSession _connectSession;

    private static uint GenerateRequestId()
    {
        return (uint)Interlocked.Increment(ref _requestIdCounter);
    }

    private static long _requestIdCounter = 0;
    private static Timestamp GetProtoTimestamp() => Timestamp.FromDateTimeOffset(DateTimeOffset.UtcNow);

    public EcliptixProtocolSystem(EcliptixSystemIdentityKeys ecliptixSystemIdentityKeys)
    {
        _ecliptixSystemIdentityKeys = ecliptixSystemIdentityKeys;
    }

    public PubKeyExchange BeginDataCenterPubKeyExchangeAsync(
        uint connectId,
        PubKeyExchangeType exchangeType)
    {
        Debug.WriteLine($"[ShieldPro] Beginning exchange {exchangeType}, generated ConnectId: {connectId}");
        Debug.WriteLine("[ShieldPro] Generating ephemeral key pair.");

        _ecliptixSystemIdentityKeys.GenerateEphemeralKeyPair();

        Result<LocalPublicKeyBundle, ShieldFailure>
            localBundleResult = _ecliptixSystemIdentityKeys.CreatePublicBundle();
        if (!localBundleResult.IsOk)
        {
            throw new ShieldChainStepException(
                $"Failed to create local public bundle: {localBundleResult.UnwrapErr()}");
        }

        LocalPublicKeyBundle localBundle = localBundleResult.Unwrap();
        PublicKeyBundle protoBundle = localBundle.ToProtobufExchange();

        Result<ConnectSession, ShieldFailure> sessionResult = ConnectSession.Create(connectId, localBundle, true);
        if (!sessionResult.IsOk)
        {
            throw new ShieldChainStepException($"Failed to create session: {sessionResult.UnwrapErr()}");
        }

        _connectSession = sessionResult.Unwrap();

        Result<byte[]?, ShieldFailure> dhPublicKeyResult = _connectSession.GetCurrentSenderDhPublicKey();
        if (!dhPublicKeyResult.IsOk)
        {
            throw new ShieldChainStepException($"Sender DH key not initialized: {dhPublicKeyResult.UnwrapErr()}");
        }

        byte[]? dhPublicKey = dhPublicKeyResult.Unwrap();

        Debug.WriteLine($"[ShieldPro] Initial DH Public Key: {Convert.ToHexString(dhPublicKey)}");

        PubKeyExchange pubKeyExchange = new()
        {
            State = PubKeyExchangeState.Init,
            OfType = exchangeType,
            Payload = protoBundle.ToByteString(),
            InitialDhPublicKey = ByteString.CopyFrom(dhPublicKey)
        };

        return pubKeyExchange;
    }

    public PubKeyExchange ProcessAndRespondToPubKeyExchangeAsync(
        uint connectId,PubKeyExchange peerInitialMessageProto)
    {
        if (peerInitialMessageProto.State != PubKeyExchangeState.Init)
        {
            throw new ArgumentException("Expected peer message state to be Init.", nameof(peerInitialMessageProto));
        }

        PubKeyExchangeType exchangeType = peerInitialMessageProto.OfType;
        Debug.WriteLine($"[ShieldPro] Processing exchange request {exchangeType}, generated Session ID: {connectId}");

        SodiumSecureMemoryHandle? rootKeyHandle = null;

        try
        {
            PublicKeyBundle peerBundleProto =
                Helpers.ParseFromBytes<PublicKeyBundle>(peerInitialMessageProto.Payload.ToByteArray());
            Result<LocalPublicKeyBundle, ShieldFailure> peerBundleResult =
                LocalPublicKeyBundle.FromProtobufExchange(peerBundleProto);
            if (!peerBundleResult.IsOk)
            {
                throw new ShieldChainStepException($"Failed to convert peer bundle: {peerBundleResult.UnwrapErr()}");
            }

            LocalPublicKeyBundle peerBundle = peerBundleResult.Unwrap();

            Result<bool, ShieldFailure> spkValidResult = EcliptixSystemIdentityKeys.VerifyRemoteSpkSignature(
                peerBundle.IdentityEd25519,
                peerBundle.SignedPreKeyPublic,
                peerBundle.SignedPreKeySignature);

            if (!spkValidResult.IsOk || !spkValidResult.Unwrap())
            {
                throw new ShieldChainStepException(
                    $"SPK signature validation failed: {(spkValidResult.IsOk ? "Invalid signature" : spkValidResult.UnwrapErr())}");
            }

            Debug.WriteLine("[ShieldPro] Generating ephemeral key for response.");
            _ecliptixSystemIdentityKeys.GenerateEphemeralKeyPair();

            Result<LocalPublicKeyBundle, ShieldFailure> localBundleResult =
                _ecliptixSystemIdentityKeys.CreatePublicBundle();
            if (!localBundleResult.IsOk)
            {
                throw new ShieldChainStepException(
                    $"Failed to create local public bundle: {localBundleResult.UnwrapErr()}");
            }

            LocalPublicKeyBundle localBundle = localBundleResult.Unwrap();
            PublicKeyBundle protoBundle = localBundle.ToProtobufExchange();

            Result<ConnectSession, ShieldFailure> sessionResult = ConnectSession.Create(connectId, localBundle, false);
            if (!sessionResult.IsOk)
            {
                throw new ShieldChainStepException($"Failed to create session: {sessionResult.UnwrapErr()}");
            }

            _connectSession = sessionResult.Unwrap();

            Debug.WriteLine("[ShieldPro] Deriving shared secret as recipient.");
            Result<SodiumSecureMemoryHandle, ShieldFailure> deriveResult =
                _ecliptixSystemIdentityKeys.CalculateSharedSecretAsRecipient(
                    peerBundle.IdentityX25519,
                    peerBundle.EphemeralX25519,
                    peerBundle.OneTimePreKeys?.FirstOrDefault()?.PreKeyId,
                    X3dhInfo);
            if (!deriveResult.IsOk)
            {
                throw new ShieldChainStepException($"Shared secret derivation failed: {deriveResult.UnwrapErr()}");
            }

            rootKeyHandle = deriveResult.Unwrap();

            byte[] rootKeyBytes = new byte[Constants.X25519KeySize];
            rootKeyHandle.Read(rootKeyBytes.AsSpan());
            Debug.WriteLine($"[ShieldPro] Root Key: {Convert.ToHexString(rootKeyBytes)}");

            _connectSession.SetPeerBundle(peerBundle);
            _connectSession.SetConnectionState(PubKeyExchangeState.Pending);

            byte[]? peerDhKey = peerInitialMessageProto.InitialDhPublicKey.ToByteArray();
            Debug.WriteLine($"[ShieldPro] Peer Initial DH Public Key: {Convert.ToHexString(peerDhKey)}");

            Result<Unit, ShieldFailure> finalizeResult =
                _connectSession.FinalizeChainAndDhKeys(rootKeyBytes, peerDhKey);
            if (!finalizeResult.IsOk)
            {
                throw new ShieldChainStepException($"Failed to finalize chain keys: {finalizeResult.UnwrapErr()}");
            }

            Result<Unit, ShieldFailure> stateResult = _connectSession.SetConnectionState(PubKeyExchangeState.Complete);
            if (!stateResult.IsOk)
            {
                throw new ShieldChainStepException($"Failed to set Complete state: {stateResult.UnwrapErr()}");
            }

            SodiumInterop.SecureWipe(rootKeyBytes);

            Result<byte[]?, ShieldFailure> dhPublicKeyResult = _connectSession.GetCurrentSenderDhPublicKey();
            if (!dhPublicKeyResult.IsOk)
            {
                throw new ShieldChainStepException($"Failed to get sender DH key: {dhPublicKeyResult.UnwrapErr()}");
            }

            byte[]? dhPublicKey = dhPublicKeyResult.Unwrap();

            Debug.WriteLine($"[ShieldPro] Sender DH Public Key: {Convert.ToHexString(dhPublicKey)}");
            PubKeyExchange pubKeyExchange = new()
            {
                State = PubKeyExchangeState.Pending,
                OfType = exchangeType,
                Payload = protoBundle.ToByteString(),
                InitialDhPublicKey = ByteString.CopyFrom(dhPublicKey)
            };

            return pubKeyExchange;
        }
        catch
        {
            Debug.WriteLine($"[ShieldPro] Error in ProcessAndRespondToPubKeyExchangeAsync for session {connectId}.");
            throw;
        }
        finally
        {
            rootKeyHandle?.Dispose();
        }
    }

    public SodiumSecureMemoryHandle CompleteDataCenterPubKeyExchangeAsync(
        uint sessionId, PubKeyExchangeType exchangeType, PubKeyExchange peerMessage)
    {
        Debug.WriteLine($"[ShieldPro] Completing exchange for session {sessionId} ({exchangeType}).");

        PublicKeyBundle peerBundleProto = Helpers.ParseFromBytes<PublicKeyBundle>(peerMessage.Payload.ToByteArray());
        Result<LocalPublicKeyBundle, ShieldFailure> peerBundleResult =
            LocalPublicKeyBundle.FromProtobufExchange(peerBundleProto);
        if (!peerBundleResult.IsOk)
        {
            throw new ShieldChainStepException($"Failed to convert peer bundle: {peerBundleResult.UnwrapErr()}");
        }

        LocalPublicKeyBundle peerBundle = peerBundleResult.Unwrap();

        Debug.WriteLine("[ShieldPro] Verifying remote SPK signature for completion.");
        Result<bool, ShieldFailure> spkValidResult = EcliptixSystemIdentityKeys.VerifyRemoteSpkSignature(
            peerBundle.IdentityEd25519,
            peerBundle.SignedPreKeyPublic,
            peerBundle.SignedPreKeySignature);
        if (!spkValidResult.IsOk || !spkValidResult.Unwrap())
        {
            throw new ShieldChainStepException(
                $"SPK signature validation failed: {(spkValidResult.IsOk ? "Invalid signature" : spkValidResult.UnwrapErr())}");
        }

        Debug.WriteLine("[ShieldPro] Deriving X3DH shared secret.");
        Result<SodiumSecureMemoryHandle, ShieldFailure> deriveResult =
            _ecliptixSystemIdentityKeys.X3dhDeriveSharedSecret(peerBundle, X3dhInfo);
        if (!deriveResult.IsOk)
        {
            throw new ShieldChainStepException($"Shared secret derivation failed: {deriveResult.UnwrapErr()}");
        }

        SodiumSecureMemoryHandle rootKeyHandle = deriveResult.Unwrap();

        byte[] rootKeyBytes = new byte[Constants.X25519KeySize];
        rootKeyHandle.Read(rootKeyBytes.AsSpan());
        Debug.WriteLine($"[ShieldPro] Derived Root Key: {Convert.ToHexString(rootKeyBytes)}");

        Result<Unit, ShieldFailure> finalizeResult =
            _connectSession.FinalizeChainAndDhKeys(rootKeyBytes, peerMessage.InitialDhPublicKey.ToByteArray());
        if (!finalizeResult.IsOk)
        {
            throw new ShieldChainStepException($"Failed to finalize chain keys: {finalizeResult.UnwrapErr()}");
        }

        _connectSession.SetPeerBundle(peerBundle);
        Result<Unit, ShieldFailure> stateResult = _connectSession.SetConnectionState(PubKeyExchangeState.Complete);
        if (!stateResult.IsOk)
        {
            throw new ShieldChainStepException($"Failed to set Complete state: {stateResult.UnwrapErr()}");
        }

        SodiumInterop.SecureWipe(rootKeyBytes);
        return rootKeyHandle;
    }

    public CipherPayload ProduceOutboundMessageAsync(
        uint connectId, PubKeyExchangeType exchangeType, byte[] plainPayload)
    {
        Debug.WriteLine($"[ShieldPro] Producing outbound message for session {connectId} ({exchangeType}).");

        byte[]? ciphertext = null;
        byte[]? tag = null;

        ShieldMessageKey? messageKeyClone = null;

        try
        {
            Debug.WriteLine("[ShieldPro] Preparing next send message.");
            Result<(ShieldMessageKey MessageKey, bool IncludeDhKey), ShieldFailure> prepResult =
                _connectSession.PrepareNextSendMessage();
            if (!prepResult.IsOk)
            {
                throw new ShieldChainStepException(
                    $"Failed to prepare outgoing message key: {prepResult.UnwrapErr()}");
            }

            (ShieldMessageKey messageKey, bool includeDhKey) = prepResult.Unwrap();

            Result<byte[], ShieldFailure> nonceResult = _connectSession.GenerateNextNonce();
            if (!nonceResult.IsOk)
            {
                throw new ShieldChainStepException($"Failed to generate nonce: {nonceResult.UnwrapErr()}");
            }

            byte[] nonce = nonceResult.Unwrap();

            Debug.WriteLine($"[ShieldPro][Encrypt] Nonce: {Convert.ToHexString(nonce)}");
            Debug.WriteLine($"[ShieldPro][Encrypt] Plaintext: {Convert.ToHexString(plainPayload)}");

            byte[]? newSenderDhPublicKey = includeDhKey
                ? _connectSession.GetCurrentSenderDhPublicKey().Match(ok => ok,
                    err => throw new ShieldChainStepException($"Failed to get sender DH key: {err.Message}"))
                : null;
            if (newSenderDhPublicKey != null)
            {
                Debug.WriteLine(
                    $"[ShieldPro] Including new DH Public Key: {Convert.ToHexString(newSenderDhPublicKey)}");
            }

            byte[] messageKeyBytes = new byte[Constants.AesKeySize];
            messageKey.ReadKeyMaterial(messageKeyBytes);
            Debug.WriteLine($"[ShieldPro][Encrypt] Message Key: {Convert.ToHexString(messageKeyBytes)}");

            Result<ShieldMessageKey, ShieldFailure> cloneResult =
                ShieldMessageKey.New(messageKey.Index, messageKeyBytes);
            if (!cloneResult.IsOk)
            {
                throw new ShieldChainStepException($"Failed to clone message key: {cloneResult.UnwrapErr()}");
            }

            messageKeyClone = cloneResult.Unwrap();

            SodiumInterop.SecureWipe(messageKeyBytes);

            Result<LocalPublicKeyBundle, ShieldFailure> peerBundleResult = _connectSession.GetPeerBundle();
            if (!peerBundleResult.IsOk)
            {
                throw new ShieldChainStepException($"Failed to get peer bundle: {peerBundleResult.UnwrapErr()}");
            }

            LocalPublicKeyBundle peerBundle = peerBundleResult.Unwrap();

            byte[] localId = _ecliptixSystemIdentityKeys.IdentityX25519PublicKey;
            byte[] peerId = peerBundle.IdentityX25519;
            byte[] ad = new byte[localId.Length + peerId.Length];
            Buffer.BlockCopy(localId, 0, ad, 0, localId.Length);
            Buffer.BlockCopy(peerId, 0, ad, localId.Length, peerId.Length);
            Debug.WriteLine($"[ShieldPro][Encrypt] Associated Data: {Convert.ToHexString(ad)}");

            byte[] clonedKeyMaterial = new byte[Constants.AesKeySize];
            try
            {
                messageKeyClone.ReadKeyMaterial(clonedKeyMaterial);
                (ciphertext, tag) = AesGcmService.EncryptAllocating(clonedKeyMaterial, nonce, plainPayload, ad);
                Debug.WriteLine($"[ShieldPro][Encrypt] Ciphertext: {Convert.ToHexString(ciphertext)}");
                Debug.WriteLine($"[ShieldPro][Encrypt] Tag: {Convert.ToHexString(tag)}");
            }
            finally
            {
                SodiumInterop.SecureWipe(clonedKeyMaterial);
            }

            byte[] ciphertextAndTag = new byte[ciphertext.Length + tag.Length];
            Buffer.BlockCopy(ciphertext, 0, ciphertextAndTag, 0, ciphertext.Length);
            Buffer.BlockCopy(tag, 0, ciphertextAndTag, ciphertext.Length, tag.Length);
            Debug.WriteLine($"[ShieldPro][Encrypt] Ciphertext+Tag: {Convert.ToHexString(ciphertextAndTag)}");

            CipherPayload payload = new()
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

            Debug.WriteLine($"[ShieldPro] Outbound message prepared with Ratchet Index: {messageKeyClone.Index}");
            return payload;
        }
        finally
        {
            messageKeyClone?.Dispose();
            SodiumInterop.SecureWipe(ciphertext);
            SodiumInterop.SecureWipe(tag);
        }
    }

    public byte[] ProcessInboundMessageAsync(
        uint sessionId, PubKeyExchangeType exchangeType, CipherPayload cipherPayloadProto)
    {
        Debug.WriteLine(
            $"[ShieldPro] Processing inbound message for session {sessionId} ({exchangeType}), Ratchet Index: {cipherPayloadProto.RatchetIndex}");

        byte[]? messageKeyBytes = null;
        byte[]? plaintext = null;
        ShieldMessageKey? messageKeyClone = null;
        try
        {
            byte[]? receivedDhKey = cipherPayloadProto.DhPublicKey.Length > 0
                ? cipherPayloadProto.DhPublicKey.ToByteArray()
                : null;
            if (receivedDhKey != null)
            {
                Result<byte[]?, ShieldFailure> currentPeerDhResult = _connectSession.GetCurrentPeerDhPublicKey();
                if (currentPeerDhResult.IsOk)
                {
                    byte[] currentPeerDh = currentPeerDhResult.Unwrap();
                    Debug.WriteLine($"[ShieldPro][Decrypt] Received DH Key: {Convert.ToHexString(receivedDhKey)}");
                    Debug.WriteLine(
                        $"[ShieldPro][Decrypt] Current Peer DH Key: {Convert.ToHexString(currentPeerDh)}");
                    if (!receivedDhKey.SequenceEqual(currentPeerDh))
                    {
                        Debug.WriteLine("[ShieldPro] Performing DH ratchet due to new peer DH key.");
                        var ratchetResult = _connectSession.PerformReceivingRatchet(receivedDhKey);
                        if (!ratchetResult.IsOk)
                            throw new ShieldChainStepException(
                                $"Failed to perform DH ratchet: {ratchetResult.UnwrapErr()}");
                    }
                }
            }

            Debug.WriteLine(
                $"[ShieldPro][Decrypt] Ciphertext+Tag: {Convert.ToHexString(cipherPayloadProto.Cipher.ToByteArray())}");
            Debug.WriteLine(
                $"[ShieldPro][Decrypt] Nonce: {Convert.ToHexString(cipherPayloadProto.Nonce.ToByteArray())}");

            Result<ShieldMessageKey, ShieldFailure> messageKeyResult =
                _connectSession.ProcessReceivedMessage(cipherPayloadProto.RatchetIndex, receivedDhKey);
            if (!messageKeyResult.IsOk)
            {
                throw new ShieldChainStepException($"Failed to process message: {messageKeyResult.UnwrapErr()}");
            }

            ShieldMessageKey originalMessageKey = messageKeyResult.Unwrap();

            messageKeyBytes = new byte[Constants.AesKeySize];
            originalMessageKey.ReadKeyMaterial(messageKeyBytes);
            Debug.WriteLine($"[ShieldPro][Decrypt] Message Key: {Convert.ToHexString(messageKeyBytes)}");

            var cloneResult = ShieldMessageKey.New(originalMessageKey.Index, messageKeyBytes);
            if (!cloneResult.IsOk)
                throw new ShieldChainStepException(
                    $"Failed to clone message key for decryption: {cloneResult.UnwrapErr()}");
            messageKeyClone = cloneResult.Unwrap();

            Debug.WriteLine($"[ShieldPro] Processed Key Index: {messageKeyClone.Index}");

            Result<LocalPublicKeyBundle, ShieldFailure> peerBundleResult = _connectSession.GetPeerBundle();
            if (!peerBundleResult.IsOk)
                throw new ShieldChainStepException($"Failed to get peer bundle: {peerBundleResult.UnwrapErr()}");
            LocalPublicKeyBundle peerBundle = peerBundleResult.Unwrap();

            byte[] senderId = peerBundle.IdentityX25519;
            byte[] receiverId = _ecliptixSystemIdentityKeys.IdentityX25519PublicKey;
            byte[] ad = new byte[senderId.Length + receiverId.Length];
            Buffer.BlockCopy(senderId, 0, ad, 0, senderId.Length);
            Buffer.BlockCopy(receiverId, 0, ad, senderId.Length, receiverId.Length);
            Debug.WriteLine($"[ShieldPro][Decrypt] Associated Data: {Convert.ToHexString(ad)}");

            byte[] clonedKeyMaterial = new byte[Constants.AesKeySize];
            try
            {
                messageKeyClone.ReadKeyMaterial(clonedKeyMaterial);
                Debug.WriteLine($"[ShieldPro][Decrypt] Decryption Key: {Convert.ToHexString(clonedKeyMaterial)}");

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
                Debug.WriteLine($"[ShieldPro][Decrypt] Plaintext: {Convert.ToHexString(plaintext)}");

                byte[] plaintextCopy = (byte[])plaintext.Clone();
                Debug.WriteLine(
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
    }
}
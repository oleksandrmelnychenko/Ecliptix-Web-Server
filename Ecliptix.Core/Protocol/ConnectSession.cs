using System.Buffers;
using System.Buffers.Binary;
using System.Diagnostics;
using System.Security.Cryptography;
using Ecliptix.Core.Protocol.Utilities;
using Ecliptix.Protobuf.PubKeyExchange;
using Sodium;

namespace Ecliptix.Core.Protocol;

public sealed class ConnectSession : IDisposable
{
    private const int DhRotationInterval = 10;
    private static readonly TimeSpan SessionTimeout = TimeSpan.FromHours(24);
    private static readonly byte[] InitialSenderChainInfo = "ShieldInitSend"u8.ToArray();
    private static readonly byte[] InitialReceiverChainInfo = "ShieldInitRecv"u8.ToArray();
    private static readonly byte[] DhRatchetInfo = "ShieldDhRatchet"u8.ToArray();
    private const int AesGcmNonceSize = 12;

    private readonly uint _id;
    private LocalPublicKeyBundle? _peerBundle;
    private readonly ShieldChainStep? _sendingStep;
    private ShieldChainStep? _receivingStep;
    private SodiumSecureMemoryHandle? _rootKeyHandle;
    private readonly SortedDictionary<uint, ShieldMessageKey> _messageKeys;
    private PubKeyExchangeState _state;
    private ulong _nonceCounter;
    private readonly DateTimeOffset _createdAt;
    private byte[]? _peerDhPublicKey;
    private readonly bool _isInitiator;
    private bool _receivedNewDhKey;
    private SodiumSecureMemoryHandle? _persistentDhPrivateKeyHandle;
    private byte[]? _persistentDhPublicKey;
    private SodiumSecureMemoryHandle? _initialSendingDhPrivateKeyHandle;
    private SodiumSecureMemoryHandle? _currentSendingDhPrivateKeyHandle;
    private volatile bool _disposed;
    private readonly bool _isFirstReceivingRatchet;

    private ConnectSession(
        uint id,
        bool isInitiator,
        SodiumSecureMemoryHandle initialSendingDhPrivateKeyHandle,
        ShieldChainStep sendingStep,
        SodiumSecureMemoryHandle persistentDhPrivateKeyHandle,
        byte[] persistentDhPublicKey)
    {
        _id = id;
        _isInitiator = isInitiator;
        _initialSendingDhPrivateKeyHandle = initialSendingDhPrivateKeyHandle;
        _currentSendingDhPrivateKeyHandle = initialSendingDhPrivateKeyHandle;
        _sendingStep = sendingStep;
        _persistentDhPrivateKeyHandle = persistentDhPrivateKeyHandle;
        _persistentDhPublicKey = persistentDhPublicKey;
        _peerBundle = null;
        _receivingStep = null;
        _rootKeyHandle = null;
        _messageKeys = new SortedDictionary<uint, ShieldMessageKey>();
        _state = PubKeyExchangeState.Init;
        _nonceCounter = 0;
        _createdAt = DateTimeOffset.UtcNow;
        _peerDhPublicKey = null;
        _receivedNewDhKey = false;
        _disposed = false;
        _isFirstReceivingRatchet = true;
        Debug.WriteLine($"[ShieldSession] Created session {id}, Initiator: {isInitiator}");
    }

    public static Result<ConnectSession, ShieldFailure> Create(uint connectId, LocalPublicKeyBundle localBundle,
        bool isInitiator)
    {
        SodiumSecureMemoryHandle? initialSendingDhPrivateKeyHandle = null;
        byte[]? initialSendingDhPublicKey = null;
        byte[]? initialSendingDhPrivateKeyBytes = null;
        ShieldChainStep? sendingStep = null;
        SodiumSecureMemoryHandle? persistentDhPrivateKeyHandle = null;
        byte[]? persistentDhPublicKey = null;

        try
        {
            Debug.WriteLine($"[ShieldSession] Creating session {connectId}, Initiator: {isInitiator}");
            Result<ConnectSession, ShieldFailure> overallResult = GenerateX25519KeyPair("Initial Sending DH")
                .Bind(initialSendKeys =>
                {
                    (initialSendingDhPrivateKeyHandle, initialSendingDhPublicKey) = initialSendKeys;
                    Debug.WriteLine(
                        $"[ShieldSession] Generated Initial Sending DH Public Key: {Convert.ToHexString(initialSendingDhPublicKey)}");
                    return initialSendingDhPrivateKeyHandle.ReadBytes(Constants.X25519PrivateKeySize)
                        .Map(bytes =>
                        {
                            initialSendingDhPrivateKeyBytes = bytes;
                            Debug.WriteLine(
                                $"[ShieldSession] Initial Sending DH Private Key: {Convert.ToHexString(initialSendingDhPrivateKeyBytes)}");
                            return Unit.Value;
                        });
                })
                .Bind(_ => GenerateX25519KeyPair("Persistent DH"))
                .Bind(persistentKeys =>
                {
                    (persistentDhPrivateKeyHandle, persistentDhPublicKey) = persistentKeys;
                    Debug.WriteLine(
                        $"[ShieldSession] Generated Persistent DH Public Key: {Convert.ToHexString(persistentDhPublicKey)}");
                    byte[] tempChainKey = new byte[Constants.X25519KeySize];
                    Result<ShieldChainStep, ShieldFailure> stepResult = ShieldChainStep.Create(
                        ChainStepType.Sender,
                        tempChainKey,
                        initialSendingDhPrivateKeyBytes,
                        initialSendingDhPublicKey);
                    SodiumInterop.SecureWipe(tempChainKey).IgnoreResult();
                    WipeIfNotNull(initialSendingDhPrivateKeyBytes).IgnoreResult();
                    initialSendingDhPrivateKeyBytes = null;
                    return stepResult;
                })
                .Bind(createdSendingStep =>
                {
                    sendingStep = createdSendingStep;
                    Debug.WriteLine($"[ShieldSession] Sending step created for session {connectId}");
                    ConnectSession session = new ConnectSession(
                        connectId,
                        isInitiator,
                        initialSendingDhPrivateKeyHandle!,
                        sendingStep,
                        persistentDhPrivateKeyHandle!,
                        persistentDhPublicKey!);
                    initialSendingDhPrivateKeyHandle = null;
                    persistentDhPrivateKeyHandle = null;
                    sendingStep = null;
                    return Result<ConnectSession, ShieldFailure>.Ok(session);
                });

            if (overallResult.IsErr)
            {
                Debug.WriteLine(
                    $"[ShieldSession] Failed to create session {connectId}: {overallResult.UnwrapErr().Message}");
                initialSendingDhPrivateKeyHandle?.Dispose();
                sendingStep?.Dispose();
                persistentDhPrivateKeyHandle?.Dispose();
                WipeIfNotNull(initialSendingDhPrivateKeyBytes).IgnoreResult();
            }

            return overallResult;
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"[ShieldSession] Unexpected error creating session {connectId}: {ex.Message}");
            initialSendingDhPrivateKeyHandle?.Dispose();
            sendingStep?.Dispose();
            persistentDhPrivateKeyHandle?.Dispose();
            WipeIfNotNull(initialSendingDhPrivateKeyBytes).IgnoreResult();
            return Result<ConnectSession, ShieldFailure>.Err(
                ShieldFailure.Generic($"Unexpected error creating session {connectId}.", ex));
        }
    }

    private static Result<(SodiumSecureMemoryHandle skHandle, byte[] pk), ShieldFailure> GenerateX25519KeyPair(
        string keyPurpose)
    {
        SodiumSecureMemoryHandle? skHandle = null;
        byte[]? skBytes = null;
        byte[]? tempPrivCopy = null;
        try
        {
            Debug.WriteLine($"[ShieldSession] Generating X25519 key pair for {keyPurpose}");
            Result<SodiumSecureMemoryHandle, ShieldFailure> allocResult =
                SodiumSecureMemoryHandle.Allocate(Constants.X25519PrivateKeySize);
            if (allocResult.IsErr)
            {
                return Result<(SodiumSecureMemoryHandle, byte[]), ShieldFailure>.Err(allocResult.UnwrapErr());
            }
            
            skHandle = allocResult.Unwrap();
            skBytes = SodiumCore.GetRandomBytes(Constants.X25519PrivateKeySize);
            Result<Unit, ShieldFailure> writeResult = skHandle.Write(skBytes);
            if (writeResult.IsErr)
            {
                skHandle.Dispose();
                return Result<(SodiumSecureMemoryHandle, byte[]), ShieldFailure>.Err(writeResult.UnwrapErr());
            }

            SodiumInterop.SecureWipe(skBytes).IgnoreResult();
            skBytes = null;
            tempPrivCopy = new byte[Constants.X25519PrivateKeySize];
            Result<Unit, ShieldFailure> readResult = skHandle.Read(tempPrivCopy);
            if (readResult.IsErr)
            {
                skHandle.Dispose();
                SodiumInterop.SecureWipe(tempPrivCopy).IgnoreResult();
                return Result<(SodiumSecureMemoryHandle, byte[]), ShieldFailure>.Err(readResult.UnwrapErr());
            }

            Result<byte[], ShieldFailure> deriveResult = Result<byte[], ShieldFailure>.Try(
                () => ScalarMult.Base(tempPrivCopy),
                ex => ShieldFailure.Generic($"Failed to derive {keyPurpose} public key.", ex));
            SodiumInterop.SecureWipe(tempPrivCopy).IgnoreResult();
            tempPrivCopy = null;
            if (deriveResult.IsErr)
            {
                skHandle.Dispose();
                return Result<(SodiumSecureMemoryHandle, byte[]), ShieldFailure>.Err(deriveResult.UnwrapErr());
            }

            byte[] pkBytes = deriveResult.Unwrap();
            if (pkBytes.Length != Constants.X25519PublicKeySize)
            {
                skHandle.Dispose();
                SodiumInterop.SecureWipe(pkBytes).IgnoreResult();
                return Result<(SodiumSecureMemoryHandle, byte[]), ShieldFailure>.Err(
                    ShieldFailure.Generic($"Derived {keyPurpose} public key has incorrect size."));
            }

            Debug.WriteLine($"[ShieldSession] Generated {keyPurpose} Public Key: {Convert.ToHexString(pkBytes)}");
            return Result<(SodiumSecureMemoryHandle, byte[]), ShieldFailure>.Ok((skHandle, pkBytes));
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"[ShieldSession] Error generating {keyPurpose} key pair: {ex.Message}");
            skHandle?.Dispose();
            if (skBytes != null) SodiumInterop.SecureWipe(skBytes).IgnoreResult();
            if (tempPrivCopy != null) SodiumInterop.SecureWipe(tempPrivCopy).IgnoreResult();
            return Result<(SodiumSecureMemoryHandle, byte[]), ShieldFailure>.Err(
                ShieldFailure.Generic($"Unexpected error generating {keyPurpose} key pair.", ex));
        }
    }

    public Result<LocalPublicKeyBundle, ShieldFailure> GetPeerBundle() =>
        CheckDisposed().Bind(_ =>
            _peerBundle != null
                ? Result<LocalPublicKeyBundle, ShieldFailure>.Ok(_peerBundle)
                : Result<LocalPublicKeyBundle, ShieldFailure>.Err(
                    ShieldFailure.Generic("Peer bundle has not been set.")));

    public Result<bool, ShieldFailure> GetIsInitiator() =>
        CheckDisposed().Map(_ => _isInitiator);

    internal Result<Unit, ShieldFailure> SetConnectionState(PubKeyExchangeState newState) =>
        CheckDisposed().Map(u =>
        {
            Debug.WriteLine($"[ShieldSession] Setting state for session {_id} to {newState}");
            _state = newState;
            return u;
        });

    internal void SetPeerBundle(LocalPublicKeyBundle peerBundle)
    {
        if (peerBundle == null)
        {
            throw new ArgumentNullException(nameof(peerBundle));
        }
        
        Debug.WriteLine($"[ShieldSession] Setting peer bundle for session {_id}");
        _peerBundle = peerBundle;
    }

    internal Result<Unit, ShieldFailure> FinalizeChainAndDhKeys(byte[] initialRootKey, byte[] initialPeerDhPublicKey)
    {
        SodiumSecureMemoryHandle? tempRootHandle = null;
        ShieldChainStep? tempReceivingStep = null;
        byte[]? initialRootKeyCopy = null;
        byte[]? localSenderCk = null;
        byte[]? localReceiverCk = null;
        byte[]? peerDhPublicCopy = null;
        byte[]? persistentPrivKeyBytes = null;

        try
        {
            Debug.WriteLine($"[ShieldSession] Finalizing chain and DH keys for session {_id}");
            return CheckDisposed()
                .Bind(_ => CheckIfNotFinalized())
                .Bind(_ => ValidateInitialKeys(initialRootKey, initialPeerDhPublicKey))
                .Bind(_ =>
                {
                    initialRootKeyCopy = (byte[])initialRootKey.Clone();
                    peerDhPublicCopy = (byte[])initialPeerDhPublicKey.Clone();
                    Debug.WriteLine($"[ShieldSession] Initial Root Key: {Convert.ToHexString(initialRootKeyCopy)}");
                    Debug.WriteLine(
                        $"[ShieldSession] Initial Peer DH Public Key: {Convert.ToHexString(peerDhPublicCopy)}");
                    return SodiumSecureMemoryHandle.Allocate(Constants.X25519KeySize).Bind(handle =>
                    {
                        tempRootHandle = handle;
                        return handle.Write(initialRootKeyCopy);
                    });
                })
                .Bind(_ => DeriveInitialChainKeys(initialRootKeyCopy!))
                .Bind(derivedKeys =>
                {
                    (localSenderCk, localReceiverCk) = derivedKeys;
                    Debug.WriteLine($"[ShieldSession] Local Sender Chain Key: {Convert.ToHexString(localSenderCk)}");
                    Debug.WriteLine(
                        $"[ShieldSession] Local Receiver Chain Key: {Convert.ToHexString(localReceiverCk)}");
                    return _persistentDhPrivateKeyHandle!.ReadBytes(Constants.X25519PrivateKeySize)
                        .Map(bytes =>
                        {
                            persistentPrivKeyBytes = bytes;
                            Debug.WriteLine(
                                $"[ShieldSession] Persistent DH Private Key: {Convert.ToHexString(persistentPrivKeyBytes)}");
                            return Unit.Value;
                        });
                })
                .Bind(_ => _sendingStep!.UpdateKeysAfterDhRatchet(localSenderCk!))
                .Bind(_ => ShieldChainStep.Create(ChainStepType.Receiver, localReceiverCk!, persistentPrivKeyBytes,
                    _persistentDhPublicKey))
                .Map(receivingStep =>
                {
                    _rootKeyHandle = tempRootHandle;
                    tempRootHandle = null;
                    _receivingStep = receivingStep;
                    tempReceivingStep = null;
                    _peerDhPublicKey = peerDhPublicCopy;
                    peerDhPublicCopy = null;
                    Debug.WriteLine($"[ShieldSession] Chain and DH keys finalized for session {_id}");
                    return Unit.Value;
                })
                .MapErr(err =>
                {
                    Debug.WriteLine($"[ShieldSession] Error finalizing chain and DH keys: {err.Message}");
                    tempRootHandle?.Dispose();
                    tempReceivingStep?.Dispose();
                    return err;
                });
        }
        finally
        {
            WipeIfNotNull(initialRootKeyCopy).IgnoreResult();
            WipeIfNotNull(localSenderCk).IgnoreResult();
            WipeIfNotNull(localReceiverCk).IgnoreResult();
            WipeIfNotNull(peerDhPublicCopy).IgnoreResult();
            WipeIfNotNull(persistentPrivKeyBytes).IgnoreResult();
            tempRootHandle?.Dispose();
            tempReceivingStep?.Dispose();
        }
    }

    private Result<Unit, ShieldFailure> CheckIfNotFinalized() =>
        CheckDisposed().Bind(_ =>
            (_rootKeyHandle != null || _receivingStep != null)
                ? Result<Unit, ShieldFailure>.Err(ShieldFailure.Generic("Session has already been finalized."))
                : Result<Unit, ShieldFailure>.Ok(Unit.Value));

    private static Result<Unit, ShieldFailure> ValidateInitialKeys(byte[] rootKey, byte[] peerDhKey)
    {
        if (rootKey.Length != Constants.X25519KeySize)
        {
            return Result<Unit, ShieldFailure>.Err(
                ShieldFailure.InvalidInput($"Initial root key must be {Constants.X25519KeySize} bytes."));
        }

        if (peerDhKey.Length != Constants.X25519PublicKeySize)
        {
            return Result<Unit, ShieldFailure>.Err(
                ShieldFailure.InvalidInput(
                    $"Initial peer DH public key must be {Constants.X25519PublicKeySize} bytes."));
        }

        return Result<Unit, ShieldFailure>.Ok(Unit.Value);
    }

    private Result<(byte[] senderCk, byte[] receiverCk), ShieldFailure> DeriveInitialChainKeys(byte[] rootKey)
    {
        byte[]? initiatorSenderChainKey = null;
        byte[]? responderSenderChainKey = null;
        try
        {
            Debug.WriteLine(
                $"[ShieldSession] Deriving initial chain keys from root key: {Convert.ToHexString(rootKey)}");
            return Result<(byte[], byte[]), ShieldFailure>.Try(() =>
            {
                Span<byte> sendSpan = stackalloc byte[Constants.X25519KeySize];
                Span<byte> recvSpan = stackalloc byte[Constants.X25519KeySize];
                using (HkdfSha256 hkdfSend = new(rootKey, null))
                {
                    hkdfSend.Expand(InitialSenderChainInfo, sendSpan);
                }

                using (HkdfSha256 hkdfRecv = new(rootKey, null))
                {
                    hkdfRecv.Expand(InitialReceiverChainInfo, recvSpan);
                }

                initiatorSenderChainKey = sendSpan.ToArray();
                responderSenderChainKey = recvSpan.ToArray();
                byte[] localSenderCk = _isInitiator ? initiatorSenderChainKey : responderSenderChainKey;
                byte[] localReceiverCk = _isInitiator ? responderSenderChainKey : initiatorSenderChainKey;
                initiatorSenderChainKey = null;
                responderSenderChainKey = null;
                return (localSenderCk, localReceiverCk);
            }, ex => ShieldFailure.DeriveKey("Failed to derive initial chain keys.", ex));
        }
        finally
        {
            WipeIfNotNull(initiatorSenderChainKey).IgnoreResult();
            WipeIfNotNull(responderSenderChainKey).IgnoreResult();
        }
    }

    internal Result<(ShieldMessageKey MessageKey, bool IncludeDhKey), ShieldFailure> PrepareNextSendMessage()
    {
        ShieldChainStep? sendingStepLocal = null;
        ShieldMessageKey? messageKey;
        ShieldMessageKey? clonedMessageKey;
        byte[]? keyMaterial = null;
        bool includeDhKey = false;

        try
        {
            Debug.WriteLine($"[ShieldSession] Preparing next send message for session {_id}");
            return CheckDisposed()
                .Bind(_ => EnsureNotExpired())
                .Bind(_ => EnsureSendingStepInitialized())
                .Bind(step =>
                {
                    sendingStepLocal = step;
                    return MaybePerformSendingDhRatchet(sendingStepLocal);
                })
                .Bind(ratchetInfo =>
                {
                    includeDhKey = ratchetInfo.performedRatchet;
                    Debug.WriteLine($"[ShieldSession] DH Ratchet performed: {includeDhKey}");
                    return sendingStepLocal!.GetCurrentIndex()
                        .Map(currentIndex =>
                        {
                            uint nextIndex = currentIndex + 1;
                            Debug.WriteLine($"[ShieldSession] Preparing message for next index: {nextIndex}");
                            return nextIndex;
                        });
                })
                .Bind(nextIndex => sendingStepLocal!.GetOrDeriveKeyFor(nextIndex, _messageKeys)
                    .Bind(derivedKey =>
                    {
                        messageKey = derivedKey;
                        return sendingStepLocal!.SetCurrentIndex(nextIndex)
                            .Map(_ => messageKey);
                    }))
                .Bind(originalKey =>
                {
                    keyMaterial = new byte[Constants.AesKeySize];
                    return originalKey.ReadKeyMaterial(keyMaterial)
                        .Bind(_ => ShieldMessageKey.New(originalKey.Index, keyMaterial))
                        .Map(clone =>
                        {
                            clonedMessageKey = clone;
                            Debug.WriteLine($"[ShieldSession] Derived message key for index: {clonedMessageKey.Index}");
                            sendingStepLocal!.PruneOldKeys(_messageKeys);
                            return (clonedMessageKey, includeDhKey);
                        });
                });
        }
        finally
        {
            WipeIfNotNull(keyMaterial).IgnoreResult();
        }
    }

    internal Result<ShieldMessageKey, ShieldFailure> ProcessReceivedMessage(uint receivedIndex,
        byte[]? receivedDhPublicKeyBytes)
    {
        ShieldChainStep? receivingStepLocal = null;
        byte[]? peerDhPublicCopy = null;
        ShieldMessageKey? messageKey;

        try
        {
            Debug.WriteLine($"[ShieldSession] Processing received message for session {_id}, Index: {receivedIndex}");
            if (receivedDhPublicKeyBytes != null)
            {
                peerDhPublicCopy = (byte[])receivedDhPublicKeyBytes.Clone();
                Debug.WriteLine($"[ShieldSession] Received DH Public Key: {Convert.ToHexString(peerDhPublicCopy)}");
            }

            return CheckDisposed()
                .Bind(_ => EnsureNotExpired())
                .Bind(_ => EnsureReceivingStepInitialized())
                .Bind(step =>
                {
                    receivingStepLocal = step;
                    return MaybePerformReceivingDhRatchet(step, peerDhPublicCopy);
                })
                .Bind(_ => receivingStepLocal!.GetOrDeriveKeyFor(receivedIndex, _messageKeys))
                .Bind(derivedKey =>
                {
                    messageKey = derivedKey;
                    Debug.WriteLine($"[ShieldSession] Derived message key for received index: {receivedIndex}");
                    return receivingStepLocal!.SetCurrentIndex(messageKey.Index)
                        .Map(_ => messageKey);
                })
                .Map(finalKey =>
                {
                    receivingStepLocal!.PruneOldKeys(_messageKeys);
                    return finalKey;
                });
        }
        finally
        {
            WipeIfNotNull(peerDhPublicCopy).IgnoreResult();
        }
    }

    private Result<ShieldChainStep, ShieldFailure> EnsureSendingStepInitialized() =>
        CheckDisposed().Bind(_ =>
            _sendingStep != null
                ? Result<ShieldChainStep, ShieldFailure>.Ok(_sendingStep)
                : Result<ShieldChainStep, ShieldFailure>.Err(
                    ShieldFailure.Generic("Sending chain step not initialized.")));

    private Result<ShieldChainStep, ShieldFailure> EnsureReceivingStepInitialized() =>
        CheckDisposed().Bind(_ =>
            _receivingStep != null
                ? Result<ShieldChainStep, ShieldFailure>.Ok(_receivingStep)
                : Result<ShieldChainStep, ShieldFailure>.Err(
                    ShieldFailure.Generic("Receiving chain step not initialized.")));

    private Result<(bool performedRatchet, bool receivedNewKey), ShieldFailure> MaybePerformSendingDhRatchet(
        ShieldChainStep sendingStep)
    {
        return sendingStep.GetCurrentIndex().Bind(currentIndex =>
        {
            bool shouldRatchet = (currentIndex + 1) % DhRotationInterval == 0 || _receivedNewDhKey;
            bool currentReceivedNewDhKey = _receivedNewDhKey;
            Debug.WriteLine(
                $"[ShieldSession] Checking if DH ratchet needed. Current Index: {currentIndex}, Received New DH Key: {_receivedNewDhKey}, Should Ratchet: {shouldRatchet}");
            if (shouldRatchet)
            {
                return PerformDhRatchet(isSender: true)
                    .Map(_ =>
                    {
                        _receivedNewDhKey = false;
                        Debug.WriteLine("[ShieldSession] DH ratchet performed for sending.");
                        return (performedRatchet: true, receivedNewKey: currentReceivedNewDhKey);
                    });
            }

            return Result<(bool, bool), ShieldFailure>.Ok((false, currentReceivedNewDhKey));
        });
    }

    private Result<Unit, ShieldFailure> MaybePerformReceivingDhRatchet(ShieldChainStep receivingStep,
        byte[]? receivedDhPublicKeyBytes)
    {
        if (receivedDhPublicKeyBytes == null)
        {
            return Result<Unit, ShieldFailure>.Ok(Unit.Value);
        }

        bool keysDiffer = _peerDhPublicKey == null || !receivedDhPublicKeyBytes.SequenceEqual(_peerDhPublicKey);
        Debug.WriteLine(
            $"[ShieldSession] Checking DH key difference. Peer DH Key: {Convert.ToHexString(_peerDhPublicKey)}, Received: {Convert.ToHexString(receivedDhPublicKeyBytes)}");
        if (!keysDiffer)
        {
            return Result<Unit, ShieldFailure>.Ok(Unit.Value);
        }

        Result<uint, ShieldFailure> currentIndexResult = receivingStep.GetCurrentIndex();
        if (currentIndexResult.IsErr)
            return Result<Unit, ShieldFailure>.Err(currentIndexResult.UnwrapErr());
        uint currentIndex = currentIndexResult.Unwrap();
        bool shouldRatchet = _isFirstReceivingRatchet || (currentIndex + 1) % DhRotationInterval == 0;
        if (shouldRatchet)
        {
            return PerformDhRatchet(isSender: false, receivedDhPublicKeyBytes);
        }

        WipeIfNotNull(_peerDhPublicKey).IgnoreResult();
        _peerDhPublicKey = (byte[])receivedDhPublicKeyBytes.Clone();
        _receivedNewDhKey = true;
        Debug.WriteLine($"[ShieldSession] Deferred DH ratchet: New key received but waiting for interval.");
        return Result<Unit, ShieldFailure>.Ok(Unit.Value);
    }

    public Result<Unit, ShieldFailure> PerformReceivingRatchet(byte[] receivedDhKey)
    {
        Debug.WriteLine($"[ShieldSession] Performing receiving ratchet for session {_id}");
        return PerformDhRatchet(isSender: false, receivedDhPublicKeyBytes: receivedDhKey);
    }

    private Result<Unit, ShieldFailure> PerformDhRatchet(bool isSender, byte[]? receivedDhPublicKeyBytes = null)
    {
        byte[]? dhSecret = null;
        byte[]? currentRootKey = null;
        byte[]? newRootKey = null;
        byte[]? newChainKeyForTargetStep = null;
        byte[]? hkdfOutput = null;
        byte[]? localPrivateKeyBytes = null;
        SodiumSecureMemoryHandle? newEphemeralSkHandle = null;
        byte[]? newEphemeralPublicKey = null;

        try
        {
            Debug.WriteLine($"[ShieldSession] Performing DH ratchet for session {_id}, IsSender: {isSender}");
            Result<Unit, ShieldFailure> initialCheck = CheckDisposed().Bind(_ =>
                _rootKeyHandle is { IsInvalid: false }
                    ? Result<Unit, ShieldFailure>.Ok(Unit.Value)
                    : Result<Unit, ShieldFailure>.Err(
                        ShieldFailure.Generic("Root key handle not initialized or invalid.")));
            if (initialCheck.IsErr) return initialCheck;

            Result<byte[], ShieldFailure> dhResult;

            if (isSender)
            {
                if (_sendingStep == null)
                {
                    return Result<Unit, ShieldFailure>.Err(
                        ShieldFailure.Generic("Sending step not initialized for DH ratchet."));
                }

                if (_peerDhPublicKey == null)
                {
                    return Result<Unit, ShieldFailure>.Err(
                        ShieldFailure.Generic("Peer DH public key not available for sender DH ratchet."));
                }

                Result<(SodiumSecureMemoryHandle skHandle, byte[] pk), ShieldFailure> ephResult =
                    GenerateX25519KeyPair("Ephemeral DH Ratchet");
                if (ephResult.IsErr)
                {
                    return Result<Unit, ShieldFailure>.Err(ephResult.UnwrapErr());
                }

                (newEphemeralSkHandle, newEphemeralPublicKey) = ephResult.Unwrap();
                Debug.WriteLine(
                    $"[ShieldSession] New Ephemeral Public Key: {Convert.ToHexString(newEphemeralPublicKey)}");

                dhResult = newEphemeralSkHandle.ReadBytes(Constants.X25519PrivateKeySize)
                    .Bind(ephPrivBytes =>
                    {
                        localPrivateKeyBytes = ephPrivBytes;
                        Debug.WriteLine(
                            $"[ShieldSession] Ephemeral Private Key: {Convert.ToHexString(localPrivateKeyBytes)}");
                        return Result<byte[], ShieldFailure>.Try(
                            () => ScalarMult.Mult(localPrivateKeyBytes, _peerDhPublicKey),
                            ex => ShieldFailure.DeriveKey("Sender DH calculation failed.", ex));
                    });
            }
            else
            {
                if (_receivingStep == null)
                {
                    return Result<Unit, ShieldFailure>.Err(
                        ShieldFailure.Generic("Receiving step not initialized for DH ratchet."));
                }

                if (receivedDhPublicKeyBytes is not { Length: Constants.X25519PublicKeySize })
                {
                    return Result<Unit, ShieldFailure>.Err(
                        ShieldFailure.InvalidInput(
                            "Received DH public key is missing or invalid for receiver DH ratchet."));
                }

                Debug.WriteLine("[ShieldSession] Using current sending DH private key for receiver ratchet.");
                dhResult = _currentSendingDhPrivateKeyHandle!.ReadBytes(Constants.X25519PrivateKeySize)
                    .Bind(persistPrivBytes =>
                    {
                        localPrivateKeyBytes = persistPrivBytes;
                        Debug.WriteLine($"[ShieldSession] Private Key: {Convert.ToHexString(localPrivateKeyBytes)}");
                        return Result<byte[], ShieldFailure>.Try(
                            () => ScalarMult.Mult(localPrivateKeyBytes, receivedDhPublicKeyBytes),
                            ex => ShieldFailure.DeriveKey("Receiver DH calculation failed.", ex));
                    });
            }

            WipeIfNotNull(localPrivateKeyBytes).IgnoreResult();
            localPrivateKeyBytes = null;
            if (dhResult.IsErr)
            {
                newEphemeralSkHandle?.Dispose();
                return Result<Unit, ShieldFailure>.Err(dhResult.UnwrapErr());
            }

            dhSecret = dhResult.Unwrap();
            Debug.WriteLine($"[ShieldSession] DH Secret: {Convert.ToHexString(dhSecret)}");

            Result<Unit, ShieldFailure> finalResult = _rootKeyHandle!.ReadBytes(Constants.X25519KeySize)
                .Bind(rkBytes =>
                {
                    currentRootKey = rkBytes;
                    Debug.WriteLine($"[ShieldSession] Current Root Key: {Convert.ToHexString(currentRootKey)}");
                    hkdfOutput = new byte[Constants.X25519KeySize * 2];
                    return Result<Unit, ShieldFailure>.Try(() =>
                    {
                        using HkdfSha256 hkdf = new(dhSecret!, currentRootKey);
                        hkdf.Expand(DhRatchetInfo, hkdfOutput);
                    }, ex => ShieldFailure.DeriveKey("HKDF expansion failed during DH ratchet.", ex));
                })
                .Bind(_ =>
                {
                    newRootKey = hkdfOutput!.Take(Constants.X25519KeySize).ToArray();
                    newChainKeyForTargetStep = hkdfOutput!.Skip(Constants.X25519KeySize).Take(Constants.X25519KeySize)
                        .ToArray();
                    Debug.WriteLine($"[ShieldSession] New Root Key: {Convert.ToHexString(newRootKey)}");
                    Debug.WriteLine($"[ShieldSession] New Chain Key: {Convert.ToHexString(newChainKeyForTargetStep)}");
                    return _rootKeyHandle.Write(newRootKey);
                })
                .Bind(_ =>
                {
                    if (isSender)
                    {
                        Result<byte[], ShieldFailure> privateKeyResult =
                            newEphemeralSkHandle!.ReadBytes(Constants.X25519PrivateKeySize);
                        if (privateKeyResult.IsErr)
                            return Result<Unit, ShieldFailure>.Err(privateKeyResult.UnwrapErr());
                        byte[] newDhPrivateKeyBytes = privateKeyResult.Unwrap();
                        Debug.WriteLine("[ShieldSession] Updating sending step with new DH keys.");
                        _currentSendingDhPrivateKeyHandle?.Dispose();
                        _currentSendingDhPrivateKeyHandle = newEphemeralSkHandle;
                        newEphemeralSkHandle = null;
                        return _sendingStep!.UpdateKeysAfterDhRatchet(newChainKeyForTargetStep!, newDhPrivateKeyBytes,
                            newEphemeralPublicKey!);
                    }

                    Debug.WriteLine("[ShieldSession] Updating receiving step.");
                    return _receivingStep!.UpdateKeysAfterDhRatchet(newChainKeyForTargetStep!);
                })
                .Map(_ =>
                {
                    if (!isSender)
                    {
                        WipeIfNotNull(_peerDhPublicKey).IgnoreResult();
                        _peerDhPublicKey = (byte[])receivedDhPublicKeyBytes!.Clone();
                    }

                    _receivedNewDhKey = false;

                    ClearMessageKeyCache();
                    Debug.WriteLine("[ShieldSession] DH ratchet completed.");
                    return Unit.Value;
                })
                .MapErr(err =>
                {
                    Debug.WriteLine($"[ShieldSession] Error during DH ratchet: {err.Message}");
                    if (isSender) newEphemeralSkHandle?.Dispose();
                    return err;
                });

            return finalResult;
        }
        finally
        {
            WipeIfNotNull(dhSecret).IgnoreResult();
            WipeIfNotNull(currentRootKey).IgnoreResult();
            WipeIfNotNull(newRootKey).IgnoreResult();
            WipeIfNotNull(hkdfOutput).IgnoreResult();
            WipeIfNotNull(localPrivateKeyBytes).IgnoreResult();
            WipeIfNotNull(newEphemeralPublicKey).IgnoreResult();
            newEphemeralSkHandle?.Dispose();
        }
    }

    internal Result<byte[], ShieldFailure> GenerateNextNonce() => CheckDisposed().Map(_ =>
    {
        Span<byte> nonceBuffer = stackalloc byte[AesGcmNonceSize];
        RandomNumberGenerator.Fill(nonceBuffer[..8]);
        uint currentNonce = (uint)Interlocked.Increment(ref _nonceCounter) - 1;
        BinaryPrimitives.WriteUInt32LittleEndian(nonceBuffer[8..], currentNonce);
        byte[] nonce = nonceBuffer.ToArray();
        Debug.WriteLine($"[ShieldSession] Generated nonce: {Convert.ToHexString(nonce)} for counter: {currentNonce}");
        nonceBuffer.Clear();
        return nonce;
    });

    public Result<byte[]?, ShieldFailure> GetCurrentPeerDhPublicKey() =>
        CheckDisposed().Map(_ => _peerDhPublicKey != null ? (byte[])_peerDhPublicKey.Clone() : null);

    public Result<byte[]?, ShieldFailure> GetCurrentSenderDhPublicKey() =>
        CheckDisposed().Bind(_ => EnsureSendingStepInitialized()).Bind(step => step.ReadDhPublicKey());

    private Result<Unit, ShieldFailure> EnsureNotExpired() => CheckDisposed().Bind(_ =>
    {
        bool expired = DateTimeOffset.UtcNow - _createdAt > SessionTimeout;
        Debug.WriteLine($"[ShieldSession] Checking expiration for session {_id}. Expired: {expired}");
        return expired
            ? Result<Unit, ShieldFailure>.Err(ShieldFailure.Generic($"Session {_id} has expired."))
            : Result<Unit, ShieldFailure>.Ok(Unit.Value);
    });

    private void ClearMessageKeyCache()
    {
        Debug.WriteLine($"[ShieldSession] Clearing message key cache for session {_id}");
        foreach (KeyValuePair<uint, ShieldMessageKey> kvp in _messageKeys.ToList())
        {
            try
            {
                kvp.Value?.Dispose();
            }
            catch (ObjectDisposedException)
            {
                Debug.WriteLine($"[ShieldSession] Message key {kvp.Key} already disposed.");
            }
        }

        _messageKeys.Clear();
    }

    private Result<Unit, ShieldFailure> CheckDisposed() =>
        _disposed
            ? Result<Unit, ShieldFailure>.Err(ShieldFailure.ObjectDisposed(nameof(ConnectSession)))
            : Result<Unit, ShieldFailure>.Ok(Unit.Value);

    private static Result<Unit, ShieldFailure> WipeIfNotNull(byte[]? data) =>
        data == null ? Result<Unit, ShieldFailure>.Ok(Unit.Value) : SodiumInterop.SecureWipe(data);

    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    private void Dispose(bool disposing)
    {
        if (_disposed)
        {
            return;
        }

        Debug.WriteLine($"[ShieldSession] Disposing session {_id}");
        _disposed = true;

        if (disposing)
        {
            SecureCleanupLogic();
        }
    }

    private void SecureCleanupLogic()
    {
        try
        {
            _rootKeyHandle?.Dispose();
            _sendingStep?.Dispose();
            _receivingStep?.Dispose();
            ClearMessageKeyCache();
            _persistentDhPrivateKeyHandle?.Dispose();
            _initialSendingDhPrivateKeyHandle?.Dispose();
            _currentSendingDhPrivateKeyHandle?.Dispose();
            WipeIfNotNull(_peerDhPublicKey).IgnoreResult();
            WipeIfNotNull(_persistentDhPublicKey).IgnoreResult();
            _peerDhPublicKey = null;
            _persistentDhPublicKey = null;
            _initialSendingDhPrivateKeyHandle = null;
            _persistentDhPrivateKeyHandle = null;
            _currentSendingDhPrivateKeyHandle = null;
            Debug.WriteLine($"[ShieldSession] Session {_id} disposed.");
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"[ShieldSession] Error during cleanup for session {_id}: {ex.Message}");
        }
    }

    ~ConnectSession()
    {
        Dispose(false);
    }
}
using System.Buffers;
using System.Buffers.Binary;
using System.Security.Cryptography;
using Ecliptix.Core.Protocol.Failures;
using Ecliptix.Domain.Utilities;
using Ecliptix.Protobuf.PubKeyExchange;
using Sodium;

namespace Ecliptix.Core.Protocol;

public sealed class EcliptixProtocolConnection : IDisposable
{
    private const int DhRotationInterval = 10;
    private const int AesGcmNonceSize = 12;
    private static readonly TimeSpan SessionTimeout = TimeSpan.FromHours(24);
    private static readonly byte[] InitialSenderChainInfo = "ShieldInitSend"u8.ToArray();
    private static readonly byte[] InitialReceiverChainInfo = "ShieldInitRecv"u8.ToArray();
    private static readonly byte[] DhRatchetInfo = "ShieldDhRatchet"u8.ToArray();

    private readonly Lock _lock = new();

    private readonly DateTimeOffset _createdAt;
    private readonly uint _id;
    private bool _isFirstReceivingRatchet;
    private readonly bool _isInitiator;
    private readonly SortedDictionary<uint, EcliptixMessageKey> _messageKeys;
    private readonly EcliptixProtocolChainStep _sendingStep;
    private SodiumSecureMemoryHandle? _currentSendingDhPrivateKeyHandle;
    private volatile bool _disposed;
    private readonly SodiumSecureMemoryHandle? _initialSendingDhPrivateKeyHandle;
    private ulong _nonceCounter;
    private PublicKeyBundle? _peerBundle;
    private byte[]? _peerDhPublicKey;
    private readonly SodiumSecureMemoryHandle? _persistentDhPrivateKeyHandle;
    private readonly byte[]? _persistentDhPublicKey;
    private bool _receivedNewDhKey;
    private EcliptixProtocolChainStep? _receivingStep;
    private SodiumSecureMemoryHandle? _rootKeyHandle;

    private EcliptixProtocolConnection(
        uint id,
        bool isInitiator,
        SodiumSecureMemoryHandle initialSendingDhPrivateKeyHandle,
        EcliptixProtocolChainStep sendingStep,
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
        _messageKeys = new SortedDictionary<uint, EcliptixMessageKey>();
        _nonceCounter = 0;
        _createdAt = DateTimeOffset.UtcNow;
        _peerDhPublicKey = null;
        _receivedNewDhKey = false;
        _disposed = false;
        _isFirstReceivingRatchet = true;
    }

    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    public static Result<EcliptixProtocolConnection, EcliptixProtocolFailure> Create(uint connectId, bool isInitiator)
    {
        SodiumSecureMemoryHandle? initialSendingDhPrivateKeyHandle = null;
        byte[]? initialSendingDhPublicKey = null;
        byte[]? initialSendingDhPrivateKeyBytes = null;
        EcliptixProtocolChainStep? sendingStep = null;
        SodiumSecureMemoryHandle? persistentDhPrivateKeyHandle = null;
        byte[]? persistentDhPublicKey = null;

        try
        {
            Result<EcliptixProtocolConnection, EcliptixProtocolFailure> overallResult =
                SodiumInterop.GenerateX25519KeyPair("Initial Sending DH")
                    .Bind(initialSendKeys =>
                    {
                        (initialSendingDhPrivateKeyHandle, initialSendingDhPublicKey) = initialSendKeys;
                        return initialSendingDhPrivateKeyHandle.ReadBytes(Constants.X25519PrivateKeySize)
                            .MapSodiumFailure()
                            .Map(bytes =>
                            {
                                initialSendingDhPrivateKeyBytes = bytes;
                                return Unit.Value;
                            });
                    })
                    .Bind(_ => SodiumInterop.GenerateX25519KeyPair("Persistent DH"))
                    .Bind(persistentKeys =>
                    {
                        (persistentDhPrivateKeyHandle, persistentDhPublicKey) = persistentKeys;
                        byte[] tempChainKey = new byte[Constants.X25519KeySize];
                        Result<EcliptixProtocolChainStep, EcliptixProtocolFailure> stepResult =
                            EcliptixProtocolChainStep.Create(ChainStepType.Sender, tempChainKey,
                                initialSendingDhPrivateKeyBytes, initialSendingDhPublicKey);
                        WipeIfNotNull(tempChainKey);
                        WipeIfNotNull(initialSendingDhPrivateKeyBytes);
                        initialSendingDhPrivateKeyBytes = null;
                        return stepResult;
                    })
                    .Bind(createdSendingStep =>
                    {
                        sendingStep = createdSendingStep;
                        EcliptixProtocolConnection connection = new(connectId, isInitiator,
                            initialSendingDhPrivateKeyHandle!, sendingStep, persistentDhPrivateKeyHandle!,
                            persistentDhPublicKey!);
                        initialSendingDhPrivateKeyHandle = null;
                        persistentDhPrivateKeyHandle = null;
                        sendingStep = null;
                        return Result<EcliptixProtocolConnection, EcliptixProtocolFailure>.Ok(connection);
                    });

            if (overallResult.IsErr)
            {
                initialSendingDhPrivateKeyHandle?.Dispose();
                sendingStep?.Dispose();
                persistentDhPrivateKeyHandle?.Dispose();
                WipeIfNotNull(initialSendingDhPrivateKeyBytes);
            }

            return overallResult;
        }
        catch (Exception ex)
        {
            initialSendingDhPrivateKeyHandle?.Dispose();
            sendingStep?.Dispose();
            persistentDhPrivateKeyHandle?.Dispose();
            WipeIfNotNull(initialSendingDhPrivateKeyBytes);
            return Result<EcliptixProtocolConnection, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.Generic($"Unexpected error creating session {connectId}.", ex));
        }
    }

    public Result<PublicKeyBundle, EcliptixProtocolFailure> GetPeerBundle()
    {
        lock (_lock)
        {
            return CheckDisposed().Bind(_ =>
                _peerBundle != null
                    ? Result<PublicKeyBundle, EcliptixProtocolFailure>.Ok(_peerBundle)
                    : Result<PublicKeyBundle, EcliptixProtocolFailure>.Err(
                        EcliptixProtocolFailure.Generic("Peer bundle has not been set.")));
        }
    }

    internal Result<Unit, EcliptixProtocolFailure> SetConnectionState(PubKeyExchangeState newState)
    {
        lock (_lock)
        {
            return CheckDisposed().Map(u => u);
        }
    }

    internal Result<Unit, EcliptixProtocolFailure> SetPeerBundle(PublicKeyBundle peerBundle)
    {
        lock (_lock)
        {
            return CheckDisposed().Bind(_ =>
            {
                _peerBundle = peerBundle;
                return Result<Unit, EcliptixProtocolFailure>.Ok(Unit.Value);
            });
        }
    }

    internal Result<Unit, EcliptixProtocolFailure> FinalizeChainAndDhKeys(byte[] initialRootKey,
        byte[] initialPeerDhPublicKey)
    {
        lock (_lock)
        {
            SodiumSecureMemoryHandle? tempRootHandle = null;
            byte[]? localSenderCk = null,
                localReceiverCk = null,
                persistentPrivKeyBytes = null,
                peerDhPublicCopy = null;

            try
            {
                return CheckDisposed()
                    .Bind(_ => CheckIfNotFinalized())
                    .Bind(_ => ValidateInitialKeys(initialRootKey, initialPeerDhPublicKey))
                    .Bind(_ =>
                    {
                        peerDhPublicCopy = (byte[])initialPeerDhPublicKey.Clone();
                        return SodiumSecureMemoryHandle.Allocate(Constants.X25519KeySize).MapSodiumFailure()
                            .Bind(handle =>
                            {
                                tempRootHandle = handle;
                                return handle.Write(initialRootKey).MapSodiumFailure();
                            });
                    })
                    .Bind(_ =>
                    {
                        localSenderCk = ArrayPool<byte>.Shared.Rent(Constants.X25519KeySize);
                        localReceiverCk = ArrayPool<byte>.Shared.Rent(Constants.X25519KeySize);
                        return DeriveInitialChainKeys(initialRootKey, localSenderCk, localReceiverCk);
                    })
                    .Bind(_ => _persistentDhPrivateKeyHandle!.ReadBytes(Constants.X25519PrivateKeySize)
                        .MapSodiumFailure()
                        .Map(bytes =>
                        {
                            persistentPrivKeyBytes = bytes;
                            return Unit.Value;
                        }))
                    .Bind(_ => _sendingStep.UpdateKeysAfterDhRatchet(localSenderCk.AsSpan(0, Constants.X25519KeySize)
                        .ToArray()))
                    .Bind(_ => EcliptixProtocolChainStep.Create(ChainStepType.Receiver,
                        localReceiverCk.AsSpan(0, Constants.X25519KeySize).ToArray(), persistentPrivKeyBytes,
                        _persistentDhPublicKey))
                    .Map(receivingStep =>
                    {
                        _rootKeyHandle = tempRootHandle;
                        tempRootHandle = null;
                        _receivingStep = receivingStep;
                        _peerDhPublicKey = peerDhPublicCopy;
                        peerDhPublicCopy = null;
                        return Unit.Value;
                    })
                    .MapErr(err =>
                    {
                        tempRootHandle?.Dispose();
                        return err;
                    });
            }
            finally
            {
                if (localSenderCk != null) ArrayPool<byte>.Shared.Return(localSenderCk, clearArray: true);
                if (localReceiverCk != null) ArrayPool<byte>.Shared.Return(localReceiverCk, clearArray: true);
                WipeIfNotNull(persistentPrivKeyBytes);
                WipeIfNotNull(peerDhPublicCopy);
            }
        }
    }

    internal Result<(EcliptixMessageKey MessageKey, bool IncludeDhKey), EcliptixProtocolFailure>
        PrepareNextSendMessage()
    {
        lock (_lock)
        {
            byte[]? keyMaterial = null;
            try
            {
                return CheckDisposed()
                    .Bind(_ => EnsureNotExpired())
                    .Bind(_ => EnsureSendingStepInitialized())
                    .Bind(sendingStep => MaybePerformSendingDhRatchet(sendingStep)
                        .Bind(includeDhKey => sendingStep.GetCurrentIndex()
                            .Bind(currentIndex => sendingStep.GetOrDeriveKeyFor(currentIndex + 1, _messageKeys)
                                .Bind(derivedKey =>
                                    sendingStep.SetCurrentIndex(currentIndex + 1)
                                        .Map(_ => (derivedKey, includeDhKey))))))
                    .Bind(result =>
                    {
                        (EcliptixMessageKey originalKey, bool includeDhKey) = result;
                        keyMaterial = ArrayPool<byte>.Shared.Rent(Constants.AesKeySize);
                        Span<byte> keySpan = keyMaterial.AsSpan(0, Constants.AesKeySize);
                        originalKey.ReadKeyMaterial(keySpan);

                        return EcliptixMessageKey.New(originalKey.Index, keySpan)
                            .Map(clonedKey => (clonedKey, includeDhKey));
                    })
                    .Map(finalResult =>
                    {
                        _sendingStep.PruneOldKeys(_messageKeys);
                        return finalResult;
                    });
            }
            finally
            {
                if (keyMaterial != null) ArrayPool<byte>.Shared.Return(keyMaterial, clearArray: true);
            }
        }
    }

    internal Result<EcliptixMessageKey, EcliptixProtocolFailure> ProcessReceivedMessage(uint receivedIndex,
        byte[]? receivedDhPublicKeyBytes)
    {
        lock (_lock)
        {
            return CheckDisposed()
                .Bind(_ => EnsureNotExpired())
                .Bind(_ => EnsureReceivingStepInitialized())
                .Bind(receivingStep => MaybePerformReceivingDhRatchet(receivingStep, receivedDhPublicKeyBytes)
                    .Bind(_ => receivingStep.GetOrDeriveKeyFor(receivedIndex, _messageKeys))
                    .Bind(derivedKey => receivingStep.SetCurrentIndex(derivedKey.Index).Map(_ => derivedKey)))
                .Map(finalKey =>
                {
                    _receivingStep!.PruneOldKeys(_messageKeys);
                    return finalKey;
                });
        }
    }

    public Result<Unit, EcliptixProtocolFailure> PerformReceivingRatchet(byte[] receivedDhKey)
    {
        lock (_lock)
        {
            return PerformDhRatchet(false, receivedDhKey);
        }
    }

    private Result<Unit, EcliptixProtocolFailure> PerformDhRatchet(bool isSender,
        byte[]? receivedDhPublicKeyBytes = null)
    {
        byte[]? dhSecret = null, newRootKey = null, newChainKeyForTargetStep = null, newEphemeralPublicKey = null;
        byte[]? localPrivateKeyBytes = null, currentRootKey = null, newDhPrivateKeyBytes = null;
        byte[]? hkdfOutput = null;
        SodiumSecureMemoryHandle? newEphemeralSkHandle = null;

        try
        {
            Result<Unit, EcliptixProtocolFailure> initialCheck = CheckDisposed().Bind(_ =>
                _rootKeyHandle is { IsInvalid: false }
                    ? Result<Unit, EcliptixProtocolFailure>.Ok(Unit.Value)
                    : Result<Unit, EcliptixProtocolFailure>.Err(
                        EcliptixProtocolFailure.Generic("Root key handle not initialized.")));
            if (initialCheck.IsErr) return initialCheck;

            Result<Unit, EcliptixProtocolFailure> dhCalculationResult = Result<Unit, EcliptixProtocolFailure>.Try(() =>
            {
                if (isSender)
                {
                    if (_sendingStep == null || _peerDhPublicKey == null)
                        throw new InvalidOperationException("Sender ratchet pre-conditions not met.");
                    (SodiumSecureMemoryHandle skHandle, byte[] pk) ephResult = SodiumInterop.GenerateX25519KeyPair("Ephemeral DH Ratchet").Unwrap();
                    (newEphemeralSkHandle, newEphemeralPublicKey) = ephResult;
                    localPrivateKeyBytes = newEphemeralSkHandle.ReadBytes(Constants.X25519PrivateKeySize).Unwrap();
                    dhSecret = ScalarMult.Mult(localPrivateKeyBytes, _peerDhPublicKey);
                }
                else
                {
                    if (_receivingStep == null || receivedDhPublicKeyBytes is not
                            { Length: Constants.X25519PublicKeySize })
                        throw new InvalidOperationException("Receiver ratchet pre-conditions not met.");
                    localPrivateKeyBytes = _currentSendingDhPrivateKeyHandle!.ReadBytes(Constants.X25519PrivateKeySize)
                        .Unwrap();
                    dhSecret = ScalarMult.Mult(localPrivateKeyBytes, receivedDhPublicKeyBytes);
                }
            }, ex => EcliptixProtocolFailure.DeriveKey("DH calculation failed during ratchet.", ex));
            if (dhCalculationResult.IsErr) return dhCalculationResult;

            currentRootKey = _rootKeyHandle!.ReadBytes(Constants.X25519KeySize).Unwrap();
            hkdfOutput = ArrayPool<byte>.Shared.Rent(Constants.X25519KeySize * 2);
            using (HkdfSha256 hkdf = new(dhSecret!, currentRootKey))
            {
                hkdf.Expand(DhRatchetInfo, hkdfOutput.AsSpan(0, Constants.X25519KeySize * 2));
            }

            newRootKey = hkdfOutput.AsSpan(0, Constants.X25519KeySize).ToArray();
            newChainKeyForTargetStep = hkdfOutput.AsSpan(Constants.X25519KeySize).ToArray();

            Result<Unit, EcliptixProtocolFailure> writeResult = _rootKeyHandle.Write(newRootKey).MapSodiumFailure();
            if (writeResult.IsErr) return writeResult.MapErr(f => f);

            Result<Unit, EcliptixProtocolFailure> updateResult;
            if (isSender)
            {
                newDhPrivateKeyBytes = newEphemeralSkHandle!.ReadBytes(Constants.X25519PrivateKeySize).Unwrap();
                _currentSendingDhPrivateKeyHandle?.Dispose();
                _currentSendingDhPrivateKeyHandle = newEphemeralSkHandle;
                newEphemeralSkHandle = null;
                updateResult = _sendingStep.UpdateKeysAfterDhRatchet(newChainKeyForTargetStep, newDhPrivateKeyBytes,
                    newEphemeralPublicKey);
            }
            else
            {
                updateResult = _receivingStep!.UpdateKeysAfterDhRatchet(newChainKeyForTargetStep);
                if (updateResult.IsOk)
                {
                    WipeIfNotNull(_peerDhPublicKey);
                    _peerDhPublicKey = (byte[])receivedDhPublicKeyBytes!.Clone();
                }
            }

            if (updateResult.IsErr) return updateResult;

            _receivedNewDhKey = false;
            ClearMessageKeyCache();
            return Result<Unit, EcliptixProtocolFailure>.Ok(Unit.Value);
        }
        finally
        {
            WipeIfNotNull(dhSecret);
            WipeIfNotNull(newRootKey);
            WipeIfNotNull(newChainKeyForTargetStep);
            WipeIfNotNull(newEphemeralPublicKey);
            WipeIfNotNull(localPrivateKeyBytes);
            WipeIfNotNull(currentRootKey);
            WipeIfNotNull(newDhPrivateKeyBytes);
            if (hkdfOutput != null) ArrayPool<byte>.Shared.Return(hkdfOutput, clearArray: true);
            newEphemeralSkHandle?.Dispose();
        }
    }

    internal Result<byte[], EcliptixProtocolFailure> GenerateNextNonce()
    {
        lock (_lock)
        {
            return CheckDisposed().Map(_ =>
            {
                Span<byte> nonceBuffer = stackalloc byte[AesGcmNonceSize];
                RandomNumberGenerator.Fill(nonceBuffer[..8]);
                uint currentNonce = (uint)Interlocked.Increment(ref _nonceCounter) - 1;
                BinaryPrimitives.WriteUInt32LittleEndian(nonceBuffer[8..], currentNonce);
                return nonceBuffer.ToArray();
            });
        }
    }

    public Result<byte[]?, EcliptixProtocolFailure> GetCurrentPeerDhPublicKey()
    {
        lock (_lock)
        {
            return CheckDisposed().Map(_ => _peerDhPublicKey != null ? (byte[])_peerDhPublicKey.Clone() : null);
        }
    }

    public Result<byte[]?, EcliptixProtocolFailure> GetCurrentSenderDhPublicKey()
    {
        lock (_lock)
        {
            return CheckDisposed().Bind(_ => EnsureSendingStepInitialized()).Bind(step => step.ReadDhPublicKey());
        }
    }

    private void Dispose(bool disposing)
    {
        lock (_lock)
        {
            if (_disposed) return;
            _disposed = true;
            if (disposing)
            {
                SecureCleanupLogic();
            }
        }
    }

    ~EcliptixProtocolConnection()
    {
        Dispose(false);
    }

    private void SecureCleanupLogic()
    {
        _rootKeyHandle?.Dispose();
        _sendingStep.Dispose();
        _receivingStep?.Dispose();
        ClearMessageKeyCache();
        _persistentDhPrivateKeyHandle?.Dispose();
        if (_currentSendingDhPrivateKeyHandle != _initialSendingDhPrivateKeyHandle)
            _currentSendingDhPrivateKeyHandle?.Dispose();
        _initialSendingDhPrivateKeyHandle?.Dispose();
        WipeIfNotNull(_peerDhPublicKey);
        WipeIfNotNull(_persistentDhPublicKey);
    }

    private Result<Unit, EcliptixProtocolFailure> CheckDisposed()
    {
        return _disposed
            ? Result<Unit, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.ObjectDisposed(nameof(EcliptixProtocolConnection)))
            : Result<Unit, EcliptixProtocolFailure>.Ok(Unit.Value);
    }

    private static Result<Unit, EcliptixProtocolFailure> WipeIfNotNull(byte[]? data)
    {
        return data == null
            ? Result<Unit, EcliptixProtocolFailure>.Ok(Unit.Value)
            : SodiumInterop.SecureWipe(data).MapSodiumFailure();
    }

    private void ClearMessageKeyCache()
    {
        foreach (KeyValuePair<uint, EcliptixMessageKey> kvp in _messageKeys.ToList())
        {
            kvp.Value.Dispose();
        }

        _messageKeys.Clear();
    }

    private Result<Unit, EcliptixProtocolFailure> EnsureNotExpired()
    {
        return CheckDisposed().Bind(_ =>
            DateTimeOffset.UtcNow - _createdAt > SessionTimeout
                ? Result<Unit, EcliptixProtocolFailure>.Err(
                    EcliptixProtocolFailure.Generic($"Session {_id} has expired."))
                : Result<Unit, EcliptixProtocolFailure>.Ok(Unit.Value));
    }

    private Result<EcliptixProtocolChainStep, EcliptixProtocolFailure> EnsureSendingStepInitialized()
    {
        return CheckDisposed().Bind(_ =>
            _sendingStep != null
                ? Result<EcliptixProtocolChainStep, EcliptixProtocolFailure>.Ok(_sendingStep)
                : Result<EcliptixProtocolChainStep, EcliptixProtocolFailure>.Err(
                    EcliptixProtocolFailure.Generic("Sending chain step not initialized.")));
    }

    private Result<EcliptixProtocolChainStep, EcliptixProtocolFailure> EnsureReceivingStepInitialized()
    {
        return CheckDisposed().Bind(_ =>
            _receivingStep != null
                ? Result<EcliptixProtocolChainStep, EcliptixProtocolFailure>.Ok(_receivingStep)
                : Result<EcliptixProtocolChainStep, EcliptixProtocolFailure>.Err(
                    EcliptixProtocolFailure.Generic("Receiving chain step not initialized.")));
    }

    private Result<Unit, EcliptixProtocolFailure> CheckIfNotFinalized()
    {
        return CheckDisposed().Bind(_ =>
            _rootKeyHandle != null || _receivingStep != null
                ? Result<Unit, EcliptixProtocolFailure>.Err(
                    EcliptixProtocolFailure.Generic("Session has already been finalized."))
                : Result<Unit, EcliptixProtocolFailure>.Ok(Unit.Value));
    }

    private static Result<Unit, EcliptixProtocolFailure> ValidateInitialKeys(byte[] rootKey, byte[] peerDhKey)
    {
        if (rootKey.Length != Constants.X25519KeySize)
            return Result<Unit, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.InvalidInput($"Initial root key must be {Constants.X25519KeySize} bytes."));
        if (peerDhKey.Length != Constants.X25519PublicKeySize)
            return Result<Unit, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.InvalidInput(
                    $"Initial peer DH public key must be {Constants.X25519PublicKeySize} bytes."));
        return Result<Unit, EcliptixProtocolFailure>.Ok(Unit.Value);
    }

    private Result<Unit, EcliptixProtocolFailure> DeriveInitialChainKeys(byte[] rootKey, byte[] senderCkDest,
        byte[] receiverCkDest)
    {
        return Result<Unit, EcliptixProtocolFailure>.Try(() =>
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

            if (_isInitiator)
            {
                sendSpan.CopyTo(senderCkDest);
                recvSpan.CopyTo(receiverCkDest);
            }
            else
            {
                recvSpan.CopyTo(senderCkDest);
                sendSpan.CopyTo(receiverCkDest);
            }
        }, ex => EcliptixProtocolFailure.DeriveKey("Failed to derive initial chain keys.", ex));
    }

    private Result<bool, EcliptixProtocolFailure> MaybePerformSendingDhRatchet(EcliptixProtocolChainStep sendingStep)
    {
        return sendingStep.GetCurrentIndex().Bind(currentIndex =>
        {
            bool shouldRatchet = (currentIndex + 1) % DhRotationInterval == 0 || _receivedNewDhKey;
            if (shouldRatchet)
                return PerformDhRatchet(true).Map(_ =>
                {
                    _receivedNewDhKey = false;
                    return true;
                });
            return Result<bool, EcliptixProtocolFailure>.Ok(false);
        });
    }

    private Result<Unit, EcliptixProtocolFailure> MaybePerformReceivingDhRatchet(
        EcliptixProtocolChainStep receivingStep, byte[]? receivedDhPublicKeyBytes)
    {
        if (receivedDhPublicKeyBytes == null) return Result<Unit, EcliptixProtocolFailure>.Ok(Unit.Value);
        bool keysDiffer = _peerDhPublicKey == null || !receivedDhPublicKeyBytes.SequenceEqual(receivedDhPublicKeyBytes);
        if (!keysDiffer) return Result<Unit, EcliptixProtocolFailure>.Ok(Unit.Value);

        return receivingStep.GetCurrentIndex().Bind(currentIndex =>
        {
            bool shouldRatchetNow = _isFirstReceivingRatchet || (currentIndex + 1) % DhRotationInterval == 0;
            if (shouldRatchetNow)
            {
                _isFirstReceivingRatchet = false;
                return PerformDhRatchet(false, receivedDhPublicKeyBytes);
            }
            else
            {
                WipeIfNotNull(_peerDhPublicKey);
                _peerDhPublicKey = (byte[])receivedDhPublicKeyBytes.Clone();
                _receivedNewDhKey = true;
                return Result<Unit, EcliptixProtocolFailure>.Ok(Unit.Value);
            }
        });
    }
}
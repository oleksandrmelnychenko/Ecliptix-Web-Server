using System.Buffers;
using System.Buffers.Binary;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using Ecliptix.Core.Protocol.Failures;
using Ecliptix.Domain.Utilities;
using Ecliptix.Protobuf.ProtocolState;
using Ecliptix.Protobuf.PubKeyExchange;
using Google.Protobuf;
using Google.Protobuf.WellKnownTypes;
using Sodium;

namespace Ecliptix.Core.Protocol;

public sealed class EcliptixProtocolConnection : IDisposable
{
    // --- Constants ---
    private const int DhRotationInterval = 10;
    private const int AesGcmNonceSize = 12;
    private static readonly TimeSpan SessionTimeout = TimeSpan.FromHours(24);
    private static readonly byte[] InitialSenderChainInfo = "ShieldInitSend"u8.ToArray();
    private static readonly byte[] InitialReceiverChainInfo = "ShieldInitRecv"u8.ToArray();
    private static readonly byte[] DhRatchetInfo = "ShieldDhRatchet"u8.ToArray();

    // --- Fields ---
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

    #region Constructors and Factories

    // Private constructor for new sessions
    private EcliptixProtocolConnection(uint id, bool isInitiator, SodiumSecureMemoryHandle initialSendingDh,
        EcliptixProtocolChainStep sendingStep, SodiumSecureMemoryHandle persistentDh, byte[] persistentDhPublic)
    {
        _id = id;
        _isInitiator = isInitiator;
        _initialSendingDhPrivateKeyHandle = initialSendingDh;
        _currentSendingDhPrivateKeyHandle = initialSendingDh;
        _sendingStep = sendingStep;
        _persistentDhPrivateKeyHandle = persistentDh;
        _persistentDhPublicKey = persistentDhPublic;
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

    // Private constructor for rehydrated sessions
    private EcliptixProtocolConnection(uint id, RatchetState proto, EcliptixProtocolChainStep sendingStep,
        EcliptixProtocolChainStep? receivingStep, SodiumSecureMemoryHandle rootKeyHandle)
    {
        _id = id;
        _isInitiator = proto.IsInitiator;
        _createdAt = proto.CreatedAt.ToDateTimeOffset();
        _nonceCounter = proto.NonceCounter;
        _peerBundle = PublicKeyBundle.FromProtobufExchange(proto.PeerBundle).Unwrap();
        _peerDhPublicKey = proto.PeerDhPublicKey.IsEmpty ? null : proto.PeerDhPublicKey.ToByteArray();
        _isFirstReceivingRatchet = proto.IsFirstReceivingRatchet;
        _rootKeyHandle = rootKeyHandle;
        _sendingStep = sendingStep;
        _receivingStep = receivingStep;
        _currentSendingDhPrivateKeyHandle = sendingStep.GetDhPrivateKeyHandle();
        _initialSendingDhPrivateKeyHandle = null;
        _persistentDhPrivateKeyHandle = null;
        _persistentDhPublicKey = null;
        _messageKeys = new SortedDictionary<uint, EcliptixMessageKey>();
        _receivedNewDhKey = false;
        _disposed = false;
        _lock = new Lock();
    }

    public static Result<EcliptixProtocolConnection, EcliptixProtocolFailure> Create(uint connectId, bool isInitiator)
    {
        // ... implementation is correct and unchanged ...
        SodiumSecureMemoryHandle? initialSendingDhPrivateKeyHandle = null;
        EcliptixProtocolChainStep? sendingStep = null;
        SodiumSecureMemoryHandle? persistentDhPrivateKeyHandle = null;

        try
        {
            var initialKeysResult = SodiumInterop.GenerateX25519KeyPair("Initial Sending DH");
            if (initialKeysResult.IsErr)
                return Result<EcliptixProtocolConnection, EcliptixProtocolFailure>.Err(initialKeysResult.UnwrapErr());
            (initialSendingDhPrivateKeyHandle, var initialSendingDhPublicKey) = initialKeysResult.Unwrap();

            var persistentKeysResult = SodiumInterop.GenerateX25519KeyPair("Persistent DH");
            if (persistentKeysResult.IsErr)
                return Result<EcliptixProtocolConnection, EcliptixProtocolFailure>.Err(persistentKeysResult
                    .UnwrapErr());
            (persistentDhPrivateKeyHandle, var persistentDhPublicKey) = persistentKeysResult.Unwrap();

            var initialSkBytes = initialSendingDhPrivateKeyHandle.ReadBytes(Constants.X25519PrivateKeySize).Unwrap();
            var tempChainKey = new byte[Constants.X25519KeySize]; // Zero-filled, will be updated later

            var stepResult = EcliptixProtocolChainStep.Create(ChainStepType.Sender, tempChainKey, initialSkBytes,
                initialSendingDhPublicKey);
            WipeIfNotNull(initialSkBytes).IgnoreResult();
            if (stepResult.IsErr)
                return Result<EcliptixProtocolConnection, EcliptixProtocolFailure>.Err(stepResult.UnwrapErr());
            sendingStep = stepResult.Unwrap();

            var connection = new EcliptixProtocolConnection(connectId, isInitiator, initialSendingDhPrivateKeyHandle,
                sendingStep, persistentDhPrivateKeyHandle, persistentDhPublicKey);

            // Null out to transfer ownership
            initialSendingDhPrivateKeyHandle = null;
            sendingStep = null;
            persistentDhPrivateKeyHandle = null;

            return Result<EcliptixProtocolConnection, EcliptixProtocolFailure>.Ok(connection);
        }
        catch (Exception ex)
        {
            initialSendingDhPrivateKeyHandle?.Dispose();
            sendingStep?.Dispose();
            persistentDhPrivateKeyHandle?.Dispose();
            return Result<EcliptixProtocolConnection, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.Generic($"Unexpected error creating session {connectId}.", ex));
        }
    }

    #endregion

    #region Persistence Conversion

    public Result<RatchetState, EcliptixProtocolFailure> ToProtoState()
    {
        // ... implementation is correct and unchanged ...
        lock (_lock)
        {
            if (_disposed)
                return Result<RatchetState, EcliptixProtocolFailure>.Err(
                    EcliptixProtocolFailure.ObjectDisposed(nameof(EcliptixProtocolConnection)));

            try
            {
                var sendingStepStateResult = _sendingStep.ToProtoState();
                if (sendingStepStateResult.IsErr)
                    return Result<RatchetState, EcliptixProtocolFailure>.Err(sendingStepStateResult.UnwrapErr());

                var rootKeyResult = _rootKeyHandle!.ReadBytes(Constants.X25519KeySize).MapSodiumFailure();
                if (rootKeyResult.IsErr)
                    return Result<RatchetState, EcliptixProtocolFailure>.Err(rootKeyResult.UnwrapErr());

                var proto = new RatchetState
                {
                    IsInitiator = _isInitiator,
                    CreatedAt = Timestamp.FromDateTimeOffset(_createdAt),
                    NonceCounter = _nonceCounter,
                    PeerBundle = _peerBundle!.ToProtobufExchange(), // Assumes peer bundle is set
                    PeerDhPublicKey = ByteString.CopyFrom(_peerDhPublicKey ?? Array.Empty<byte>()),
                    IsFirstReceivingRatchet = _isFirstReceivingRatchet,
                    RootKey = ByteString.CopyFrom(rootKeyResult.Unwrap()),
                    SendingStep = sendingStepStateResult.Unwrap()
                };

                if (_receivingStep != null)
                {
                    var receivingStepStateResult = _receivingStep.ToProtoState();
                    if (receivingStepStateResult.IsErr)
                        return Result<RatchetState, EcliptixProtocolFailure>.Err(receivingStepStateResult.UnwrapErr());
                    proto.ReceivingStep = receivingStepStateResult.Unwrap();
                }

                return Result<RatchetState, EcliptixProtocolFailure>.Ok(proto);
            }
            catch (Exception ex)
            {
                return Result<RatchetState, EcliptixProtocolFailure>.Err(
                    EcliptixProtocolFailure.Generic("Failed to export connection to proto state.", ex));
            }
        }
    }

    public static Result<EcliptixProtocolConnection, EcliptixProtocolFailure> FromProtoState(uint connectId,
        RatchetState proto)
    {
        // ... implementation is correct and unchanged ...
        EcliptixProtocolChainStep? sendingStep = null;
        EcliptixProtocolChainStep? receivingStep = null;
        SodiumSecureMemoryHandle? rootKeyHandle = null;

        try
        {
            var sendingStepResult = EcliptixProtocolChainStep.FromProtoState(ChainStepType.Sender, proto.SendingStep);
            if (sendingStepResult.IsErr)
                return Result<EcliptixProtocolConnection, EcliptixProtocolFailure>.Err(sendingStepResult.UnwrapErr());
            sendingStep = sendingStepResult.Unwrap();


            var receivingStepResult =
                EcliptixProtocolChainStep.FromProtoState(ChainStepType.Receiver, proto.ReceivingStep);
            if (receivingStepResult.IsErr)
                return Result<EcliptixProtocolConnection, EcliptixProtocolFailure>.Err(receivingStepResult.UnwrapErr());
            receivingStep = receivingStepResult.Unwrap();

            var rootKeyResult = SodiumSecureMemoryHandle.Allocate(proto.RootKey.Length).MapSodiumFailure();
            if (rootKeyResult.IsErr)
                return Result<EcliptixProtocolConnection, EcliptixProtocolFailure>.Err(rootKeyResult.UnwrapErr());
            rootKeyHandle = rootKeyResult.Unwrap();
            rootKeyHandle.Write(proto.RootKey.ToByteArray()).MapSodiumFailure().Unwrap();

            var connection =
                new EcliptixProtocolConnection(connectId, proto, sendingStep, receivingStep, rootKeyHandle);

            // Null out to transfer ownership
            sendingStep = null;
            receivingStep = null;
            rootKeyHandle = null;

            return Result<EcliptixProtocolConnection, EcliptixProtocolFailure>.Ok(connection);
        }
        catch (Exception ex)
        {
            sendingStep?.Dispose();
            receivingStep?.Dispose();
            rootKeyHandle?.Dispose();
            return Result<EcliptixProtocolConnection, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.Generic("Failed to rehydrate connection from proto state.", ex));
        }
    }

    // Inside the EcliptixProtocolConnection class, for example, after the Dispose() method.

    /// <summary>
    /// Retrieves the public key bundle of the peer in this connection.
    /// </summary>
    /// <returns>The peer's PublicKeyBundle if the session is established, otherwise an error.</returns>
    public Result<PublicKeyBundle, EcliptixProtocolFailure> GetPeerBundle()
    {
        lock (_lock)
        {
            return CheckDisposed().Bind(_ =>
                _peerBundle != null
                    ? Result<PublicKeyBundle, EcliptixProtocolFailure>.Ok(_peerBundle)
                    : Result<PublicKeyBundle, EcliptixProtocolFailure>.Err(
                        EcliptixProtocolFailure.Generic("Peer bundle has not been set in the connection.")));
        }
    }

    #endregion

    #region Core Logic Methods

    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
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
        // ... implementation is correct and unchanged ...
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
        // ... implementation is correct and unchanged ...
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
                // Note: The MaybePerformReceivingDhRatchet logic is now part of the public PerformReceivingRatchet call
                .Bind(_ => _receivingStep!.GetOrDeriveKeyFor(receivedIndex, _messageKeys))
                .Bind(derivedKey => _receivingStep!.SetCurrentIndex(derivedKey.Index).Map(_ => derivedKey))
                .Map(finalKey =>
                {
                    _receivingStep!.PruneOldKeys(_messageKeys);
                    return finalKey;
                });
        }
    }

    /// <summary>
    /// RESTORED/CORRECTED: This is the public entry point for handling a potential DH ratchet on message receipt.
    /// It contains the logic to check if a ratchet is needed and perform it.
    /// </summary>
    public Result<Unit, EcliptixProtocolFailure> PerformReceivingRatchet(byte[]? receivedDhKey)
    {
        lock (_lock)
        {
            if (receivedDhKey == null) return Result<Unit, EcliptixProtocolFailure>.Ok(Unit.Value);

            var keysAreEqual = _peerDhPublicKey != null && receivedDhKey.AsSpan().SequenceEqual(_peerDhPublicKey);
            if (keysAreEqual) return Result<Unit, EcliptixProtocolFailure>.Ok(Unit.Value);

            return EnsureReceivingStepInitialized().Bind(receivingStep =>
                receivingStep.GetCurrentIndex().Bind(currentIndex =>
                {
                    // A DH ratchet happens if it's the first message or we've hit the rotation interval.
                    bool shouldRatchetNow = _isFirstReceivingRatchet || (currentIndex + 1) % DhRotationInterval == 0;
                    if (shouldRatchetNow)
                    {
                        _isFirstReceivingRatchet = false;
                        return PerformDhRatchet(isSender: false, receivedDhPublicKeyBytes: receivedDhKey);
                    }
                    else
                    {
                        // The peer has sent a new key early. We'll store it and use it on our next send.
                        WipeIfNotNull(_peerDhPublicKey);
                        _peerDhPublicKey = (byte[])receivedDhKey.Clone();
                        _receivedNewDhKey = true;
                        return Result<Unit, EcliptixProtocolFailure>.Ok(Unit.Value);
                    }
                })
            );
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
                // Use the shared _nonceCounter, incrementing it atomically
                ulong currentNonceValue =
                    (ulong)Interlocked.Increment(ref Unsafe.As<ulong, long>(ref _nonceCounter)) - 1;
                BinaryPrimitives.WriteUInt64LittleEndian(nonceBuffer, currentNonceValue);
                // For a 12-byte nonce, the last 4 bytes can be zero or randomized further if needed.
                return nonceBuffer.ToArray();
            });
        }
    }

    public Result<byte[]?, EcliptixProtocolFailure> GetCurrentSenderDhPublicKey()
    {
        lock (_lock)
        {
            return CheckDisposed().Bind(_ => EnsureSendingStepInitialized()).Bind(step => step.ReadDhPublicKey());
        }
    }

    #endregion

    #region Private Helpers

    private void Dispose(bool disposing)
    {
        lock (_lock)
        {
            if (_disposed) return;
            _disposed = true;
            if (disposing)
            {
                _rootKeyHandle?.Dispose();
                _sendingStep?.Dispose();
                _receivingStep?.Dispose();
                _persistentDhPrivateKeyHandle?.Dispose();
                // Avoid double-disposing the handle if it's the same as the initial one
                if (_currentSendingDhPrivateKeyHandle != null &&
                    _currentSendingDhPrivateKeyHandle != _initialSendingDhPrivateKeyHandle)
                    _currentSendingDhPrivateKeyHandle.Dispose();
                _initialSendingDhPrivateKeyHandle?.Dispose();

                ClearMessageKeyCache();
                WipeIfNotNull(_peerDhPublicKey).IgnoreResult();
                WipeIfNotNull(_persistentDhPublicKey).IgnoreResult();
            }
        }
    }

    ~EcliptixProtocolConnection()
    {
        Dispose(false);
    }

    private Result<Unit, EcliptixProtocolFailure> PerformDhRatchet(bool isSender,
        byte[]? receivedDhPublicKeyBytes = null)
    {
        // ... implementation is correct and unchanged ...
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
                    (SodiumSecureMemoryHandle skHandle, byte[] pk) ephResult =
                        SodiumInterop.GenerateX25519KeyPair("Ephemeral DH Ratchet").Unwrap();
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

    private static Result<Unit, EcliptixProtocolFailure> WipeIfNotNull(byte[]? data) =>
        data == null
            ? Result<Unit, EcliptixProtocolFailure>.Ok(Unit.Value)
            : SodiumInterop.SecureWipe(data).MapSodiumFailure();

    private void ClearMessageKeyCache()
    {
        foreach (var (_, key) in _messageKeys)
        {
            key.Dispose();
        }

        _messageKeys.Clear();
    }

    // other private helpers like EnsureNotExpired, etc...
    private Result<Unit, EcliptixProtocolFailure> CheckDisposed()
    {
        return _disposed
            ? Result<Unit, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.ObjectDisposed(nameof(EcliptixProtocolConnection)))
            : Result<Unit, EcliptixProtocolFailure>.Ok(Unit.Value);
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

    #endregion
}
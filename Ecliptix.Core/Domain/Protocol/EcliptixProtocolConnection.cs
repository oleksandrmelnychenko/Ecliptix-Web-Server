using System.Buffers;
using System.Buffers.Binary;
using System.Security.Cryptography;
using Ecliptix.Core.Domain.Protocol.Failures;
using Ecliptix.Core.Protocol;
using Ecliptix.Utilities;
using Ecliptix.Protobuf.ProtocolState;
using Google.Protobuf;
using Google.Protobuf.WellKnownTypes;
using Sodium;

namespace Ecliptix.Core.Domain.Protocol;

public sealed class EcliptixProtocolConnection : IDisposable
{
    private const int AesGcmNonceSize = 12;
    private static readonly TimeSpan ConnectTimeout = TimeSpan.FromHours(24);
    private static ReadOnlySpan<byte> InitialSenderChainInfo => "ShieldInitSend"u8;
    private static ReadOnlySpan<byte> InitialReceiverChainInfo => "ShieldInitRecv"u8;
    private static ReadOnlySpan<byte> DhRatchetInfo => "ShieldDhRatchet"u8;

    private readonly Lock _lock = new();
    private readonly ReplayProtection _replayProtection = new();
    private readonly RatchetConfig _ratchetConfig;
    private readonly RatchetRecovery _ratchetRecovery = new();
    private readonly PerformanceProfiler _profiler = new();

    private readonly DateTimeOffset _createdAt;
    private readonly uint _id;
    private DateTime _lastRatchetTime = DateTime.UtcNow;
    private bool _isFirstReceivingRatchet;
    private readonly bool _isInitiator;

    private readonly EcliptixProtocolChainStep _sendingStep;
    private SodiumSecureMemoryHandle? _currentSendingDhPrivateKeyHandle;
    private volatile bool _disposed;
    private readonly SodiumSecureMemoryHandle? _initialSendingDhPrivateKeyHandle;
    private long _nonceCounter;
    private PublicKeyBundle? _peerBundle;
    private byte[]? _peerDhPublicKey;
    private readonly SodiumSecureMemoryHandle? _persistentDhPrivateKeyHandle;
    private readonly byte[]? _persistentDhPublicKey;
    private bool _receivedNewDhKey;
    private EcliptixProtocolChainStep? _receivingStep;
    private SodiumSecureMemoryHandle? _rootKeyHandle;

    private EcliptixProtocolConnection(uint id, bool isInitiator, SodiumSecureMemoryHandle initialSendingDh,
        EcliptixProtocolChainStep sendingStep, SodiumSecureMemoryHandle persistentDh, byte[] persistentDhPublic,
        RatchetConfig ratchetConfig)
    {
        _id = id;
        _isInitiator = isInitiator;
        _ratchetConfig = ratchetConfig;
        _initialSendingDhPrivateKeyHandle = initialSendingDh;
        _currentSendingDhPrivateKeyHandle = initialSendingDh;
        _sendingStep = sendingStep;
        _persistentDhPrivateKeyHandle = persistentDh;
        _persistentDhPublicKey = persistentDhPublic;
        _peerBundle = null;
        _receivingStep = null;
        _rootKeyHandle = null;
        _nonceCounter = 0;
        _createdAt = DateTimeOffset.UtcNow;
        _peerDhPublicKey = null;
        _receivedNewDhKey = false;
        _disposed = false;
        _isFirstReceivingRatchet = false;
    }

    private EcliptixProtocolConnection(uint id, RatchetState proto, EcliptixProtocolChainStep sendingStep,
        EcliptixProtocolChainStep? receivingStep, SodiumSecureMemoryHandle rootKeyHandle)
    {
        _id = id;
        _isInitiator = proto.IsInitiator;
        _ratchetConfig = RatchetConfig.Default;
        _createdAt = proto.CreatedAt.ToDateTimeOffset();

        _nonceCounter = (long)proto.NonceCounter;
        _peerBundle = PublicKeyBundle.FromProtobufExchange(proto.PeerBundle).Unwrap();
        if (proto.PeerDhPublicKey.IsEmpty)
        {
            _peerDhPublicKey = null;
        }
        else
        {
            SecureByteStringInterop.SecureCopyWithCleanup(proto.PeerDhPublicKey, out byte[] dhKeyBytes);
            _peerDhPublicKey = dhKeyBytes;
        }
        _isFirstReceivingRatchet = proto.IsFirstReceivingRatchet;
        _rootKeyHandle = rootKeyHandle;
        _sendingStep = sendingStep;
        _receivingStep = receivingStep;
        _currentSendingDhPrivateKeyHandle = sendingStep.GetDhPrivateKeyHandle();
        _initialSendingDhPrivateKeyHandle = null;
        _persistentDhPrivateKeyHandle = null;
        _persistentDhPublicKey = null;
        _receivedNewDhKey = false;
        _disposed = false;
        _lock = new Lock();
    }

    public static Result<EcliptixProtocolConnection, EcliptixProtocolFailure> Create(uint connectId, bool isInitiator)
    {
        return Create(connectId, isInitiator, RatchetConfig.Default);
    }

    public static Result<EcliptixProtocolConnection, EcliptixProtocolFailure> Create(
        uint connectId, bool isInitiator, RatchetConfig ratchetConfig)
    {
        SodiumSecureMemoryHandle? initialSendingDhPrivateKeyHandle = null;
        EcliptixProtocolChainStep? sendingStep = null;
        SodiumSecureMemoryHandle? persistentDhPrivateKeyHandle = null;

        try
        {
            Result<(SodiumSecureMemoryHandle skHandle, byte[] pk), EcliptixProtocolFailure> initialKeysResult = SodiumInterop.GenerateX25519KeyPair("Initial Sending DH");
            if (initialKeysResult.IsErr)
                return Result<EcliptixProtocolConnection, EcliptixProtocolFailure>.Err(initialKeysResult.UnwrapErr());
            (initialSendingDhPrivateKeyHandle, byte[] initialSendingDhPublicKey) = initialKeysResult.Unwrap();

            byte[] tempInitialSk = new byte[Constants.X25519PrivateKeySize];
            initialSendingDhPrivateKeyHandle.Read(tempInitialSk);

            Result<(SodiumSecureMemoryHandle skHandle, byte[] pk), EcliptixProtocolFailure> persistentKeysResult = SodiumInterop.GenerateX25519KeyPair("Persistent DH");
            if (persistentKeysResult.IsErr)
                return Result<EcliptixProtocolConnection, EcliptixProtocolFailure>.Err(persistentKeysResult.UnwrapErr());
            (persistentDhPrivateKeyHandle, byte[] persistentDhPublicKey) = persistentKeysResult.Unwrap();

            byte[] tempPersistentSk = new byte[Constants.X25519PrivateKeySize];
            persistentDhPrivateKeyHandle.Read(tempPersistentSk);

            Result<byte[], EcliptixProtocolFailure> initialSkResult = initialSendingDhPrivateKeyHandle.ReadBytes(Constants.X25519PrivateKeySize).MapSodiumFailure();
            if (initialSkResult.IsErr)
                return Result<EcliptixProtocolConnection, EcliptixProtocolFailure>.Err(initialSkResult.UnwrapErr());
            byte[] initialSkBytes = initialSkResult.Unwrap();
            byte[] tempChainKey = new byte[Constants.X25519KeySize];

            Result<EcliptixProtocolChainStep, EcliptixProtocolFailure> stepResult = EcliptixProtocolChainStep.Create(ChainStepType.Sender, tempChainKey, initialSkBytes,
                initialSendingDhPublicKey);
            Result<Unit, EcliptixProtocolFailure> wipeResult = WipeIfNotNull(initialSkBytes);
            if (wipeResult.IsErr)
                return Result<EcliptixProtocolConnection, EcliptixProtocolFailure>.Err(wipeResult.UnwrapErr());
            if (stepResult.IsErr)
                return Result<EcliptixProtocolConnection, EcliptixProtocolFailure>.Err(stepResult.UnwrapErr());
            sendingStep = stepResult.Unwrap();

            EcliptixProtocolConnection connection = new(connectId, isInitiator, initialSendingDhPrivateKeyHandle,
                sendingStep, persistentDhPrivateKeyHandle, persistentDhPublicKey, ratchetConfig);

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

    public Result<RatchetState, EcliptixProtocolFailure> ToProtoState()
    {
        lock (_lock)
        {
            if (_disposed)
                return Result<RatchetState, EcliptixProtocolFailure>.Err(
                    EcliptixProtocolFailure.ObjectDisposed(nameof(EcliptixProtocolConnection)));

            try
            {
                Result<ChainStepState, EcliptixProtocolFailure> sendingStepStateResult = _sendingStep.ToProtoState();
                if (sendingStepStateResult.IsErr)
                    return Result<RatchetState, EcliptixProtocolFailure>.Err(sendingStepStateResult.UnwrapErr());

                Result<ByteString, EcliptixProtocolFailure> rootKeyBytesResult = SecureByteStringInterop.CreateByteStringFromSecureMemorySpan(_rootKeyHandle!, Constants.X25519KeySize).MapSodiumFailure();
                if (rootKeyBytesResult.IsErr)
                    return Result<RatchetState, EcliptixProtocolFailure>.Err(rootKeyBytesResult.UnwrapErr());

                RatchetState proto = new()
                {
                    IsInitiator = _isInitiator,
                    CreatedAt = Timestamp.FromDateTimeOffset(_createdAt),
                    NonceCounter = (ulong)_nonceCounter,
                    PeerBundle = _peerBundle!.ToProtobufExchange(),
                    PeerDhPublicKey = _peerDhPublicKey != null ? ByteString.CopyFrom(_peerDhPublicKey.AsSpan()) : ByteString.Empty,
                    IsFirstReceivingRatchet = _isFirstReceivingRatchet,
                    RootKey = rootKeyBytesResult.Unwrap(),
                    SendingStep = sendingStepStateResult.Unwrap()
                };

                if (_receivingStep != null)
                {
                    Result<ChainStepState, EcliptixProtocolFailure> receivingStepStateResult = _receivingStep.ToProtoState();
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
        EcliptixProtocolChainStep? sendingStep = null;
        EcliptixProtocolChainStep? receivingStep = null;
        SodiumSecureMemoryHandle? rootKeyHandle = null;

        try
        {
            Result<EcliptixProtocolChainStep, EcliptixProtocolFailure> sendingStepResult = EcliptixProtocolChainStep.FromProtoState(ChainStepType.Sender, proto.SendingStep);
            if (sendingStepResult.IsErr)
                return Result<EcliptixProtocolConnection, EcliptixProtocolFailure>.Err(sendingStepResult.UnwrapErr());
            sendingStep = sendingStepResult.Unwrap();

            Result<EcliptixProtocolChainStep, EcliptixProtocolFailure> receivingStepResult =
                EcliptixProtocolChainStep.FromProtoState(ChainStepType.Receiver, proto.ReceivingStep);
            if (receivingStepResult.IsErr)
                return Result<EcliptixProtocolConnection, EcliptixProtocolFailure>.Err(receivingStepResult.UnwrapErr());
            receivingStep = receivingStepResult.Unwrap();

            Result<SodiumSecureMemoryHandle, EcliptixProtocolFailure> rootKeyResult = SodiumSecureMemoryHandle.Allocate(proto.RootKey.Length).MapSodiumFailure();
            if (rootKeyResult.IsErr)
                return Result<EcliptixProtocolConnection, EcliptixProtocolFailure>.Err(rootKeyResult.UnwrapErr());
            rootKeyHandle = rootKeyResult.Unwrap();
            SecureByteStringInterop.SecureCopyWithCleanup(proto.RootKey, out byte[] rootKeyBytes);
            Result<Unit, EcliptixProtocolFailure> writeResult = rootKeyHandle.Write(rootKeyBytes).MapSodiumFailure();
            if (writeResult.IsErr)
                return Result<EcliptixProtocolConnection, EcliptixProtocolFailure>.Err(writeResult.UnwrapErr());

            EcliptixProtocolConnection connection = new(connectId, proto, sendingStep, receivingStep, rootKeyHandle);

            byte[] tempRootKey = new byte[Constants.X25519KeySize];
            rootKeyHandle.Read(tempRootKey);

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

    public Result<PublicKeyBundle, EcliptixProtocolFailure> GetPeerBundle()
    {
        lock (_lock)
        {
            Result<Unit, EcliptixProtocolFailure> disposedCheck = CheckDisposed();
            if (disposedCheck.IsErr)
                return Result<PublicKeyBundle, EcliptixProtocolFailure>.Err(disposedCheck.UnwrapErr());

            if (_peerBundle != null)
                return Result<PublicKeyBundle, EcliptixProtocolFailure>.Ok(_peerBundle);
            else
                return Result<PublicKeyBundle, EcliptixProtocolFailure>.Err(
                    EcliptixProtocolFailure.Generic("Peer bundle has not been set in the connection."));
        }
    }

    public void Dispose()
    {
        Dispose(true);
    }

    internal Result<Unit, EcliptixProtocolFailure> SetPeerBundle(PublicKeyBundle peerBundle)
    {
        lock (_lock)
        {
            Result<Unit, EcliptixProtocolFailure> disposedCheck = CheckDisposed();
            if (disposedCheck.IsErr)
                return disposedCheck;

            _peerBundle = peerBundle;
            return Result<Unit, EcliptixProtocolFailure>.Ok(Unit.Value);
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
                Result<Unit, EcliptixProtocolFailure> disposedCheck = CheckDisposed();
                if (disposedCheck.IsErr)
                {
                    tempRootHandle?.Dispose();
                    return disposedCheck;
                }

                Result<Unit, EcliptixProtocolFailure> finalizedCheck = CheckIfNotFinalized();
                if (finalizedCheck.IsErr)
                {
                    tempRootHandle?.Dispose();
                    return finalizedCheck;
                }

                Result<Unit, EcliptixProtocolFailure> validationResult = ValidateInitialKeys(initialRootKey, initialPeerDhPublicKey);
                if (validationResult.IsErr)
                {
                    tempRootHandle?.Dispose();
                    return validationResult;
                }

                peerDhPublicCopy = (byte[])initialPeerDhPublicKey.Clone();

                Result<SodiumSecureMemoryHandle, SodiumFailure> allocateResult = SodiumSecureMemoryHandle.Allocate(Constants.X25519KeySize);
                if (allocateResult.IsErr)
                {
                    tempRootHandle?.Dispose();
                    return Result<Unit, EcliptixProtocolFailure>.Err(allocateResult.UnwrapErr().ToEcliptixProtocolFailure());
                }

                tempRootHandle = allocateResult.Unwrap();

                Result<Unit, SodiumFailure> writeResult = tempRootHandle.Write(initialRootKey);
                if (writeResult.IsErr)
                {
                    tempRootHandle?.Dispose();
                    return Result<Unit, EcliptixProtocolFailure>.Err(writeResult.UnwrapErr().ToEcliptixProtocolFailure());
                }

                localSenderCk = ArrayPool<byte>.Shared.Rent(Constants.X25519KeySize);
                localReceiverCk = ArrayPool<byte>.Shared.Rent(Constants.X25519KeySize);

                Result<Unit, EcliptixProtocolFailure> chainKeysResult = DeriveInitialChainKeys(initialRootKey, localSenderCk, localReceiverCk);
                if (chainKeysResult.IsErr)
                {
                    tempRootHandle?.Dispose();
                    return chainKeysResult;
                }

                Result<byte[], SodiumFailure> readResult = _persistentDhPrivateKeyHandle!.ReadBytes(Constants.X25519PrivateKeySize);
                if (readResult.IsErr)
                {
                    tempRootHandle?.Dispose();
                    return Result<Unit, EcliptixProtocolFailure>.Err(readResult.UnwrapErr().ToEcliptixProtocolFailure());
                }

                persistentPrivKeyBytes = readResult.Unwrap();

                byte[] senderKey = localSenderCk.AsSpan(0, Constants.X25519KeySize).ToArray();
                Result<Unit, EcliptixProtocolFailure> updateSenderResult = _sendingStep.UpdateKeysAfterDhRatchet(senderKey);
                if (updateSenderResult.IsErr)
                {
                    tempRootHandle?.Dispose();
                    return updateSenderResult;
                }

                byte[] receiverKey = localReceiverCk.AsSpan(0, Constants.X25519KeySize).ToArray();
                Result<EcliptixProtocolChainStep, EcliptixProtocolFailure> createReceiverResult = EcliptixProtocolChainStep.Create(
                    ChainStepType.Receiver, receiverKey, persistentPrivKeyBytes, _persistentDhPublicKey);
                if (createReceiverResult.IsErr)
                {
                    tempRootHandle?.Dispose();
                    return Result<Unit, EcliptixProtocolFailure>.Err(createReceiverResult.UnwrapErr());
                }

                EcliptixProtocolChainStep receivingStep = createReceiverResult.Unwrap();

                _rootKeyHandle = tempRootHandle;
                tempRootHandle = null;
                _receivingStep = receivingStep;
                _peerDhPublicKey = peerDhPublicCopy;
                peerDhPublicCopy = null;

                return Result<Unit, EcliptixProtocolFailure>.Ok(Unit.Value);
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
        using IDisposable profilerScope = _profiler.StartOperation("PrepareNextSendMessage");
        lock (_lock)
        {
            byte[]? keyMaterial = null;
            try
            {
                Result<Unit, EcliptixProtocolFailure> disposedCheckResult = CheckDisposed();
                if (disposedCheckResult.IsErr) return Result<(EcliptixMessageKey, bool), EcliptixProtocolFailure>.Err(disposedCheckResult.UnwrapErr());

                Result<Unit, EcliptixProtocolFailure> expirationCheckResult = EnsureNotExpired();
                if (expirationCheckResult.IsErr) return Result<(EcliptixMessageKey, bool), EcliptixProtocolFailure>.Err(expirationCheckResult.UnwrapErr());

                Result<EcliptixProtocolChainStep, EcliptixProtocolFailure> sendingStepResult = EnsureSendingStepInitialized();
                if (sendingStepResult.IsErr) return Result<(EcliptixMessageKey, bool), EcliptixProtocolFailure>.Err(sendingStepResult.UnwrapErr());

                EcliptixProtocolChainStep sendingStep = sendingStepResult.Unwrap();

                Result<bool, EcliptixProtocolFailure> dhRatchetResult = MaybePerformSendingDhRatchet(sendingStep);
                if (dhRatchetResult.IsErr) return Result<(EcliptixMessageKey, bool), EcliptixProtocolFailure>.Err(dhRatchetResult.UnwrapErr());

                bool includeDhKey = dhRatchetResult.Unwrap();

                Result<uint, EcliptixProtocolFailure> currentIndexResult = sendingStep.GetCurrentIndex();
                if (currentIndexResult.IsErr) return Result<(EcliptixMessageKey, bool), EcliptixProtocolFailure>.Err(currentIndexResult.UnwrapErr());

                uint currentIndex = currentIndexResult.Unwrap();

                Result<EcliptixMessageKey, EcliptixProtocolFailure> derivedKeyResult = sendingStep.GetOrDeriveKeyFor(currentIndex + 1);
                if (derivedKeyResult.IsErr) return Result<(EcliptixMessageKey, bool), EcliptixProtocolFailure>.Err(derivedKeyResult.UnwrapErr());

                EcliptixMessageKey derivedKey = derivedKeyResult.Unwrap();

                Result<Unit, EcliptixProtocolFailure> setIndexResult = sendingStep.SetCurrentIndex(currentIndex + 1);
                if (setIndexResult.IsErr) return Result<(EcliptixMessageKey, bool), EcliptixProtocolFailure>.Err(setIndexResult.UnwrapErr());

                keyMaterial = ArrayPool<byte>.Shared.Rent(Constants.AesKeySize);
                Span<byte> keySpan = keyMaterial.AsSpan(0, Constants.AesKeySize);
                derivedKey.ReadKeyMaterial(keySpan);

                Result<EcliptixMessageKey, EcliptixProtocolFailure> clonedKeyResult = EcliptixMessageKey.New(derivedKey.Index, keySpan);
                if (clonedKeyResult.IsErr) return Result<(EcliptixMessageKey, bool), EcliptixProtocolFailure>.Err(clonedKeyResult.UnwrapErr());

                EcliptixMessageKey clonedKey = clonedKeyResult.Unwrap();

                _sendingStep.PruneOldKeys();
                return Result<(EcliptixMessageKey, bool), EcliptixProtocolFailure>.Ok((clonedKey, includeDhKey));
            }
            finally
            {
                if (keyMaterial != null) ArrayPool<byte>.Shared.Return(keyMaterial, clearArray: true);
            }
        }
    }

    internal Result<EcliptixMessageKey, EcliptixProtocolFailure> ProcessReceivedMessage(uint receivedIndex)
    {
        using IDisposable profilerScope = _profiler.StartOperation("ProcessReceivedMessage");
        lock (_lock)
        {
            Result<Unit, EcliptixProtocolFailure> disposedCheckResult = CheckDisposed();
            if (disposedCheckResult.IsErr) return Result<EcliptixMessageKey, EcliptixProtocolFailure>.Err(disposedCheckResult.UnwrapErr());

            Result<Unit, EcliptixProtocolFailure> expirationCheckResult = EnsureNotExpired();
            if (expirationCheckResult.IsErr) return Result<EcliptixMessageKey, EcliptixProtocolFailure>.Err(expirationCheckResult.UnwrapErr());

            Result<EcliptixProtocolChainStep, EcliptixProtocolFailure> receivingStepResult = EnsureReceivingStepInitialized();
            if (receivingStepResult.IsErr) return Result<EcliptixMessageKey, EcliptixProtocolFailure>.Err(receivingStepResult.UnwrapErr());

            Result<uint, EcliptixProtocolFailure> currentIndexResult = _receivingStep!.GetCurrentIndex();
            if (currentIndexResult.IsOk)
            {
                uint currentIndex = currentIndexResult.Unwrap();
                if (receivedIndex > currentIndex + 1)
                {
                    uint gapSize = receivedIndex - currentIndex - 1;
                    
                    
                    System.Diagnostics.Debug.WriteLine($"Message gap detected: missing {gapSize} messages between {currentIndex + 1} and {receivedIndex}");
                }
            }

            Result<EcliptixMessageKey, EcliptixProtocolFailure> derivedKeyResult = _receivingStep!.GetOrDeriveKeyFor(receivedIndex);
            if (derivedKeyResult.IsErr) return Result<EcliptixMessageKey, EcliptixProtocolFailure>.Err(derivedKeyResult.UnwrapErr());

            EcliptixMessageKey derivedKey = derivedKeyResult.Unwrap();

            Result<Unit, EcliptixProtocolFailure> setIndexResult = _receivingStep!.SetCurrentIndex(derivedKey.Index);
            if (setIndexResult.IsErr) return Result<EcliptixMessageKey, EcliptixProtocolFailure>.Err(setIndexResult.UnwrapErr());

            _receivingStep!.PruneOldKeys();

            return Result<EcliptixMessageKey, EcliptixProtocolFailure>.Ok(derivedKey);
        }
    }

    public Result<Unit, EcliptixProtocolFailure> PerformReceivingRatchet(byte[]? receivedDhKey)
    {
        using IDisposable profilerScope = _profiler.StartOperation("PerformReceivingRatchet");
        lock (_lock)
        {
            if (receivedDhKey == null) return Result<Unit, EcliptixProtocolFailure>.Ok(Unit.Value);

            bool keysAreEqual = false;
            if (_peerDhPublicKey != null)
            {
                Result<bool, SodiumFailure> constantTimeResult = SodiumInterop.ConstantTimeEquals(
                    receivedDhKey.AsSpan(), _peerDhPublicKey);
                keysAreEqual = constantTimeResult.IsOk && constantTimeResult.Unwrap();
            }
            if (keysAreEqual) return Result<Unit, EcliptixProtocolFailure>.Ok(Unit.Value);

            Result<EcliptixProtocolChainStep, EcliptixProtocolFailure> receivingStepResult = EnsureReceivingStepInitialized();
            if (receivingStepResult.IsErr) return Result<Unit, EcliptixProtocolFailure>.Err(receivingStepResult.UnwrapErr());

            EcliptixProtocolChainStep receivingStep = receivingStepResult.Unwrap();

            Result<uint, EcliptixProtocolFailure> currentIndexResult = receivingStep.GetCurrentIndex();
            if (currentIndexResult.IsErr) return Result<Unit, EcliptixProtocolFailure>.Err(currentIndexResult.UnwrapErr());

            uint currentIndex = currentIndexResult.Unwrap();
            bool shouldRatchetNow = _isFirstReceivingRatchet || _ratchetConfig.ShouldRatchet(currentIndex + 1, _lastRatchetTime, _receivedNewDhKey);

            if (shouldRatchetNow)
            {
                _isFirstReceivingRatchet = false;
                return PerformDhRatchet(isSender: false, receivedDhPublicKeyBytes: receivedDhKey);
            }

            WipeIfNotNull(_peerDhPublicKey);
            _peerDhPublicKey = (byte[])receivedDhKey.Clone();
            _receivedNewDhKey = true;
            return Result<Unit, EcliptixProtocolFailure>.Ok(Unit.Value);
        }
    }

    internal Result<byte[], EcliptixProtocolFailure> GenerateNextNonce()
    {
        lock (_lock)
        {
            Result<Unit, EcliptixProtocolFailure> disposedCheckResult = CheckDisposed();
            if (disposedCheckResult.IsErr) return Result<byte[], EcliptixProtocolFailure>.Err(disposedCheckResult.UnwrapErr());

            byte[] nonceBuffer = new byte[AesGcmNonceSize];
            RandomNumberGenerator.Fill(nonceBuffer.AsSpan(0, 8));

            long nextCounter = Interlocked.Increment(ref _nonceCounter);
            if (nextCounter >= uint.MaxValue)
            {
                return Result<byte[], EcliptixProtocolFailure>.Err(
                    EcliptixProtocolFailure.Generic("Nonce counter overflow detected - connection must be rekeyed"));
            }

            BinaryPrimitives.WriteUInt32LittleEndian(nonceBuffer.AsSpan(8), (uint)nextCounter);
            return Result<byte[], EcliptixProtocolFailure>.Ok(nonceBuffer);
        }
    }

    public Result<Unit, EcliptixProtocolFailure> CheckReplayProtection(ReadOnlySpan<byte> nonce, ulong messageIndex)
    {
        if (_disposed)
            return Result<Unit, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.ObjectDisposed(nameof(EcliptixProtocolConnection)));

        Result<Unit, EcliptixProtocolFailure> replayCheckResult = _replayProtection.CheckAndRecordMessage(nonce, messageIndex);
        if (replayCheckResult.IsErr)
        {
            return Result<Unit, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.Generic($"Replay protection check failed: {replayCheckResult.UnwrapErr()}"));
        }

        return Result<Unit, EcliptixProtocolFailure>.Ok(Unit.Value);
    }

    public Dictionary<string, (long Count, double AvgMs, double MaxMs, double MinMs)> GetPerformanceMetrics()
    {
        return _profiler.GetMetrics();
    }

    public void UpdateRatchetConfig(RatchetConfig newConfig)
    {
        lock (_lock)
        {
            if (_disposed) return;
            
        }
    }

    public Result<Option<EcliptixMessageKey>, EcliptixProtocolFailure> TryRecoverMessageKey(uint messageIndex)
    {
        return _ratchetRecovery.TryRecoverMessageKey(messageIndex);
    }

    public uint ConnectId => _id;

    public PerformanceProfiler GetProfiler()
    {
        return _profiler;
    }

    public bool IsInitiator()
    {
        return _isInitiator;
    }

    public void NotifyRatchetRotation()
    {
        _replayProtection.OnRatchetRotation();
    }

    public Result<byte[]?, EcliptixProtocolFailure> GetCurrentSenderDhPublicKey()
    {
        lock (_lock)
        {
            Result<Unit, EcliptixProtocolFailure> disposedCheckResult = CheckDisposed();
            if (disposedCheckResult.IsErr) return Result<byte[]?, EcliptixProtocolFailure>.Err(disposedCheckResult.UnwrapErr());

            Result<EcliptixProtocolChainStep, EcliptixProtocolFailure> sendingStepResult = EnsureSendingStepInitialized();
            if (sendingStepResult.IsErr) return Result<byte[]?, EcliptixProtocolFailure>.Err(sendingStepResult.UnwrapErr());

            EcliptixProtocolChainStep step = sendingStepResult.Unwrap();
            return step.ReadDhPublicKey();
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
                _replayProtection?.Dispose();
                _ratchetRecovery?.Dispose();
                _profiler?.Reset();

                _rootKeyHandle?.Dispose();
                _sendingStep?.Dispose();
                _receivingStep?.Dispose();
                _persistentDhPrivateKeyHandle?.Dispose();
                if (_currentSendingDhPrivateKeyHandle != null &&
                    _currentSendingDhPrivateKeyHandle != _initialSendingDhPrivateKeyHandle)
                    _currentSendingDhPrivateKeyHandle.Dispose();
                _initialSendingDhPrivateKeyHandle?.Dispose();

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
        using IDisposable profilerScope = _profiler.StartOperation("PerformDhRatchet");
        byte[]? dhSecret = null, newRootKey = null, newChainKeyForTargetStep = null, newEphemeralPublicKey = null;
        byte[]? localPrivateKeyBytes = null, currentRootKey = null, newDhPrivateKeyBytes = null;
        byte[]? hkdfOutput = null;
        SodiumSecureMemoryHandle? newEphemeralSkHandle = null;

        try
        {
            Result<Unit, EcliptixProtocolFailure> disposedCheckResult = CheckDisposed();
            if (disposedCheckResult.IsErr) return disposedCheckResult;

            if (_rootKeyHandle is not { IsInvalid: false })
            {
                return Result<Unit, EcliptixProtocolFailure>.Err(
                    EcliptixProtocolFailure.Generic("Root key handle not initialized."));
            }

            Result<Unit, EcliptixProtocolFailure> dhCalculationResult = Result<Unit, EcliptixProtocolFailure>.Try(() =>
            {
                if (isSender)
                {
                    if (_sendingStep == null || _peerDhPublicKey == null)
                        throw new InvalidOperationException("Sender ratchet pre-conditions not met.");
                    Result<(SodiumSecureMemoryHandle skHandle, byte[] pk), EcliptixProtocolFailure> ephResult =
                        SodiumInterop.GenerateX25519KeyPair("Ephemeral DH Ratchet");
                    if (ephResult.IsErr)
                        throw new InvalidOperationException($"Failed to generate ephemeral key pair: {ephResult.UnwrapErr().Message}");
                    (newEphemeralSkHandle, newEphemeralPublicKey) = ephResult.Unwrap();
                    Result<byte[], EcliptixProtocolFailure> privKeyResult = newEphemeralSkHandle.ReadBytes(Constants.X25519PrivateKeySize).MapSodiumFailure();
                    if (privKeyResult.IsErr)
                        throw new InvalidOperationException($"Failed to read ephemeral private key: {privKeyResult.UnwrapErr().Message}");
                    localPrivateKeyBytes = privKeyResult.Unwrap();
                    dhSecret = ScalarMult.Mult(localPrivateKeyBytes, _peerDhPublicKey);
                }
                else
                {
                    if (_receivingStep == null || receivedDhPublicKeyBytes is not
                            { Length: Constants.X25519PublicKeySize })
                        throw new InvalidOperationException("Receiver ratchet pre-conditions not met.");
                    Result<byte[], EcliptixProtocolFailure> privKeyResult = _currentSendingDhPrivateKeyHandle!.ReadBytes(Constants.X25519PrivateKeySize).MapSodiumFailure();
                    if (privKeyResult.IsErr)
                        throw new InvalidOperationException($"Failed to read current DH private key: {privKeyResult.UnwrapErr().Message}");
                    localPrivateKeyBytes = privKeyResult.Unwrap();
                    dhSecret = ScalarMult.Mult(localPrivateKeyBytes, receivedDhPublicKeyBytes);
                }
            }, ex => EcliptixProtocolFailure.DeriveKey("DH calculation failed during ratchet.", ex));
            if (dhCalculationResult.IsErr) return dhCalculationResult;

            Result<byte[], EcliptixProtocolFailure> rootKeyReadResult = _rootKeyHandle!.ReadBytes(Constants.X25519KeySize).MapSodiumFailure();
            if (rootKeyReadResult.IsErr)
                return Result<Unit, EcliptixProtocolFailure>.Err(rootKeyReadResult.UnwrapErr());
            currentRootKey = rootKeyReadResult.Unwrap();
            hkdfOutput = ArrayPool<byte>.Shared.Rent(Constants.X25519KeySize * 2);
            try
            {
                HKDF.DeriveKey(
                    HashAlgorithmName.SHA256,
                    ikm: dhSecret!,
                    output: hkdfOutput.AsSpan(0, Constants.X25519KeySize * 2),
                    salt: currentRootKey,
                    info: DhRatchetInfo
                );
            }
            catch (Exception ex)
            {
                ArrayPool<byte>.Shared.Return(hkdfOutput);
                hkdfOutput = null;
                return Result<Unit, EcliptixProtocolFailure>.Err(
                    EcliptixProtocolFailure.DeriveKey("HKDF failed during DH ratchet.", ex));
            }

            newRootKey = hkdfOutput.AsSpan(0, Constants.X25519KeySize).ToArray();
            newChainKeyForTargetStep = hkdfOutput.AsSpan(Constants.X25519KeySize).ToArray();

            Result<Unit, EcliptixProtocolFailure> writeResult = _rootKeyHandle.Write(newRootKey).MapSodiumFailure();
            if (writeResult.IsErr) return writeResult.MapErr(f => f);

            Result<Unit, EcliptixProtocolFailure> updateResult;
            if (isSender)
            {
                Result<byte[], EcliptixProtocolFailure> newDhPrivResult = newEphemeralSkHandle!.ReadBytes(Constants.X25519PrivateKeySize).MapSodiumFailure();
                if (newDhPrivResult.IsErr) return Result<Unit, EcliptixProtocolFailure>.Err(newDhPrivResult.UnwrapErr());
                newDhPrivateKeyBytes = newDhPrivResult.Unwrap();
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

            _replayProtection.OnRatchetRotation();

            _receivedNewDhKey = false;
            _lastRatchetTime = DateTime.UtcNow;

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

    private Result<Unit, EcliptixProtocolFailure> CheckDisposed()
    {
        return _disposed
            ? Result<Unit, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.ObjectDisposed(nameof(EcliptixProtocolConnection)))
            : Result<Unit, EcliptixProtocolFailure>.Ok(Unit.Value);
    }

    private Result<Unit, EcliptixProtocolFailure> EnsureNotExpired()
    {
        Result<Unit, EcliptixProtocolFailure> disposedCheckResult = CheckDisposed();
        if (disposedCheckResult.IsErr) return disposedCheckResult;

        if (DateTimeOffset.UtcNow - _createdAt > ConnectTimeout)
        {
            return Result<Unit, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.Generic($"Session {_id} has expired."));
        }

        return Result<Unit, EcliptixProtocolFailure>.Ok(Unit.Value);
    }

    private Result<EcliptixProtocolChainStep, EcliptixProtocolFailure> EnsureSendingStepInitialized()
    {
        Result<Unit, EcliptixProtocolFailure> disposedCheckResult = CheckDisposed();
        if (disposedCheckResult.IsErr) return Result<EcliptixProtocolChainStep, EcliptixProtocolFailure>.Err(disposedCheckResult.UnwrapErr());

        if (_sendingStep == null)
        {
            return Result<EcliptixProtocolChainStep, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.Generic("Sending chain step not initialized."));
        }

        return Result<EcliptixProtocolChainStep, EcliptixProtocolFailure>.Ok(_sendingStep);
    }

    private Result<EcliptixProtocolChainStep, EcliptixProtocolFailure> EnsureReceivingStepInitialized()
    {
        Result<Unit, EcliptixProtocolFailure> disposedCheckResult = CheckDisposed();
        if (disposedCheckResult.IsErr) return Result<EcliptixProtocolChainStep, EcliptixProtocolFailure>.Err(disposedCheckResult.UnwrapErr());

        if (_receivingStep == null)
        {
            return Result<EcliptixProtocolChainStep, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.Generic("Receiving chain step not initialized."));
        }

        return Result<EcliptixProtocolChainStep, EcliptixProtocolFailure>.Ok(_receivingStep);
    }

    private Result<Unit, EcliptixProtocolFailure> CheckIfNotFinalized()
    {
        Result<Unit, EcliptixProtocolFailure> disposedCheckResult = CheckDisposed();
        if (disposedCheckResult.IsErr) return disposedCheckResult;

        if (_rootKeyHandle != null || _receivingStep != null)
        {
            return Result<Unit, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.Generic("Session has already been finalized."));
        }

        return Result<Unit, EcliptixProtocolFailure>.Ok(Unit.Value);
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

            HKDF.DeriveKey(
                HashAlgorithmName.SHA256,
                ikm: rootKey,
                output: sendSpan,
                salt: null,
                info: InitialSenderChainInfo
            );

            HKDF.DeriveKey(
                HashAlgorithmName.SHA256,
                ikm: rootKey,
                output: recvSpan,
                salt: null,
                info: InitialReceiverChainInfo
            );

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
        Result<uint, EcliptixProtocolFailure> currentIndexResult = sendingStep.GetCurrentIndex();
        if (currentIndexResult.IsErr) return Result<bool, EcliptixProtocolFailure>.Err(currentIndexResult.UnwrapErr());

        uint currentIndex = currentIndexResult.Unwrap();
        bool shouldRatchet = _ratchetConfig.ShouldRatchet(currentIndex + 1, _lastRatchetTime, _receivedNewDhKey);

        if (shouldRatchet)
        {
            Result<Unit, EcliptixProtocolFailure> ratchetResult = PerformDhRatchet(true);
            if (ratchetResult.IsErr) return Result<bool, EcliptixProtocolFailure>.Err(ratchetResult.UnwrapErr());

            _receivedNewDhKey = false;
            return Result<bool, EcliptixProtocolFailure>.Ok(true);
        }

        return Result<bool, EcliptixProtocolFailure>.Ok(false);
    }
}
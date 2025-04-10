using Ecliptix.Core.Protocol.Utilities;
using Ecliptix.Protobuf.PubKeyExchange;
using Sodium;
using System.Buffers.Binary;

namespace Ecliptix.Core.Protocol;

public sealed class ShieldSession : IDisposable
{
    private const int MaxProcessedIds = 6000;
    private static readonly TimeSpan SessionTimeout = TimeSpan.FromHours(24);

    private readonly uint _id;
    private readonly PublicKeyBundle _localBundle;
    private PublicKeyBundle? _peerBundle;
    private ShieldChainStep? _sendingStep;
    private ShieldChainStep? _receivingStep;
    private SodiumSecureMemoryHandle? _rootKeyHandle;

    private readonly SortedDictionary<uint, ShieldMessageKey> _messageKeys;
    private PubKeyExchangeState _state;
    private ulong _nonceCounter;
    private readonly DateTimeOffset _createdAt;
    private readonly SortedSet<uint> _missedReceiverIndices;
    private readonly SortedSet<uint> _processedMessageIds;
    private byte[]? _lastReceivedDhPublicKeyBytes;
    private byte[]? _peerSendingDhPublicKeyBytes;
    private volatile bool _disposed = false;

    public ShieldSession(uint id, PublicKeyBundle localBundle)
    {
        _id = id;
        _localBundle = localBundle ?? throw new ArgumentNullException(nameof(localBundle));
        _peerBundle = null;
        _sendingStep = null;
        _receivingStep = null;
        _rootKeyHandle = null;
        _messageKeys = new SortedDictionary<uint, ShieldMessageKey>();
        _state = PubKeyExchangeState.Init;
        _nonceCounter = 0;
        _createdAt = DateTimeOffset.UtcNow;
        _missedReceiverIndices = new SortedSet<uint>();
        _processedMessageIds = new SortedSet<uint>();
        _lastReceivedDhPublicKeyBytes = null;
        _peerSendingDhPublicKeyBytes = null;
    }

    public uint SessionId => _id;
    public PubKeyExchangeState State => _state;
    public PublicKeyBundle LocalBundle => _localBundle;

    public PublicKeyBundle PeerBundle => _peerBundle ?? throw new InvalidOperationException("Peer bundle not set.");

    internal void SetConnectionState(PubKeyExchangeState newState) => _state = newState;

    internal void SetPeerBundle(PublicKeyBundle peerBundle) =>
        _peerBundle = peerBundle ?? throw new ArgumentNullException(nameof(peerBundle));

    internal (ShieldMessageKey MessageKey, byte[] Nonce, byte[]? NewDhPublicKey) PrepareNextSendMessage()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        EnsureNotExpired();
        var sendingStep = _sendingStep ?? throw new InvalidOperationException("Sending chain step not initialized.");
        if (_rootKeyHandle == null) throw new InvalidOperationException("Root key handle not initialized.");

        uint nextIndexToSend = sendingStep.NextMessageIndex;
        Console.WriteLine(
            $"[{sendingStep.StepType}] Preparing message #{nextIndexToSend}. Current Index: {sendingStep.CurrentIndex}");
        Console.WriteLine(
            $"[{sendingStep.StepType}] Current Sending Chain Key: {Convert.ToHexString(sendingStep.ReadChainKey())}");

        byte[]? newSenderDhPublicKeyBytes = null;
        byte[]? newSenderDhPrivateKey = null;

        bool shouldRotate = (nextIndexToSend > 0 && nextIndexToSend % Constants.DhRotationInterval == 0);

        if (shouldRotate)
        {
            Console.WriteLine(
                $"[{sendingStep.StepType}] Triggering DH Ratchet before sending message #{nextIndexToSend}.");
            newSenderDhPrivateKey = SodiumCore.GetRandomBytes(Constants.X25519PrivateKeySize);
            newSenderDhPublicKeyBytes = ScalarMult.Base(newSenderDhPrivateKey);
            Console.WriteLine(
                $"[{sendingStep.StepType}] Generated New DH PK: {Convert.ToHexString(newSenderDhPublicKeyBytes)}");

            byte[] peerDhPublicKey = _peerSendingDhPublicKeyBytes ??
                                     throw new InvalidOperationException(
                                         "Cannot perform sender DH ratchet: Peer sending DH key unavailable.");
            Console.WriteLine(
                $"[{sendingStep.StepType}] Using Peer Sending DH PK: {Convert.ToHexString(peerDhPublicKey)}");

            byte[]? dhSecret = null;
            byte[]? currentRootKey = null;
            byte[]? newRootKey = null;
            byte[]? newSendingChainKey = null;
            byte[]? hkdfOutput = null;
            byte[]? dhSecretBytes = null;
            byte[]? rootKeyBytes = null;

            try
            {
                dhSecret = ScalarMult.Mult(newSenderDhPrivateKey, peerDhPublicKey);
                Console.WriteLine($"[{sendingStep.StepType}] Computed DH Secret: {Convert.ToHexString(dhSecret)}");
                currentRootKey = new byte[Constants.X25519KeySize];
                _rootKeyHandle.Read(currentRootKey.AsSpan());

                newRootKey = new byte[Constants.X25519KeySize];
                newSendingChainKey = new byte[Constants.X25519KeySize];
                hkdfOutput = new byte[Constants.X25519KeySize * 2];
                dhSecretBytes = new byte[dhSecret.Length];
                rootKeyBytes = new byte[currentRootKey.Length];

                using (var sdh = SodiumSecureMemoryHandle.Allocate(dhSecret.Length))
                {
                    sdh.Write(dhSecret);
                    sdh.Read(dhSecretBytes.AsSpan());
                }

                using (var srk = SodiumSecureMemoryHandle.Allocate(currentRootKey.Length))
                {
                    srk.Write(currentRootKey);
                    srk.Read(rootKeyBytes.AsSpan());
                }

                using (HkdfSha256 hkdf = new HkdfSha256(dhSecretBytes, rootKeyBytes))
                {
                    hkdf.Expand(Constants.DhRatchetInfo, hkdfOutput);
                }

                Buffer.BlockCopy(hkdfOutput, 0, newRootKey, 0, newRootKey.Length);
                Buffer.BlockCopy(hkdfOutput, newRootKey.Length, newSendingChainKey, 0, newSendingChainKey.Length);

                Console.WriteLine($"[{sendingStep.StepType}] Derived New Root Key: {Convert.ToHexString(newRootKey)}");
                Console.WriteLine(
                    $"[{sendingStep.StepType}] Derived New Sending CK: {Convert.ToHexString(newSendingChainKey)}");

                _rootKeyHandle.Write(newRootKey);
                sendingStep.UpdateKeysAfterDhRatchet(newSendingChainKey, newSenderDhPrivateKey,
                    newSenderDhPublicKeyBytes);
                ClearMessageKeyCache();
                nextIndexToSend = sendingStep.NextMessageIndex; // Reset to next index after ratchet
                Console.WriteLine(
                    $"[{sendingStep.StepType}] DH Rotation complete. Index reset. Next msg index: {nextIndexToSend}.");
            }
            finally
            {
                WipeIfNotNull(dhSecret);
                WipeIfNotNull(currentRootKey);
                WipeIfNotNull(newRootKey);
                WipeIfNotNull(newSendingChainKey);
                WipeIfNotNull(hkdfOutput);
                WipeIfNotNull(dhSecretBytes);
                WipeIfNotNull(rootKeyBytes);
                WipeIfNotNull(newSenderDhPrivateKey);
            }
        }

        ShieldMessageKey messageKey = sendingStep.GetOrDeriveKeyFor(nextIndexToSend, _messageKeys);

        byte[]? keyMaterial = null;
        ShieldMessageKey? clonedMessageKey = null;
        try
        {
            keyMaterial = new byte[Constants.AesKeySize];
            messageKey.ReadKeyMaterial(keyMaterial);
            clonedMessageKey = new ShieldMessageKey(messageKey.Index, keyMaterial);
            if (clonedMessageKey.Index != nextIndexToSend)
                throw new InvalidOperationException(
                    $"Cloned key index mismatch: expected {nextIndexToSend}, got {clonedMessageKey.Index}");
            Console.WriteLine(
                $"[{sendingStep.StepType}] Cloned Message Key #{clonedMessageKey.Index}: {Convert.ToHexString(keyMaterial)}");
        }
        finally
        {
            WipeIfNotNull(keyMaterial);
        }

        Console.WriteLine(
            $"[{sendingStep.StepType}] Prepared Message Key #{clonedMessageKey.Index}. Current Index now: {sendingStep.CurrentIndex}");
        byte[] nonce = GenerateNextNonce(ChainStepType.Sender);
        return (clonedMessageKey, nonce, newSenderDhPublicKeyBytes);
    }

    internal void FinalizeChainAndDhKeys(byte[] initialRootKey, byte[] initialPeerDhPublicKey)
{
    if (_sendingStep != null || _receivingStep != null || _rootKeyHandle != null)
        throw new InvalidOperationException("Session already finalized.");
    if (initialRootKey == null || initialRootKey.Length != Constants.X25519KeySize)
        throw new ArgumentException("Initial root key invalid.", nameof(initialRootKey));
    if (initialPeerDhPublicKey == null || initialPeerDhPublicKey.Length != Constants.X25519KeySize)
        throw new ArgumentException("Initial peer DH public key invalid.", nameof(initialPeerDhPublicKey));

    Console.WriteLine($"[Session {_id}] Finalizing Chains from Root Key...");
    Console.WriteLine($"[Session {_id}] Initial Peer DH Public Key: {Convert.ToHexString(initialPeerDhPublicKey)}");

    SodiumSecureMemoryHandle? tempRootHandle = null;
    ShieldChainStep? tempSendingStep = null;
    ShieldChainStep? tempReceivingStep = null;

    try
    {
        tempRootHandle = SodiumSecureMemoryHandle.Allocate(Constants.X25519KeySize);
        tempRootHandle.Write(initialRootKey);

        Span<byte> senderChainKey = stackalloc byte[Constants.X25519KeySize];
        Span<byte> receiverChainKey = stackalloc byte[Constants.X25519KeySize];
        using (HkdfSha256 hkdfSend = new HkdfSha256(initialRootKey, default))
            hkdfSend.Expand(Constants.InitialSenderChainInfo, senderChainKey);
        using (HkdfSha256 hkdfRecv = new HkdfSha256(initialRootKey, default))
            hkdfRecv.Expand(Constants.InitialReceiverChainInfo, receiverChainKey);

        byte[] senderDhPrivateKeyBytes = SodiumCore.GetRandomBytes(Constants.X25519PrivateKeySize);
        byte[] senderDhPublicKeyBytes = ScalarMult.Base(senderDhPrivateKeyBytes);

        // Sender chain: uses local sender chain key
        tempSendingStep = new ShieldChainStep(ChainStepType.Sender, senderChainKey.ToArray(), senderDhPrivateKeyBytes, senderDhPublicKeyBytes);
        // Receiver chain: uses peer’s sender chain key (swap with senderChainKey for symmetry)
        tempReceivingStep = new ShieldChainStep(ChainStepType.Receiver, senderChainKey.ToArray(), new byte[Constants.X25519PrivateKeySize], initialPeerDhPublicKey);

        _rootKeyHandle = tempRootHandle;
        _sendingStep = tempSendingStep;
        _receivingStep = tempReceivingStep;
        _peerSendingDhPublicKeyBytes = (byte[])initialPeerDhPublicKey.Clone();

        Console.WriteLine($"[Session {_id}] Sender Chain Key: {Convert.ToHexString(senderChainKey)}");
        Console.WriteLine($"[Session {_id}] Receiver Chain Key: {Convert.ToHexString(senderChainKey)}"); // Note: Receiver uses senderChainKey
        Console.WriteLine($"[Session {_id}] Chains and initial DH keys finalized successfully.");
    }
    catch (Exception ex)
    {
        tempRootHandle?.Dispose();
        tempSendingStep?.Dispose();
        tempReceivingStep?.Dispose();
        throw new ShieldChainStepException($"Failed to finalize session {_id}: {ex.Message}", ex);
    }
}

    internal ShieldMessageKey ProcessReceivedMessage(uint receivedIndex, byte[]? receivedDhPublicKeyBytes)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        EnsureNotExpired();
        var receivingStep =
            _receivingStep ?? throw new InvalidOperationException("Receiving chain step not initialized.");
        if (_rootKeyHandle == null) throw new InvalidOperationException("Root key handle not initialized.");

        Console.WriteLine(
            $"[{receivingStep.StepType}] Processing received message #{receivedIndex}. Current Index: {receivingStep.CurrentIndex}");
        Console.WriteLine(
            $"[{receivingStep.StepType}] Current Receiving Chain Key: {Convert.ToHexString(receivingStep.ReadChainKey())}");

        if (receivedDhPublicKeyBytes != null && receivedDhPublicKeyBytes.Length == Constants.X25519KeySize)
        {
            Console.WriteLine(
                $"[{receivingStep.StepType}] Processing received Peer DH PK: {Convert.ToHexString(receivedDhPublicKeyBytes)}");
            Console.WriteLine($"[{receivingStep.StepType}] Received new Peer DH PK, performing DH Ratchet response.");

            byte[]? dhSecret = null;
            byte[]? currentRootKey = null;
            byte[]? newRootKey = null;
            byte[]? newReceivingChainKey = null;
            byte[]? hkdfOutput = null;
            byte[]? senderDhPrivateKeyBytes = null;
            byte[]? senderDhPublicKeyBytes = null;

            try
            {
                // Generate new DH key pair for the receiver’s response
                senderDhPrivateKeyBytes = SodiumCore.GetRandomBytes(Constants.X25519PrivateKeySize);
                senderDhPublicKeyBytes = ScalarMult.Base(senderDhPrivateKeyBytes);

                dhSecret = ScalarMult.Mult(senderDhPrivateKeyBytes, receivedDhPublicKeyBytes);
                Console.WriteLine($"[{receivingStep.StepType}] Computed DH Secret: {Convert.ToHexString(dhSecret)}");

                currentRootKey = new byte[Constants.X25519KeySize];
                _rootKeyHandle.Read(currentRootKey.AsSpan());

                newRootKey = new byte[Constants.X25519KeySize];
                newReceivingChainKey = new byte[Constants.X25519KeySize];
                hkdfOutput = new byte[Constants.X25519KeySize * 2];

                using (HkdfSha256 hkdf = new HkdfSha256(dhSecret, currentRootKey))
                {
                    hkdf.Expand(Constants.DhRatchetInfo, hkdfOutput);
                }

                Buffer.BlockCopy(hkdfOutput, 0, newRootKey, 0, newRootKey.Length);
                Buffer.BlockCopy(hkdfOutput, newRootKey.Length, newReceivingChainKey, 0, newReceivingChainKey.Length);

                Console.WriteLine(
                    $"[{receivingStep.StepType}] Derived New Root Key: {Convert.ToHexString(newRootKey)}");
                Console.WriteLine(
                    $"[{receivingStep.StepType}] Derived New Receiving CK: {Convert.ToHexString(newReceivingChainKey)}");

                _rootKeyHandle.Write(newRootKey);
                receivingStep.UpdateKeysAfterDhRatchet(newReceivingChainKey);
                _sendingStep.UpdateKeysAfterDhRatchet(newReceivingChainKey, senderDhPrivateKeyBytes,
                    senderDhPublicKeyBytes);
                _peerSendingDhPublicKeyBytes = (byte[])receivedDhPublicKeyBytes.Clone();
                ClearMessageKeyCache();

                Console.WriteLine($"[{receivingStep.StepType}] DH Response complete. Index reset.");
            }
            finally
            {
                WipeIfNotNull(dhSecret);
                WipeIfNotNull(currentRootKey);
                WipeIfNotNull(newRootKey);
                WipeIfNotNull(newReceivingChainKey);
                WipeIfNotNull(hkdfOutput);
                WipeIfNotNull(senderDhPrivateKeyBytes);
                WipeIfNotNull(senderDhPublicKeyBytes);
            }
        }

        ShieldMessageKey messageKey = receivingStep.GetOrDeriveKeyFor(receivedIndex, _messageKeys);
        _processedMessageIds.Add(receivedIndex);
        if (_processedMessageIds.Count > MaxProcessedIds)
            _processedMessageIds.Remove(_processedMessageIds.Min);

        byte[]? keyMaterial = null;
        ShieldMessageKey? clonedMessageKey = null;
        try
        {
            keyMaterial = new byte[Constants.AesKeySize];
            messageKey.ReadKeyMaterial(keyMaterial);
            clonedMessageKey = new ShieldMessageKey(messageKey.Index, keyMaterial);
            Console.WriteLine(
                $"[{receivingStep.StepType}] Cloned Message Key #{clonedMessageKey.Index}: {Convert.ToHexString(keyMaterial)}");
        }
        finally
        {
            WipeIfNotNull(keyMaterial);
        }

        return clonedMessageKey;
    }

    private byte[] GenerateNextNonce(ChainStepType chainStepType)
    {
        byte[] nonce = new byte[Constants.AesGcmNonceSize];
        BinaryPrimitives.WriteUInt64LittleEndian(nonce, Interlocked.Increment(ref _nonceCounter));
        return nonce;
    }

    internal void EnsureNotExpired()
    {
        if (DateTimeOffset.UtcNow - _createdAt > SessionTimeout)
            throw new ShieldChainStepException($"Session {_id} has expired.");
    }

    private void ClearMessageKeyCache()
    {
        Console.WriteLine($"[Session {_id}] Clearing message key cache ({_messageKeys.Count} items).");
        foreach (var kvp in _messageKeys)
            kvp.Value.Dispose();
        _messageKeys.Clear();
    }

    internal bool IsExpired()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return DateTimeOffset.UtcNow - _createdAt > SessionTimeout;
    }

    private static void WipeIfNotNull(byte[]? data)
    {
        if (data != null)
            SodiumInterop.SecureWipe(data);
    }

    public void Dispose()
    {
        if (!_disposed)
        {
            _disposed = true;
            _rootKeyHandle?.Dispose();
            _sendingStep?.Dispose();
            _receivingStep?.Dispose();
            ClearMessageKeyCache();
            SodiumInterop.SecureWipe(_lastReceivedDhPublicKeyBytes);
            SodiumInterop.SecureWipe(_peerSendingDhPublicKeyBytes);
            GC.SuppressFinalize(this);
        }
    }
}
using Ecliptix.Core.Protocol.Utilities;
using Ecliptix.Protobuf.PubKeyExchange;
using Sodium;
using System.Buffers.Binary;

namespace Ecliptix.Core.Protocol;

public sealed class ShieldSession : IDisposable
{
    private const int MaxProcessedIds = 6000;
    private const int DhRotationInterval = 50; // Assuming this from test context
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
    private byte[]? _peerSendingDhPublicKeyBytes; // Peer’s current DH public key
    private volatile bool _disposed = false;

    // Added for clarity and Signal alignment
    private bool _isInitiator; // True for Alice, false for Bob
    private bool _receivedNewDhKey = false;

    public ShieldSession(uint id, PublicKeyBundle localBundle, bool isInitiator)
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
        _peerSendingDhPublicKeyBytes = null;
        _isInitiator = isInitiator; // Set based on protocol role
    }

    public uint SessionId => _id;
    public PubKeyExchangeState State => _state;
    public PublicKeyBundle LocalBundle => _localBundle;
    public PublicKeyBundle PeerBundle => _peerBundle ?? throw new InvalidOperationException("Peer bundle not set.");
    public bool IsInitiator => _isInitiator;

    internal void SetConnectionState(PubKeyExchangeState newState) => _state = newState;

    internal void SetPeerBundle(PublicKeyBundle peerBundle) =>
        _peerBundle = peerBundle ?? throw new ArgumentNullException(nameof(peerBundle));

    internal (ShieldMessageKey MessageKey, bool IncludeDhKey) PrepareNextSendMessage()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        EnsureNotExpired();
        var sendingStep = _sendingStep ?? throw new InvalidOperationException("Sending chain step not initialized.");

        bool includeDhKey = false;

        bool shouldRatchet = _receivedNewDhKey || ((sendingStep.CurrentIndex + 1) % DhRotationInterval == 0);
        if (shouldRatchet)
        {
            Console.WriteLine($"[{sendingStep.StepType}] Triggering DH Ratchet before message preparation.");
            PerformDhRatchet();
            _receivedNewDhKey = false;
            includeDhKey = true;
        }

        uint nextIndex = sendingStep.CurrentIndex + 1;
        ShieldMessageKey messageKey = sendingStep.GetOrDeriveKeyFor(nextIndex, _messageKeys);
        sendingStep.CurrentIndex = nextIndex;

        byte[]? keyMaterial = null;
        ShieldMessageKey? clonedMessageKey = null;
        try
        {
            keyMaterial = new byte[Constants.AesKeySize];
            messageKey.ReadKeyMaterial(keyMaterial);
            clonedMessageKey = new ShieldMessageKey(messageKey.Index, keyMaterial);
        }
        finally
        {
            WipeIfNotNull(keyMaterial);
        }

        return (clonedMessageKey, includeDhKey);
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

            // Derive two chain keys from root key
            Span<byte> initiatorSenderChainKey = stackalloc byte[Constants.X25519KeySize];
            Span<byte> responderSenderChainKey = stackalloc byte[Constants.X25519KeySize];
            using (HkdfSha256 hkdfSend = new HkdfSha256(initialRootKey, null))
                hkdfSend.Expand(Constants.InitialSenderChainInfo, initiatorSenderChainKey);
            using (HkdfSha256 hkdfRecv = new HkdfSha256(initialRootKey, null))
                hkdfRecv.Expand(Constants.InitialReceiverChainInfo, responderSenderChainKey);

            byte[] senderDhPrivateKeyBytes = SodiumCore.GetRandomBytes(Constants.X25519PrivateKeySize);
            byte[] senderDhPublicKeyBytes = ScalarMult.Base(senderDhPrivateKeyBytes);

            // Assign chain keys based on role
            byte[] localSenderCK = _isInitiator ? initiatorSenderChainKey.ToArray() : responderSenderChainKey.ToArray();
            byte[] localReceiverCK =
                _isInitiator ? responderSenderChainKey.ToArray() : initiatorSenderChainKey.ToArray();

            tempSendingStep = new ShieldChainStep(ChainStepType.Sender, localSenderCK, senderDhPrivateKeyBytes,
                senderDhPublicKeyBytes);
            tempReceivingStep = new ShieldChainStep(ChainStepType.Receiver, localReceiverCK,
                new byte[Constants.X25519PrivateKeySize], initialPeerDhPublicKey);

            _rootKeyHandle = tempRootHandle;
            _sendingStep = tempSendingStep;
            _receivingStep = tempReceivingStep;
            _peerSendingDhPublicKeyBytes = (byte[])initialPeerDhPublicKey.Clone();

            Console.WriteLine($"[Session {_id}] Sender Chain Key: {Convert.ToHexString(localSenderCK)}");
            Console.WriteLine($"[Session {_id}] Receiver Chain Key: {Convert.ToHexString(localReceiverCK)}");
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

        // Step 1: Perform receiving DH ratchet if a new DH public key is received (BEFORE deriving the message key)
        if (receivedDhPublicKeyBytes != null && receivedDhPublicKeyBytes.Length == Constants.X25519KeySize &&
            !receivedDhPublicKeyBytes.SequenceEqual(_peerSendingDhPublicKeyBytes))
        {
            Console.WriteLine(
                $"[{receivingStep.StepType}] Processing received Peer DH PK: {Convert.ToHexString(receivedDhPublicKeyBytes)}");
            Console.WriteLine($"[{receivingStep.StepType}] Received new Peer DH PK, performing receiving ratchet.");

            byte[]? dhSecret = null;
            byte[]? currentRootKey = null;
            byte[]? newRootKey = null;
            byte[]? newChainKey = null;
            byte[]? hkdfOutput = null;

            try
            {
                // Use current DH private key for receiving ratchet
                byte[] currentDhPrivateKey = _sendingStep.ReadDhPrivateKey();
                dhSecret = ScalarMult.Mult(currentDhPrivateKey, receivedDhPublicKeyBytes);
                Console.WriteLine($"[{receivingStep.StepType}] Computed DH Secret: {Convert.ToHexString(dhSecret)}");

                currentRootKey = new byte[Constants.X25519KeySize];
                _rootKeyHandle.Read(currentRootKey.AsSpan());

                newRootKey = new byte[Constants.X25519KeySize];
                newChainKey = new byte[Constants.X25519KeySize];
                hkdfOutput = new byte[Constants.X25519KeySize * 2];

                using (HkdfSha256 hkdf = new HkdfSha256(dhSecret, currentRootKey))
                {
                    hkdf.Expand(Constants.DhRatchetInfo, hkdfOutput);
                }

                Buffer.BlockCopy(hkdfOutput, 0, newRootKey, 0, newRootKey.Length);
                Buffer.BlockCopy(hkdfOutput, newRootKey.Length, newChainKey, 0, newChainKey.Length);

                _rootKeyHandle.Write(newRootKey);
                receivingStep.UpdateKeysAfterDhRatchet(newChainKey);
                _peerSendingDhPublicKeyBytes = (byte[])receivedDhPublicKeyBytes.Clone();
                _receivedNewDhKey = true; // Flag for next send
                ClearMessageKeyCache();

                Console.WriteLine($"[{receivingStep.StepType}] Receiving ratchet complete. Index reset.");
            }
            finally
            {
                WipeIfNotNull(dhSecret);
                WipeIfNotNull(currentRootKey);
                WipeIfNotNull(newRootKey);
                WipeIfNotNull(newChainKey);
                WipeIfNotNull(hkdfOutput);
            }
        }

        // Step 2: Derive the message key AFTER the ratchet
        ShieldMessageKey messageKey = receivingStep.GetOrDeriveKeyFor(receivedIndex, _messageKeys);

        // Step 3: Clone the message key material
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

        _processedMessageIds.Add(receivedIndex);
        if (_processedMessageIds.Count > MaxProcessedIds)
            _processedMessageIds.Remove(_processedMessageIds.Min);

        return clonedMessageKey;
    }

    private void PerformDhRatchet()
    {
        var sendingStep = _sendingStep ?? throw new InvalidOperationException("Sending chain step not initialized.");
        if (_rootKeyHandle == null) throw new InvalidOperationException("Root key handle not initialized.");
        if (_peerSendingDhPublicKeyBytes == null) throw new InvalidOperationException("Peer DH public key not set.");

        byte[]? dhSecret = null;
        byte[]? currentRootKey = null;
        byte[]? newRootKey = null;
        byte[]? newChainKey = null;
        byte[]? hkdfOutput = null;
        byte[]? newDhPrivateKeyBytes = null;
        byte[]? newDhPublicKeyBytes = null;

        try
        {
            newDhPrivateKeyBytes = SodiumCore.GetRandomBytes(Constants.X25519PrivateKeySize);
            newDhPublicKeyBytes = ScalarMult.Base(newDhPrivateKeyBytes);
            Console.WriteLine(
                $"[{sendingStep.StepType}] Generated New DH PK: {Convert.ToHexString(newDhPublicKeyBytes)}");

            Console.WriteLine(
                $"[{sendingStep.StepType}] Using Peer Sending DH PK: {Convert.ToHexString(_peerSendingDhPublicKeyBytes)}");
            dhSecret = ScalarMult.Mult(newDhPrivateKeyBytes, _peerSendingDhPublicKeyBytes);
            Console.WriteLine($"[{sendingStep.StepType}] Computed DH Secret: {Convert.ToHexString(dhSecret)}");

            currentRootKey = new byte[Constants.X25519KeySize];
            _rootKeyHandle.Read(currentRootKey.AsSpan());

            newRootKey = new byte[Constants.X25519KeySize];
            newChainKey = new byte[Constants.X25519KeySize];
            hkdfOutput = new byte[Constants.X25519KeySize * 2];

            using (HkdfSha256 hkdf = new HkdfSha256(dhSecret, currentRootKey))
            {
                hkdf.Expand(Constants.DhRatchetInfo, hkdfOutput);
            }

            Buffer.BlockCopy(hkdfOutput, 0, newRootKey, 0, newRootKey.Length);
            Buffer.BlockCopy(hkdfOutput, newRootKey.Length, newChainKey, 0, newChainKey.Length);

            Console.WriteLine($"[{sendingStep.StepType}] Derived New Root Key: {Convert.ToHexString(newRootKey)}");
            Console.WriteLine($"[{sendingStep.StepType}] Derived New Sending CK: {Convert.ToHexString(newChainKey)}");

            _rootKeyHandle.Write(newRootKey);
            sendingStep.UpdateKeysAfterDhRatchet(newChainKey, newDhPrivateKeyBytes, newDhPublicKeyBytes);
            ClearMessageKeyCache();

            Console.WriteLine($"[{sendingStep.StepType}] DH Rotation complete. Index will reset after this message.");
        }
        finally
        {
            WipeIfNotNull(dhSecret);
            WipeIfNotNull(currentRootKey);
            WipeIfNotNull(newRootKey);
            WipeIfNotNull(newChainKey);
            WipeIfNotNull(hkdfOutput);
            WipeIfNotNull(newDhPrivateKeyBytes);
            WipeIfNotNull(newDhPublicKeyBytes);
        }
    }

    internal byte[] GenerateNextNonce(ChainStepType chainStepType)
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
            SodiumInterop.SecureWipe(_peerSendingDhPublicKeyBytes);
            GC.SuppressFinalize(this);
        }
    }

    // Added for external access if needed
    public byte[]? GetCurrentSenderDhPublicKey()
    {
        return _sendingStep?.ReadDhPublicKey();
    }
}
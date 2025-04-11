using Ecliptix.Core.Protocol.Utilities;
using Ecliptix.Protobuf.PubKeyExchange;
using Sodium;
using System.Buffers.Binary;

namespace Ecliptix.Core.Protocol;

public sealed class ShieldSession : IDisposable
{
    // ... (Constants, Fields, Constructor, Properties, Setters, FinalizeChainAndDhKeys) ...
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

        // Ratchet is triggered if we received a new key OR if the interval is hit.
        bool shouldRatchet = _receivedNewDhKey || ((sendingStep.CurrentIndex + 1) % DhRotationInterval == 0);
        if (shouldRatchet)
        {
            Console.WriteLine(
                $"[{sendingStep.StepType}] Triggering DH Ratchet before message preparation. ReceivedNewKey={_receivedNewDhKey}, Interval={((sendingStep.CurrentIndex + 1) % DhRotationInterval == 0)}");
            PerformDhRatchet();
            _receivedNewDhKey = false; // Reset the flag *after* performing our ratchet
            includeDhKey = true; // Include our new key
        }

        // Get next index AFTER potential ratchet (index might have been reset)
        uint nextIndex = sendingStep.CurrentIndex + 1;
        ShieldMessageKey messageKey = sendingStep.GetOrDeriveKeyFor(nextIndex, _messageKeys);

        // ***** Explicitly update the step's index *****
        sendingStep.CurrentIndex = nextIndex;

        byte[]? keyMaterial = null;
        ShieldMessageKey? clonedMessageKey = null;
        try
        {
            keyMaterial = new byte[Constants.AesKeySize];
            messageKey.ReadKeyMaterial(keyMaterial);
            clonedMessageKey = new ShieldMessageKey(messageKey.Index, keyMaterial);
            Console.WriteLine($"[{sendingStep.StepType}] Prepared message key for index {clonedMessageKey.Index}");

            // *** Call PruneOldKeys for the sending chain ***
            sendingStep.PruneOldKeys(_messageKeys);
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
        byte[]? initialRootKeyCopy = null;
        byte[]? senderDhPrivateKeyBytes = null;
        byte[]? senderDhPublicKeyBytes = null;
        byte[]? localSenderCk = null;
        byte[]? localReceiverCk = null;

        try
        {
            // Work with copies to ensure originals are not held longer than needed
            initialRootKeyCopy = (byte[])initialRootKey.Clone();

            tempRootHandle = SodiumSecureMemoryHandle.Allocate(Constants.X25519KeySize);
            tempRootHandle.Write(initialRootKeyCopy);

            Span<byte> initiatorSenderChainKey = stackalloc byte[Constants.X25519KeySize];
            Span<byte> responderSenderChainKey = stackalloc byte[Constants.X25519KeySize];

            // Use the copied root key for HKDF
            using (HkdfSha256 hkdfSend = new(initialRootKeyCopy, null))
            {
                hkdfSend.Expand(Constants.InitialSenderChainInfo, initiatorSenderChainKey);
            }

            using (HkdfSha256 hkdfRecv = new(initialRootKeyCopy, null))
            {
                hkdfRecv.Expand(Constants.InitialReceiverChainInfo, responderSenderChainKey);
            }

            SodiumInterop.SecureWipe(initialRootKeyCopy); // Wipe the copy
            initialRootKeyCopy = null;

            senderDhPrivateKeyBytes = SodiumCore.GetRandomBytes(Constants.X25519PrivateKeySize);
            senderDhPublicKeyBytes = ScalarMult.Base(senderDhPrivateKeyBytes);

            // Assign chain keys based on role
            localSenderCk = _isInitiator ? initiatorSenderChainKey.ToArray() : responderSenderChainKey.ToArray();
            localReceiverCk = _isInitiator ? responderSenderChainKey.ToArray() : initiatorSenderChainKey.ToArray();

            // Pass copies to ShieldChainStep constructors
            tempSendingStep = new ShieldChainStep(ChainStepType.Sender, localSenderCk, senderDhPrivateKeyBytes,
                senderDhPublicKeyBytes);
            tempReceivingStep = new ShieldChainStep(ChainStepType.Receiver, localReceiverCk,
                new byte[Constants.X25519PrivateKeySize],
                initialPeerDhPublicKey); // Receiver doesn't need initial private key

            _rootKeyHandle = tempRootHandle;
            tempRootHandle = null; // Transfer ownership
            _sendingStep = tempSendingStep;
            tempSendingStep = null; // Transfer ownership
            _receivingStep = tempReceivingStep;
            tempReceivingStep = null; // Transfer ownership
            _peerSendingDhPublicKeyBytes = (byte[])initialPeerDhPublicKey.Clone(); // Store peer's initial key

            Console.WriteLine($"[Session {_id}] Sender Chain Key: {Convert.ToHexString(localSenderCk)}");
            Console.WriteLine($"[Session {_id}] Receiver Chain Key: {Convert.ToHexString(localReceiverCk)}");
            Console.WriteLine($"[Session {_id}] Chains and initial DH keys finalized successfully.");
        }
        catch (Exception ex)
        {
            // Dispose any handles created in this scope if exception occurred
            tempRootHandle?.Dispose();
            tempSendingStep?.Dispose();
            tempReceivingStep?.Dispose();
            // Re-throw wrapped exception
            throw new ShieldChainStepException($"Failed to finalize session {_id}: {ex.Message}", ex);
        }
        finally
        {
            // Ensure sensitive intermediate copies are wiped
            WipeIfNotNull(initialRootKeyCopy);
            WipeIfNotNull(senderDhPrivateKeyBytes);
            WipeIfNotNull(senderDhPublicKeyBytes);
            WipeIfNotNull(localSenderCk);
            WipeIfNotNull(localReceiverCk);
        }
    }

    internal ShieldMessageKey ProcessReceivedMessage(uint receivedIndex, byte[]? receivedDhPublicKeyBytes)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        EnsureNotExpired();
        var receivingStep =
            _receivingStep ?? throw new InvalidOperationException("Receiving chain step not initialized.");
        var sendingStep = // Need sending step for its private key during ratchet
            _sendingStep ?? throw new InvalidOperationException("Sending chain step not initialized.");
        if (_rootKeyHandle == null) throw new InvalidOperationException("Root key handle not initialized.");

        Console.WriteLine(
            $"[{receivingStep.StepType}] Processing received message #{receivedIndex}. Current Index: {receivingStep.CurrentIndex}");
        Console.WriteLine(
            $"[{receivingStep.StepType}] Current Receiving Chain Key (Before processing): {Convert.ToHexString(receivingStep.ReadChainKey())}");

        bool ratchetPerformed = false;

        // Step 1: Perform the receiving DH ratchet if a new key is present
        if (receivedDhPublicKeyBytes != null &&
            receivedDhPublicKeyBytes.Length == Constants.X25519KeySize &&
            !receivedDhPublicKeyBytes.SequenceEqual(_peerSendingDhPublicKeyBytes ??
                                                    Array.Empty<byte>()))
        {
            Console.WriteLine(
                $"[{receivingStep.StepType}] Received new Peer DH PK: {Convert.ToHexString(receivedDhPublicKeyBytes)}. Performing receiving ratchet first.");
            ratchetPerformed = true;

            byte[]? dhSecret = null;
            byte[]? currentRootKey = null;
            byte[]? newRootKey = null;
            byte[]? newChainKey = null;
            byte[]? hkdfOutput = null;
            byte[]? currentSendingDhPrivateKey = null; // Temporary copy

            try
            {
                // Use the OUR SENDER's private key for the receiving ratchet calculation
                currentSendingDhPrivateKey = sendingStep.ReadDhPrivateKey(); // Read securely
                dhSecret = ScalarMult.Mult(currentSendingDhPrivateKey, receivedDhPublicKeyBytes);
                Console.WriteLine($"[{receivingStep.StepType}] Computed DH Secret: {Convert.ToHexString(dhSecret)}");

                currentRootKey = new byte[Constants.X25519KeySize];
                _rootKeyHandle.Read(currentRootKey.AsSpan());
                Console.WriteLine(
                    $"[{receivingStep.StepType}] Current Root Key (Before Ratchet): {Convert.ToHexString(currentRootKey)}");

                newRootKey = new byte[Constants.X25519KeySize];
                newChainKey = new byte[Constants.X25519KeySize];
                hkdfOutput = new byte[Constants.X25519KeySize * 2];

                // Derive new RK and new Receiving CK from DH secret and current RK
                using (HkdfSha256 hkdf = new(dhSecret, currentRootKey))
                {
                    hkdf.Expand(Constants.DhRatchetInfo, hkdfOutput);
                }

                Buffer.BlockCopy(hkdfOutput, 0, newRootKey, 0, newRootKey.Length);
                Buffer.BlockCopy(hkdfOutput, newRootKey.Length, newChainKey, 0, newChainKey.Length);

                Console.WriteLine(
                    $"[{receivingStep.StepType}] Derived New Root Key: {Convert.ToHexString(newRootKey)}");
                Console.WriteLine(
                    $"[{receivingStep.StepType}] Derived New Receiving CK: {Convert.ToHexString(newChainKey)}");

                // Update state AFTER calculations are complete
                _rootKeyHandle.Write(newRootKey); // Update RK
                receivingStep.UpdateKeysAfterDhRatchet(newChainKey); // Updates CK and resets index to 0
                _peerSendingDhPublicKeyBytes = (byte[])receivedDhPublicKeyBytes.Clone(); // Store peer's new pub key
                _receivedNewDhKey = true; // Flag that *our* sender needs to ratchet next time
                ClearMessageKeyCache(); // Clear old message keys

                Console.WriteLine(
                    $"[{receivingStep.StepType}] Receiving ratchet state update complete. Index reset to {receivingStep.CurrentIndex}. Cache cleared.");
                Console.WriteLine(
                    $"[{receivingStep.StepType}] New Receiving Chain Key (Post-Ratchet): {Convert.ToHexString(receivingStep.ReadChainKey())}");
            }
            finally
            {
                // Wipe all temporary sensitive materials
                WipeIfNotNull(dhSecret);
                WipeIfNotNull(currentRootKey);
                WipeIfNotNull(newRootKey);
                WipeIfNotNull(newChainKey);
                WipeIfNotNull(hkdfOutput);
                WipeIfNotNull(currentSendingDhPrivateKey); // Wipe the copy
            }
        }

        // Step 2: Derive the message key using the potentially updated state
        ShieldMessageKey messageKeyForDecryption;
        byte[]? keyMaterialBytes = null; // Use temporary storage
        uint derivedKeyIndex = 0; // To store the index of the derived key
        try
        {
            messageKeyForDecryption = receivingStep.GetOrDeriveKeyFor(receivedIndex, _messageKeys);
            derivedKeyIndex = messageKeyForDecryption.Index; // Store the actual index from the key
            Console.WriteLine(
                $"[{receivingStep.StepType}] Derived key for index {derivedKeyIndex} using {(ratchetPerformed ? "post-ratchet" : "current")} state.");

            keyMaterialBytes = new byte[Constants.AesKeySize];
            messageKeyForDecryption.ReadKeyMaterial(keyMaterialBytes.AsSpan());
            receivingStep.CurrentIndex = derivedKeyIndex;
            Console.WriteLine(
                $"[{receivingStep.StepType}] Read key material for index {derivedKeyIndex}: {Convert.ToHexString(keyMaterialBytes)}");
        }
        catch (Exception ex)
        {
            Console.WriteLine(
                $"[{receivingStep.StepType}] ERROR deriving/reading key for index {receivedIndex}: {ex.Message}");
            WipeIfNotNull(keyMaterialBytes);
            throw;
        }

        // Step 3: Create the clone for the caller
        ShieldMessageKey? clonedMessageKey = null;
        try
        {
            if (keyMaterialBytes == null)
            {
                throw new InvalidOperationException("Key material was not read successfully.");
            }

            // Use the actual derived key index for the clone
            clonedMessageKey = new ShieldMessageKey(derivedKeyIndex, keyMaterialBytes.AsSpan());
            Console.WriteLine(
                $"[{receivingStep.StepType}] Returning Cloned Message Key #{clonedMessageKey.Index}.");

            // *** Call PruneOldKeys for the receiving chain ***
            // Prune based on the index *after* successfully deriving the key
            receivingStep.PruneOldKeys(_messageKeys);
        }
        finally
        {
            WipeIfNotNull(keyMaterialBytes);
        }

        // Step 4: Manage processed message IDs (Use derivedKeyIndex for consistency)
        _processedMessageIds.Add(derivedKeyIndex);
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
            // 1. Generate new ephemeral key pair for sending
            newDhPrivateKeyBytes = SodiumCore.GetRandomBytes(Constants.X25519PrivateKeySize);
            newDhPublicKeyBytes = ScalarMult.Base(newDhPrivateKeyBytes);
            Console.WriteLine(
                $"[{sendingStep.StepType}] Generated New DH PK: {Convert.ToHexString(newDhPublicKeyBytes)}");

            // 2. Calculate DH output using new private key and peer's current public key
            Console.WriteLine(
                $"[{sendingStep.StepType}] Using Peer Sending DH PK: {Convert.ToHexString(_peerSendingDhPublicKeyBytes)}");
            dhSecret = ScalarMult.Mult(newDhPrivateKeyBytes, _peerSendingDhPublicKeyBytes);
            Console.WriteLine($"[{sendingStep.StepType}] Computed DH Secret: {Convert.ToHexString(dhSecret)}");

            // 3. Get current root key
            currentRootKey = new byte[Constants.X25519KeySize];
            _rootKeyHandle.Read(currentRootKey.AsSpan());
            Console.WriteLine(
                $"[{sendingStep.StepType}] Current Root Key (Before Ratchet): {Convert.ToHexString(currentRootKey)}");


            // 4. Derive new RK and new Sending CK from DH secret and current RK
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

            // 5. Update state AFTER calculations
            _rootKeyHandle.Write(newRootKey); // Update RK
            // Update sending step with new CK, new DH private/public keys, and reset index
            sendingStep.UpdateKeysAfterDhRatchet(newChainKey, newDhPrivateKeyBytes, newDhPublicKeyBytes);
            ClearMessageKeyCache(); // Clear message keys associated with the old chain

            Console.WriteLine(
                $"[{sendingStep.StepType}] DH Rotation complete. Index reset to {sendingStep.CurrentIndex}.");
        }
        finally
        {
            // Wipe all temporary sensitive materials
            WipeIfNotNull(dhSecret);
            WipeIfNotNull(currentRootKey);
            WipeIfNotNull(newRootKey);
            WipeIfNotNull(newChainKey);
            WipeIfNotNull(hkdfOutput);
            WipeIfNotNull(newDhPrivateKeyBytes); // Wipe the temp private key copy
            // newDhPublicKeyBytes is public, no need to wipe rigorously, but wipe for consistency
            WipeIfNotNull(newDhPublicKeyBytes);
        }
    }

    // ... (GenerateNextNonce, EnsureNotExpired, ClearMessageKeyCache, IsExpired, WipeIfNotNull, Dispose, GetCurrentSenderDhPublicKey) ...
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
            WipeIfNotNull(_peerSendingDhPublicKeyBytes); // Use WipeIfNotNull
            _peerSendingDhPublicKeyBytes = null; // Nullify after wipe
            GC.SuppressFinalize(this);
        }
    }

    // Added for external access if needed
    public byte[]? GetCurrentSenderDhPublicKey()
    {
        // Ensure thread safety and disposal check if accessed externally
        ObjectDisposedException.ThrowIf(_disposed, this);
        // Reading the public key doesn't require locking the session semaphore,
        // but reading from the step requires the step not to be disposed.
        return _sendingStep?.ReadDhPublicKey(); // Returns a clone
    }
}
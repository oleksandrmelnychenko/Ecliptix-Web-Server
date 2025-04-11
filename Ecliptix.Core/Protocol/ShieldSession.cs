using Ecliptix.Core.Protocol.Utilities;
using Ecliptix.Protobuf.PubKeyExchange;
using Sodium;
using System.Buffers.Binary;
using System;

namespace Ecliptix.Core.Protocol;

public sealed class ShieldSession : IDisposable
{
    #region Constants

    private const int MaxProcessedIds = 6000;
    private const int DhRotationInterval = 10;
    private static readonly TimeSpan SessionTimeout = TimeSpan.FromHours(24);

    #endregion

    #region Fields

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
    private byte[]? _peerDhPublicKey; // Peer’s current DH public key

    private bool _isInitiator; // True for Alice, false for Bob
    private bool _receivedNewDhKey = false;

    private byte[] _currentDhPrivateKey; // Persistent DH private key for this session
    private byte[] _currentDhPublicKey; // Persistent DH public key for this session

    private volatile bool _disposed = false;

    #endregion

    #region Constructor
    private byte[] _initialSendingDhPrivateKey; // Add to store initial sending private key
    private bool _isFirstReceivingRatchet = true;
    
    public ShieldSession(uint id, PublicKeyBundle localBundle, bool isInitiator)
    {
        _id = id;
        _localBundle = localBundle ?? throw new ArgumentNullException(nameof(localBundle));
        _peerBundle = null;
        _messageKeys = new SortedDictionary<uint, ShieldMessageKey>();
        _state = PubKeyExchangeState.Init;
        _nonceCounter = 0;
        _createdAt = DateTimeOffset.UtcNow;
        _missedReceiverIndices = new SortedSet<uint>();
        _processedMessageIds = new SortedSet<uint>();
        _peerDhPublicKey = null;
        _isInitiator = isInitiator;
        _receivedNewDhKey = false;
        _isFirstReceivingRatchet = true;
        // Initialize persistent DH key pair
        _currentDhPrivateKey = SodiumCore.GetRandomBytes(Constants.X25519PrivateKeySize);
        _currentDhPublicKey = ScalarMult.Base(_currentDhPrivateKey);

        _initialSendingDhPrivateKey = SodiumCore.GetRandomBytes(Constants.X25519PrivateKeySize);
        byte[] initialSendingDhPublicKey = ScalarMult.Base(_initialSendingDhPrivateKey);
        _sendingStep = new ShieldChainStep(ChainStepType.Sender, new byte[Constants.X25519KeySize],
            _initialSendingDhPrivateKey, initialSendingDhPublicKey);
        
        _receivingStep = null;
        _rootKeyHandle = null;

        Console.WriteLine($"[Session {_id}] Initial Sender DH PK: {Convert.ToHexString(initialSendingDhPublicKey)}");
    }

    #endregion

    #region Properties

    public uint SessionId => _id;
    public PubKeyExchangeState State => _state;
    public PublicKeyBundle LocalBundle => _localBundle;
    public PublicKeyBundle PeerBundle => _peerBundle ?? throw new InvalidOperationException("Peer bundle not set.");
    public bool IsInitiator => _isInitiator;

    #endregion

    #region Internal Setters

    internal void SetConnectionState(PubKeyExchangeState newState) => _state = newState;

    internal void SetPeerBundle(PublicKeyBundle peerBundle) =>
        _peerBundle = peerBundle ?? throw new ArgumentNullException(nameof(peerBundle));

    #endregion

    #region Message Preparation

    internal (ShieldMessageKey MessageKey, bool IncludeDhKey) PrepareNextSendMessage()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        EnsureNotExpired();
        var sendingStep = _sendingStep ?? throw new InvalidOperationException("Sending chain step not initialized.");

        // Trigger DH ratchet only on specific conditions (e.g., interval or new peer key)
        bool shouldRatchet = _receivedNewDhKey || ((sendingStep.CurrentIndex + 1) % DhRotationInterval == 0);
        bool includeDhKey = false; // Default to not including DH key

        if (shouldRatchet)
        {
            Console.WriteLine(
                $"[{sendingStep.StepType}] Triggering DH Ratchet before message preparation. ReceivedNewKey={_receivedNewDhKey}, Interval={((sendingStep.CurrentIndex + 1) % DhRotationInterval == 0)}");
            PerformDhRatchet();
            _receivedNewDhKey = false;
            includeDhKey = true; // Include DH key only when ratcheting
        }else if (_receivedNewDhKey)
        {
            Console.WriteLine($"[{sendingStep.StepType}] Skipping DH Ratchet: ReceivedNewKey=True but not at interval.");
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
            Console.WriteLine($"[{sendingStep.StepType}] Prepared message key for index {clonedMessageKey.Index}");
            sendingStep.PruneOldKeys(_messageKeys);
        }
        finally
        {
            WipeIfNotNull(keyMaterial);
        }

        return (clonedMessageKey, includeDhKey);
    }

    #endregion

    #region Session Initialization

    internal void FinalizeChainAndDhKeys(byte[] initialRootKey, byte[] initialPeerDhPublicKey)
    {
        if (_rootKeyHandle != null || _receivingStep != null)
            throw new InvalidOperationException("Session already finalized.");

        SodiumSecureMemoryHandle? tempRootHandle = null;
        ShieldChainStep? tempReceivingStep = null;
        byte[]? initialRootKeyCopy = null;
        byte[]? localSenderCk = null;
        byte[]? localReceiverCk = null;

        try
        {
            initialRootKeyCopy = (byte[])initialRootKey.Clone();
            tempRootHandle = SodiumSecureMemoryHandle.Allocate(Constants.X25519KeySize);
            tempRootHandle.Write(initialRootKeyCopy);

            _peerDhPublicKey = (byte[])initialPeerDhPublicKey.Clone();

            Span<byte> initiatorSenderChainKey = stackalloc byte[Constants.X25519KeySize];
            Span<byte> responderSenderChainKey = stackalloc byte[Constants.X25519KeySize];

            using (HkdfSha256 hkdfSend = new(initialRootKeyCopy, null))
                hkdfSend.Expand(Constants.InitialSenderChainInfo, initiatorSenderChainKey);
            using (HkdfSha256 hkdfRecv = new(initialRootKeyCopy, null))
                hkdfRecv.Expand(Constants.InitialReceiverChainInfo, responderSenderChainKey);

            localSenderCk = _isInitiator ? initiatorSenderChainKey.ToArray() : responderSenderChainKey.ToArray();
            localReceiverCk = _isInitiator ? responderSenderChainKey.ToArray() : initiatorSenderChainKey.ToArray();

            // Update sending chain with real chain key
            _sendingStep.UpdateKeysAfterDhRatchet(localSenderCk);
            tempReceivingStep = new ShieldChainStep(ChainStepType.Receiver, localReceiverCk, _currentDhPrivateKey, _currentDhPublicKey);

            _rootKeyHandle = tempRootHandle;
            tempRootHandle = null;
            _receivingStep = tempReceivingStep;
            tempReceivingStep = null;

            Console.WriteLine($"[Session {_id}] Initial Peer DH PK: {Convert.ToHexString(_peerDhPublicKey)}");
        }
        finally
        {
            WipeIfNotNull(initialRootKeyCopy);
            WipeIfNotNull(localSenderCk);
            WipeIfNotNull(localReceiverCk);
            tempRootHandle?.Dispose();
            tempReceivingStep?.Dispose();
        }
    }

    #endregion

    #region Message Processing

    internal ShieldMessageKey ProcessReceivedMessage(uint receivedIndex, byte[]? receivedDhPublicKeyBytes)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        EnsureNotExpired();
        var receivingStep = _receivingStep ?? throw new InvalidOperationException("Receiving chain step not initialized.");

        Console.WriteLine(
            $"[{receivingStep.StepType}] Processing received message #{receivedIndex}. Current Index: {receivingStep.CurrentIndex}");

        // Handle initial peer DH key
        if (_peerDhPublicKey == null && receivedDhPublicKeyBytes != null)
        {
            _peerDhPublicKey = (byte[])receivedDhPublicKeyBytes.Clone();
            Console.WriteLine($"[{receivingStep.StepType}] Initialized _peerDhPublicKey with first message key.");
        }
        // Perform receiving ratchet only if at interval or first message
        else if (receivedDhPublicKeyBytes != null && !receivedDhPublicKeyBytes.SequenceEqual(_peerDhPublicKey))
        {
            PerformReceivingRatchet(receivedDhPublicKeyBytes);
        }

        ShieldMessageKey messageKey = receivingStep.GetOrDeriveKeyFor(receivedIndex, _messageKeys);
        receivingStep.CurrentIndex = messageKey.Index;

        Console.WriteLine($"[{receivingStep.StepType}] Derived key for index {messageKey.Index}.");
        receivingStep.PruneOldKeys(_messageKeys);

        _processedMessageIds.Add(messageKey.Index);
        if (_processedMessageIds.Count > MaxProcessedIds)
            _processedMessageIds.Remove(_processedMessageIds.Min);

        return messageKey;
    }

    #endregion

    #region DH Ratchet Logic

    internal void PerformDhRatchet()
    {
        var sendingStep = _sendingStep ?? throw new InvalidOperationException("Sending chain step not initialized.");
        if (_rootKeyHandle == null) throw new InvalidOperationException("Root key handle not initialized.");

        byte[]? newDhPrivateKey = null;
        byte[]? newDhPublicKey = null;
        byte[]? dhSecret = null;
        byte[]? currentRootKey = null;
        byte[]? newRootKey = null;
        byte[]? newChainKey = null;
        byte[]? hkdfOutput = null;

        try
        {
            newDhPrivateKey = SodiumCore.GetRandomBytes(Constants.X25519PrivateKeySize);
            newDhPublicKey = ScalarMult.Base(newDhPrivateKey);
            dhSecret = ScalarMult.Mult(newDhPrivateKey, _peerDhPublicKey);

            Console.WriteLine($"[Sender] Using Peer DH PK: {Convert.ToHexString(_peerDhPublicKey)}");
            Console.WriteLine($"[Sender] New DH PK: {Convert.ToHexString(newDhPublicKey)}");
            Console.WriteLine($"[Sender] DH Secret: {Convert.ToHexString(dhSecret)}");

            currentRootKey = new byte[Constants.X25519KeySize];
            _rootKeyHandle.Read(currentRootKey.AsSpan());

            hkdfOutput = new byte[Constants.X25519KeySize * 2];
            using (HkdfSha256 hkdf = new HkdfSha256(dhSecret, currentRootKey))
                hkdf.Expand(Constants.DhRatchetInfo, hkdfOutput);

            newRootKey = hkdfOutput.Take(Constants.X25519KeySize).ToArray();
            newChainKey = hkdfOutput.Skip(Constants.X25519KeySize).Take(Constants.X25519KeySize).ToArray();

            _rootKeyHandle.Write(newRootKey);
            sendingStep.UpdateKeysAfterDhRatchet(newChainKey, newDhPrivateKey, newDhPublicKey);
            sendingStep.CurrentIndex = 0;

            // Update persistent DH keys
            WipeIfNotNull(_currentDhPrivateKey);
            WipeIfNotNull(_currentDhPublicKey);
            _currentDhPrivateKey = (byte[])newDhPrivateKey.Clone();
            _currentDhPublicKey = (byte[])newDhPublicKey.Clone();
            _isFirstReceivingRatchet = false;
            ClearMessageKeyCache();

            Console.WriteLine($"[Sender] DH Ratchet: New Chain Key = {Convert.ToHexString(newChainKey)}");
            Console.WriteLine($"[Sender] Updated DH Keys: PK = {Convert.ToHexString(newDhPublicKey)}");
        }
        finally
        {
            WipeIfNotNull(newDhPrivateKey);
            WipeIfNotNull(newDhPublicKey);
            WipeIfNotNull(dhSecret);
            WipeIfNotNull(currentRootKey);
            WipeIfNotNull(newRootKey);
            WipeIfNotNull(newChainKey);
            WipeIfNotNull(hkdfOutput);
        }
    }

    internal void PerformReceivingRatchet(byte[] receivedDhPublicKeyBytes)
{
    var receivingStep = _receivingStep ?? throw new InvalidOperationException("Receiving chain step not initialized.");
    if (_rootKeyHandle == null) throw new InvalidOperationException("Root key handle not initialized.");

    // Only perform ratchet if at interval or first message
    if (_isFirstReceivingRatchet || (receivingStep.CurrentIndex + 1) % DhRotationInterval == 0)
    {
        byte[]? dhSecret = null;
        byte[]? currentRootKey = null;
        byte[]? newRootKey = null;
        byte[]? newChainKey = null;
        byte[]? hkdfOutput = null;

        try
        {
            byte[] privateKeyToUse = _isFirstReceivingRatchet ? _initialSendingDhPrivateKey : _currentDhPrivateKey;
            dhSecret = ScalarMult.Mult(privateKeyToUse, receivedDhPublicKeyBytes);

            Console.WriteLine($"[Receiver] Using Private Key for: {(_isFirstReceivingRatchet ? "Initial" : "Persistent")}");
            Console.WriteLine($"[Receiver] Received DH PK: {Convert.ToHexString(receivedDhPublicKeyBytes)}");
            Console.WriteLine($"[Receiver] DH Secret: {Convert.ToHexString(dhSecret)}");

            currentRootKey = new byte[Constants.X25519KeySize];
            _rootKeyHandle.Read(currentRootKey.AsSpan());

            hkdfOutput = new byte[Constants.X25519KeySize * 2];
            using (HkdfSha256 hkdf = new HkdfSha256(dhSecret, currentRootKey))
                hkdf.Expand(Constants.DhRatchetInfo, hkdfOutput);

            newRootKey = hkdfOutput.Take(Constants.X25519KeySize).ToArray();
            newChainKey = hkdfOutput.Skip(Constants.X25519KeySize).Take(Constants.X25519KeySize).ToArray();

            _rootKeyHandle.Write(newRootKey);
            receivingStep.UpdateKeysAfterDhRatchet(newChainKey);
            receivingStep.CurrentIndex = 0;
            _peerDhPublicKey = (byte[])receivedDhPublicKeyBytes.Clone();
            _receivedNewDhKey = false; // Reset only when we actually ratchet
            _isFirstReceivingRatchet = false;
            ClearMessageKeyCache();

            Console.WriteLine($"[Receiver] DH Ratchet: New Chain Key = {Convert.ToHexString(newChainKey)}");
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
    else
    {
        // Store the new key but don’t ratchet yet
        _peerDhPublicKey = (byte[])receivedDhPublicKeyBytes.Clone();
        _receivedNewDhKey = true;
        Console.WriteLine($"[Receiver] Deferred DH Ratchet: New key received but waiting for interval.");
    }
}

    #endregion

    #region Utility Methods

    internal byte[] GenerateNextNonce(ChainStepType chainStepType)
    {
        byte[] nonce = new byte[Constants.AesGcmNonceSize];
        BinaryPrimitives.WriteUInt64LittleEndian(nonce, Interlocked.Increment(ref _nonceCounter));
        return nonce;
    }

    public byte[]? GetCurrentPeerDhPublicKey()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return _peerDhPublicKey != null ? (byte[])_peerDhPublicKey.Clone() : null;
    }

    public byte[]? GetCurrentSenderDhPublicKey()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return _sendingStep?.ReadDhPublicKey(); // Returns ephemeral public key
    }

    internal void EnsureNotExpired()
    {
        if (DateTimeOffset.UtcNow - _createdAt > SessionTimeout)
            throw new ShieldChainStepException($"Session {_id} has expired.");
    }

    internal bool IsExpired()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return DateTimeOffset.UtcNow - _createdAt > SessionTimeout;
    }

    private void ClearMessageKeyCache()
    {
        Console.WriteLine($"[Session {_id}] Clearing message key cache ({_messageKeys.Count} items).");
        foreach (var kvp in _messageKeys)
            kvp.Value.Dispose();
        _messageKeys.Clear();
    }

    private static void WipeIfNotNull(byte[]? data)
    {
        if (data != null)
            SodiumInterop.SecureWipe(data);
    }

    #endregion

    #region Disposal

    public void Dispose()
    {
        if (!_disposed)
        {
            _disposed = true;
            _rootKeyHandle?.Dispose();
            _sendingStep?.Dispose();
            _receivingStep?.Dispose();
            ClearMessageKeyCache();
            WipeIfNotNull(_peerDhPublicKey);
            _peerDhPublicKey = null;
            WipeIfNotNull(_currentDhPrivateKey);
            _currentDhPrivateKey = null;
            WipeIfNotNull(_currentDhPublicKey);
            _currentDhPublicKey = null;
            WipeIfNotNull(_initialSendingDhPrivateKey); // Wipe new field
            _initialSendingDhPrivateKey = null;
            GC.SuppressFinalize(this);
        }
    }

    #endregion
}
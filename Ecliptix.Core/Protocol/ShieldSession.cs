using Ecliptix.Core.Protocol.Utilities; // For Constants, ShieldChainStepException
using Ecliptix.Protobuf.PubKeyExchange; // Added for potential async if needed later

namespace Ecliptix.Core.Protocol;

/// <summary>
/// Manages the state for a single cryptographic session (Double Ratchet).
/// Assumes external locking is performed before calling methods that modify state.
/// Implements IDisposable to manage underlying secure handles and steps.
/// </summary>
public sealed class ShieldSession : IDisposable
{
    // --- Constants ---
    private const int MaxProcessedIds = 6000;
    private static readonly TimeSpan SessionTimeout = TimeSpan.FromHours(24); 

    // --- Fields ---
    private readonly uint _id;
    private readonly PublicKeyBundle _localBundle; // Assuming PublicKeyBundle is defined
    private PublicKeyBundle? _peerBundle;
    private ShieldChainStep? _senderStep;
    private ShieldChainStep? _receiverStep;
    private PubKeyExchangeState _state;
    private ulong _nonceCounter;

    private readonly DateTimeOffset _createdAt;

    // private SessionDirectionTracker _directionTracker; // Omitted for now
    private readonly SortedSet<uint> _missedIndices; // Use SortedSet to easily find/remove minimum
    private readonly SortedSet<uint> _processedMessageIds; // Use SortedSet to easily find/remove minimum
    private byte[]? _lastReceivedDhKeyBytes; // Store as byte[], wipe on dispose

    private bool _disposed = false;

    // --- Properties ---
    public uint SessionId => _id;
    public PubKeyExchangeState State => _state; // Read-only access is safe without lock check
    public PublicKeyBundle LocalBundle => _localBundle; // Assuming immutable

    // --- Constructor ---
    public ShieldSession(
        uint id,
        PublicKeyBundle localBundle) 
    {
        _id = id;
        _localBundle = localBundle; // Assuming PublicKeyBundle is immutable or cloned if needed
        _peerBundle = null;
        _senderStep = null;
        _receiverStep = null;
        _state = PubKeyExchangeState.Init;
        _nonceCounter = 0;
        _createdAt = DateTimeOffset.UtcNow;
        // _directionTracker = new SessionDirectionTracker(); // Omitted
        _missedIndices = new SortedSet<uint>();
        _processedMessageIds = new SortedSet<uint>();
        _lastReceivedDhKeyBytes = null;

        // No logging
    }


    // --- Methods Requiring External Lock ---

    /// <summary>
    /// Gets the peer's public key bundle. Throws if not set.
    /// Requires external lock.
    /// </summary>
    public PublicKeyBundle PeerBundle
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return _peerBundle ?? throw new InvalidOperationException("Peer bundle has not been set for this session.");
        }
    }

    /// <summary>
    /// Gets the last DH public key received from the peer, if any.
    /// Requires external lock.
    /// </summary>
    public byte[]? GetLastReceivedDhKey()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return _lastReceivedDhKeyBytes?.Clone() as byte[]; // Return a clone
    }

    /// <summary>
    /// Sets the last received DH public key from the peer. Wipes the previous key.
    /// Requires external lock.
    /// </summary>
    /// <param name="dhKey">The 32-byte X25519 public key.</param>
    public void SetLastReceivedDhKey(ReadOnlySpan<byte> dhKey)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (dhKey.Length != Constants.X25519KeySize)
            throw new ArgumentException($"DH key must be {Constants.X25519KeySize} bytes.", nameof(dhKey));

        // Wipe previous key if it exists
        if (_lastReceivedDhKeyBytes != null)
        {
            SodiumInterop.SecureWipe(_lastReceivedDhKeyBytes);
        }

        _lastReceivedDhKeyBytes = dhKey.ToArray(); // Store a copy
    }


    /// <summary>
    /// Checks for message replay and manages the processed ID set.
    /// Requires external lock.
    /// </summary>
    /// <param name="requestId">The unique ID of the incoming message.</param>
    /// <exception cref="ShieldChainStepException">Thrown if replay detected.</exception>
    public void CheckReplay(uint requestId)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (_processedMessageIds.Contains(requestId))
        {
            // No logging, just throw
            throw new ShieldChainStepException(
                $"Replay attack detected: message with request_id {requestId} already processed");
        }

        // Prune oldest if set exceeds max size
        if (_processedMessageIds.Count >= MaxProcessedIds)
        {
            // SortedSet allows efficiently getting and removing the minimum element
            uint oldestId = _processedMessageIds.Min;
            _processedMessageIds.Remove(oldestId);
            // Debug log removed
        }

        _processedMessageIds.Add(requestId);
    }

    /// <summary>
    /// Sets the current state of the session.
    /// Requires external lock.
    /// </summary>
    public void SetConnectionState(PubKeyExchangeState newState)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        _state = newState;
        // Debug log removed
    }

    /// <summary>
    /// Sets the peer's public key bundle.
    /// Requires external lock.
    /// </summary>
    /// <param name="peerBundle">The peer's bundle.</param>
    public void SetPeerBundle(PublicKeyBundle peerBundle)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        _peerBundle = peerBundle ?? throw new ArgumentNullException(nameof(peerBundle));
        // Debug log removed
    }

    /// <summary>
    /// Initializes the sender and receiver chain steps after X3DH completes.
    /// Requires external lock.
    /// </summary>
    /// <param name="chainSenderKey">Initial key for the sender chain.</param>
    /// <param name="chainReceiverKey">Initial key for the receiver chain.</param>
    public void FinalizeChainKey(byte[] chainSenderKey, byte[] chainReceiverKey)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (_senderStep != null || _receiverStep != null)
        {
            throw new InvalidOperationException("Chain steps have already been finalized.");
        }

        // Dispose potentially existing ones? Should not happen based on above check.
        _senderStep?.Dispose();
        _receiverStep?.Dispose();

        // Create steps using the provided initial keys
        _senderStep = new ShieldChainStep(ChainStepType.Sender, chainSenderKey);
        _receiverStep = new ShieldChainStep(ChainStepType.Receiver, chainReceiverKey);
        // Debug log removed
    }

    /// <summary>
    /// Performs a DH rotation on the sender chain step.
    /// Requires external lock.
    /// </summary>
    /// <param name="peerPublicKeyBytes">The peer's current DH public key.</param>
    /// <returns>The sender's new DH public key bytes if rotation occurred, otherwise null.</returns>
    /// <exception cref="InvalidOperationException">Thrown if sender step is not initialized.</exception>
    /// <exception cref="ShieldChainStepException">Thrown if DH rotation fails.</exception>
    public byte[]? RotateSenderDh(byte[] peerPublicKeyBytes)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        EnsureNotExpired(); // Check expiry first
        var sender = _senderStep ?? throw new InvalidOperationException("Sender chain step not initialized.");

        // Check if keys have been derived. If not, it's effectively the first message send attempt.
        if (!sender.HasDerivedKeys) // Assuming HasDerivedKeys property exists on ShieldChainStep
        {
            // Debug log removed ("Skipping DH ratchet for first message...")
            return null; // No rotation, no key returned
        }

        try
        {
            sender.RotateDhChain(peerPublicKeyBytes);
            // DO NOT clear _processedMessageIds here - Replay protection should persist.
            // Info log removed
            // Debug log removed
            return sender.PublicKeyBytes; // Return the NEW public key
        }
        catch (Exception ex)
        {
            throw new ShieldChainStepException($"Failed to rotate sender DH chain for session {_id}: {ex.Message}", ex);
        }
    }

    /// <summary>
    /// Performs a DH rotation on the receiver chain step.
    /// Requires external lock.
    /// </summary>
    /// <param name="peerPublicKeyBytes">The peer's (sender's) new DH public key.</param>
    /// <returns>The receiver's new DH public key bytes if rotation occurred.</returns>
    /// <exception cref="InvalidOperationException">Thrown if receiver step is not initialized.</exception>
    /// <exception cref="ShieldChainStepException">Thrown if DH rotation fails.</exception>
    public byte[] RotateReceiverDh(byte[] peerPublicKeyBytes) // Renamed parameter for clarity
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        EnsureNotExpired();
        var receiver = _receiverStep ?? throw new InvalidOperationException("Receiver chain step not initialized.");

        try
        {
            receiver.RotateDhChain(peerPublicKeyBytes);
            // DO NOT clear _processedMessageIds here.
            // Info log removed
            // Debug log removed
            return receiver.PublicKeyBytes; // Return the NEW public key
        }
        catch (Exception ex)
        {
            throw new ShieldChainStepException($"Failed to rotate receiver DH chain for session {_id}: {ex.Message}",
                ex);
        }
    }


    /// <summary>
    /// Gets the next message key and nonce for sending. Advances sender state.
    /// Requires external lock.
    /// </summary>
    /// <returns>A tuple containing the message key and the nonce.</returns>
    /// <exception cref="InvalidOperationException">Thrown if sender step is not initialized.</exception>
    /// <exception cref="ShieldChainStepException">Thrown if key derivation fails.</exception>
    public (ShieldMessageKey MessageKey, byte[] Nonce) RotateSenderKey()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        EnsureNotExpired();
        var sender = _senderStep ?? throw new InvalidOperationException("Sender chain step not initialized.");

        try
        {
            // AdvanceSenderKey derives key for NextMessageIndex
            var messageKey = sender.AdvanceSenderKey();
            var nonce = GenerateNextNonce(ChainStepType.Sender);
            // _directionTracker.record_sent(); // Omitted
            // Info log removed
            return (messageKey, nonce);
        }
        catch (Exception ex) when (ex is not ShieldChainStepException) // Catch underlying errors
        {
            throw new ShieldChainStepException($"Failed to rotate sender key for session {_id}: {ex.Message}", ex);
        }
    }

    /// <summary>
    /// Gets the message key for receiving. Handles potential DH rotation and missed messages.
    /// Requires external lock.
    /// </summary>
    /// <param name="msgIndex">The index of the incoming message.</param>
    /// <param name="receivedDhPublicKeyBytes">The DH public key included with the message, if any.</param>
    /// <returns>The message key for decryption.</returns>
    /// <exception cref="InvalidOperationException">Thrown if receiver step is not initialized.</exception>
    /// <exception cref="ShieldChainStepException">Thrown if key derivation or rotation fails.</exception>
    public ShieldMessageKey RotateReceiverKey(uint msgIndex, byte[]? receivedDhPublicKeyBytes)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        EnsureNotExpired();
        var receiver = _receiverStep ?? throw new InvalidOperationException("Receiver chain step not initialized.");

        try
        {
            // 1. Handle Potential DH Rotation based on received key
            bool isFirstMessage = !receiver.HasDerivedKeys; // Use helper property

            if (isFirstMessage)
            {
                // Debug log removed ("Skipping DH ratchet for first received message...")
                if (receivedDhPublicKeyBytes != null)
                {
                    SetLastReceivedDhKey(receivedDhPublicKeyBytes); // Store for potential future use if needed
                    // Info log removed
                }
            }
            else // Not the first message
            {
                if (receivedDhPublicKeyBytes != null)
                {
                    // Perform DH rotation using the received key
                    RotateReceiverDh(receivedDhPublicKeyBytes); // Use the dedicated method
                    // Note: RotateReceiverDh returns the *new* public key, which we don't need here.
                    // Logs are inside RotateReceiverDh
                }
                else
                {
                    // Warn log removed ("Missing dh_public_key...")
                    // Decide: Error or proceed symmetrically? Current Rust code proceeds. We follow.
                }
            }

            // 2. Check for missed messages (Compare against CURRENT index *before* deriving target)
            uint currentIndexBeforeDerivation = receiver.CurrentIndex;
            if (msgIndex > currentIndexBeforeDerivation + 1)
            {
                for (uint missed = currentIndexBeforeDerivation + 1; missed < msgIndex; missed++)
                {
                    _missedIndices.Add(missed);
                }

                // Warn log removed
                //RequestMissedMessages(); // Call placeholder/logic
            }

            // 3. Get/Derive the target message key
            var messageKey = receiver.GetOrDeriveKeyFor(msgIndex);

            // 4. Post-derivation actions
            // _directionTracker.record_received(); // Omitted

            // Check if it was an out-of-order (cached) key vs a newly derived one
            // Note: receiver.CurrentIndex reflects the state *after* derivation.
            if (msgIndex < receiver.CurrentIndex)
            {
                // Info log removed (MSG_MISSED_KEY)
            }
            else
            {
                // Info log removed (MSG_KEY_ROTATE)
            }
            // Debug log removed

            // If this message resolved a previously missed index, remove it
            _missedIndices.Remove(msgIndex);

            return messageKey;
        }
        catch (Exception ex) when (ex is not ShieldChainStepException)
        {
            throw new ShieldChainStepException(
                $"Failed to rotate receiver key for index {msgIndex}, session {_id}: {ex.Message}", ex);
        }
    }

    /// <summary>
    /// Gets the current set of missed message indices.
    /// Requires external lock.
    /// </summary>
    public IReadOnlySet<uint> GetMissedIndices() // Return a read-only interface
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        // Consider returning a copy if caller might modify, but SortedSet is reference type
        return _missedIndices;
    }

    public void EnsureNotExpired()
    {
        if (IsExpired())
        {
            // Error log removed
            throw new ShieldChainStepException($"Session ID {_id} is expired.");
        }
    }

    public bool IsExpired() // Made public for manager access
    {
        ObjectDisposedException.ThrowIf(_disposed, this); // Check dispose status before calculating
        bool expired = (DateTimeOffset.UtcNow - _createdAt) > SessionTimeout;
        if (expired)
        {
            // Warn log removed
        }

        return expired;
    }

    private byte[] GenerateNextNonce(ChainStepType stepType)
    {
        // No dispose check needed here as it's internal after public methods check
        _nonceCounter++;
        byte[] nonce = new byte[12];
        BitConverter.TryWriteBytes(nonce.AsSpan(0, 4), _id); // Use LE by default

        nonce[4] = stepType switch
        {
            ChainStepType.Sender => 1,
            ChainStepType.Receiver => 2,
            _ => throw new ArgumentOutOfRangeException(nameof(stepType)) // Should not happen
        };

        // Copy 7 bytes from counter (skip least significant byte of ulong for 12 byte nonce)
        // Caution: Check if this matches the exact Rust slicing `[1..]` intended behavior
        // ulong counter = _nonceCounter;
        // Span<byte> counterBytes = stackalloc byte[8];
        // BitConverter.TryWriteBytes(counterBytes, counter);
        // counterBytes.Slice(1, 7).CopyTo(nonce.AsSpan(5, 7)); // Copy bytes 1 through 7

        // Simpler: Use last 7 bytes of counter directly
        Span<byte> counterBytesFull = stackalloc byte[8];
        BitConverter.TryWriteBytes(counterBytesFull, _nonceCounter);
        counterBytesFull.Slice(0, 7).CopyTo(nonce.AsSpan(5, 7)); // Copy first 7 bytes (0 to 6)

        // Debug log removed
        return nonce;
    }

    // Add helper property to ShieldChainStep if needed:
    // public bool HasDerivedKeys => this.CurrentIndex > 0 || _messageKeys.Count > 0;


    // --- IDisposable Implementation ---

    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    internal byte[] GetReceiverStepPublicKeyBytes() // internal access is appropriate
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return _receiverStep?.PublicKeyBytes ?? throw new InvalidOperationException("Receiver chain step not initialized.");
    }

    private void Dispose(bool disposing)
    {
        if (!_disposed)
        {
            if (disposing)
            {
                _senderStep?.Dispose();
                _receiverStep?.Dispose();

                if (_lastReceivedDhKeyBytes != null)
                {
                    SodiumInterop.SecureWipe(_lastReceivedDhKeyBytes);
                    _lastReceivedDhKeyBytes = null;
                }
            }

            _senderStep = null;
            _receiverStep = null;
            _peerBundle = null; 

            _missedIndices?.Clear();
            _processedMessageIds?.Clear();

            _disposed = true;
        }
    }
}
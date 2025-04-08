using System.Collections.Concurrent;
using System.Diagnostics;
using Ecliptix.Protobuf.PubKeyExchange;

namespace Ecliptix.Core.Protocol;

// Define the key type explicitly for clarity
using SessionKey = ValueTuple<PubKeyExchangeOfType, uint>;

/// <summary>
/// Manages a collection of ShieldSessions, providing thread-safe access and lifecycle management.
/// Uses ConcurrentDictionary for map operations and SemaphoreSlim for per-session locking.
/// </summary>
public sealed class ShieldSessionManager : IAsyncDisposable // Implement IAsyncDisposable for cleanup task cancellation
{
    private static readonly TimeSpan
        CleanupInterval = TimeSpan.FromHours(1); // Or use Rust value: TimeSpan.FromSeconds(60 * 60)

    // Use ConcurrentDictionary for thread-safe map operations
    private readonly ConcurrentDictionary<SessionKey, SessionHolder> _sessions;
    private readonly CancellationTokenSource _cleanupCts; // For cancelling the background task
    private readonly Task _cleanupTask; // To track the background task

    public ShieldSessionManager()
    {
        _sessions = new ConcurrentDictionary<SessionKey, SessionHolder>();
        _cleanupCts = new CancellationTokenSource();
        // Start cleanup task immediately upon creation
        _cleanupTask = Task.Factory.StartNew(
            () => CleanupTaskLoop(_sessions, _cleanupCts.Token),
            _cleanupCts.Token,
            TaskCreationOptions.LongRunning | TaskCreationOptions.DenyChildAttach, // Use LongRunning
            TaskScheduler.Default);
        // No logging for task start
    }

    // Public factory method if preferred over calling constructor directly
    public static ShieldSessionManager CreateWithCleanupTask()
    {
        return new ShieldSessionManager();
    }


    /// <summary>
    /// Finds a session holder by key. Does not lock the session itself.
    /// </summary>
    /// <returns>The SessionHolder if found, otherwise null.</returns>
    private SessionHolder? FindSessionHolder(uint sessionId, PubKeyExchangeOfType exchangeType)
    {
        var key = (exchangeType, sessionId);
        _sessions.TryGetValue(key, out var holder);
        // Debug log removed
        return holder;
    }

    /// <summary>
    /// Finds a session holder or throws if not found. Does not lock the session.
    /// </summary>
    public SessionHolder GetSessionHolderOrThrow(uint sessionId, PubKeyExchangeOfType exchangeType)
    {
        var holder = FindSessionHolder(sessionId, exchangeType);
        if (holder == null)
        {
            // Error log removed
            throw new ShieldChainStepException(
                $"Session not found for type {exchangeType} and ID {sessionId}"); // Use specific exception
        }

        return holder;
    }

    /// <summary>
    /// Finds the session object itself. Does not lock the session.
    /// Prefer interacting via methods that acquire the lock when modification is needed.
    /// </summary>
    /// <returns>The ShieldSession if found, otherwise null.</returns>
    public ShieldSession? FindSession(uint sessionId, PubKeyExchangeOfType exchangeType)
    {
        return FindSessionHolder(sessionId, exchangeType)?.Session;
    }

    /// <summary>
    /// Checks if any session exists for the given type.
    /// </summary>
    public bool HasSessionForType(PubKeyExchangeOfType exchangeType)
    {
        // ConcurrentDictionary allows safe iteration even during updates.
        // This might not be perfectly atomic but is generally sufficient for a "has" check.
        return _sessions.Keys.Any(key => key.Item1 == exchangeType);
    }

    /// <summary>
    /// Tries to insert a new session.
    /// </summary>
    /// <returns>True if added successfully, False if a session with the same key already exists.</returns>
    /// <exception cref="ArgumentNullException">Thrown if session is null.</exception>
    public bool TryInsertSession(uint sessionId, PubKeyExchangeOfType exchangeType, ShieldSession session)
    {
        ArgumentNullException.ThrowIfNull(session);
        var key = (exchangeType, sessionId);
        var holder = new SessionHolder(session);
        bool added = _sessions.TryAdd(key, holder);
        // Info/Error logs removed
        return added;
    }

    /// <summary>
    /// Inserts a new session or throws if it already exists.
    /// </summary>
    /// <exception cref="ArgumentNullException">Thrown if session is null.</exception>
    /// <exception cref="ShieldChainStepException">Thrown if session already exists.</exception>
    public void InsertSessionOrThrow(uint sessionId, PubKeyExchangeOfType exchangeType, ShieldSession session)
    {
        if (!TryInsertSession(sessionId, exchangeType, session))
        {
            throw new ShieldChainStepException($"Session already exists for type {exchangeType} and ID {sessionId}");
        }
    }


    /// <summary>
    /// Updates the state of a specific session. Acquires the session lock.
    /// </summary>
    /// <exception cref="ShieldChainStepException">Thrown if session not found or update fails.</exception>
    public async ValueTask UpdateSessionStateAsync(uint sessionId, PubKeyExchangeOfType exchangeType,
        PubKeyExchangeState state)
    {
        var holder = GetSessionHolderOrThrow(sessionId, exchangeType);
        await holder.Lock.WaitAsync(); // Acquire lock for this specific session
        try
        {
            holder.Session.SetConnectionState(state);
            // Info log removed
        }
        finally
        {
            holder.Lock.Release(); // Release lock
        }
    }

    /// <summary>
    /// Finds the first session matching the given type.
    /// Note: "First" is not strictly guaranteed in ConcurrentDictionary iteration order.
    /// Use only if expecting at most one session per type. Does not lock the session.
    /// </summary>
    /// <returns>The ShieldSession if found, otherwise null.</returns>
    public ShieldSession? FirstSessionByType(PubKeyExchangeOfType exchangeType)
    {
        // Find the holder first, then return the session
        return _sessions.FirstOrDefault(kvp => kvp.Key.Item1 == exchangeType).Value?.Session;
    }

    /// <summary>
    /// Gets the session or throws if not found. Does not lock the session.
    /// </summary>
    public ShieldSession GetSessionOrThrow(uint sessionId, PubKeyExchangeOfType exchangeType)
    {
        return GetSessionHolderOrThrow(sessionId, exchangeType).Session;
    }


    /// <summary>
    /// Performs a DH rotation for the specified session and step type. Acquires the session lock.
    /// </summary>
    /// <returns>The new public key bytes if rotation occurred, otherwise null.</returns>
    /// <exception cref="ShieldChainStepException">Thrown if session not found or rotation fails.</exception>
    public async Task<byte[]?> RotateDhChainAsync(
        uint sessionId,
        PubKeyExchangeOfType exchangeType,
        byte[] peerPublicKeyBytes,
        ChainStepType stepToRotate) // Use ChainStepType for clarity
    {
        var holder = GetSessionHolderOrThrow(sessionId, exchangeType);
        await holder.Lock.WaitAsync(); // Acquire session lock
        try
        {
            // Call appropriate method based on step type
            return stepToRotate switch
            {
                ChainStepType.Sender => holder.Session.RotateSenderDh(peerPublicKeyBytes),
                ChainStepType.Receiver => holder.Session.RotateReceiverDh(peerPublicKeyBytes),
                _ => throw new ArgumentOutOfRangeException(nameof(stepToRotate)),
            };
        }
        // Catch specific exceptions from ShieldSession if needed for wrapping
        catch (Exception ex) when (ex is not ShieldChainStepException)
        {
            throw new ShieldChainStepException(
                $"Failed during {stepToRotate} DH rotation for session {sessionId}, type {exchangeType}: {ex.Message}",
                ex);
        }
        finally
        {
            holder.Lock.Release(); // Release lock
        }
    }


    // --- Cleanup Task ---

    private static async Task CleanupTaskLoop(
        ConcurrentDictionary<SessionKey, SessionHolder> sessions,
        CancellationToken cancellationToken)
    {
        // No initial start log

        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(CleanupInterval, cancellationToken);
            }
            catch (OperationCanceledException)
            {
                // Expected when cancellation is requested
                // Log removed ("Cleanup task cancelled.")
                break;
            }

            int removedCount = 0;
            // Create a list of keys to avoid modifying dict while iterating its Keys collection directly
            // Although ConcurrentDictionary allows iteration during modification, copying keys is safer for removal logic.
            var keys = sessions.Keys.ToList();

            foreach (var key in keys)
            {
                if (cancellationToken.IsCancellationRequested) break;

                if (sessions.TryGetValue(key, out var holder))
                {
                    bool acquiredLock = false;
                    bool requiresRemoval = false;
                    try
                    {
                        // Try to acquire lock briefly without blocking the cleanup thread
                        acquiredLock = await holder.Lock.WaitAsync(TimeSpan.Zero, cancellationToken);
                        if (acquiredLock)
                        {
                            // Check expiration ONLY if lock is held to get consistent state
                            if (holder.Session.IsExpired())
                            {
                                requiresRemoval = true;
                            }
                        }
                        // If lock not acquired, session is busy, skip check until next interval
                    }
                    catch (OperationCanceledException)
                    {
                        break;
                    } // Exit loop if cancelled during wait
                    catch (ObjectDisposedException)
                    {
                        // Session or semaphore might have been disposed concurrently?
                        // Mark for removal just in case.
                        requiresRemoval = true;
                    }
                    catch (Exception ex)
                    {
                        // Log unexpected error during check
                        Debug.WriteLine($"[WARN] Error checking session {key} expiration: {ex.Message}");
                        // Optionally mark for removal or skip
                        requiresRemoval = false; // Safer to skip if unsure
                    }
                    finally
                    {
                        if (acquiredLock) holder.Lock.Release();
                    }

                    if (requiresRemoval)
                    {
                        // Attempt to remove from the dictionary
                        if (sessions.TryRemove(key, out var removedHolder))
                        {
                            removedCount++;
                            // Asynchronously dispose the session *after* removal from dictionary
                            // Fire-and-forget dispose or queue it if dispose is long running
                            Task.Run(() => removedHolder.Session.Dispose()); // Dispose on thread pool
                            // Info log removed
                        }
                    }
                }
            }

            // Log removed count if any
            if (removedCount > 0)
            {
                Debug.WriteLine($"[INFO] Background cleanup removed {removedCount} expired sessions");
            }
            // else { Debug.WriteLine("[DEBUG] No expired sessions found during cleanup"); }
        }
        // Log removed ("Cleanup task stopping.")
    }

    /// <summary>
    /// Signals the background cleanup task to stop and waits for it to complete.
    /// </summary>
    public async ValueTask DisposeAsync()
    {
        if (!_cleanupCts.IsCancellationRequested)
        {
            _cleanupCts.Cancel();
        }

        // Wait for the task to complete, handling potential exceptions
        try
        {
            // Use await with timeout? Or just await?
            await _cleanupTask.ConfigureAwait(false); // Wait for completion
        }
        catch (OperationCanceledException)
        {
            // Expected if cancelled
            // Log removed ("Cleanup task stopped via cancellation.")
        }
        catch (Exception ex)
        {
            // Log unexpected error during task completion/shutdown
            Debug.WriteLine($"[ERROR] Exception during cleanup task shutdown: {ex.Message}");
        }
        finally
        {
            _cleanupCts.Dispose();
            // Do NOT dispose sessions here, cleanup task should have handled expired ones.
            // Active sessions might still be in use elsewhere. Let GC handle SessionHolder.
            // If manager shutdown should forcibly dispose ALL sessions, add logic here.
        }
    }
}
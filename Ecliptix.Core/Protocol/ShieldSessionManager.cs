using System.Collections.Concurrent;
using System.Diagnostics;
using Ecliptix.Protobuf.PubKeyExchange;
// Added for ArgumentNullException, etc.
// Added for Any(), FirstOrDefault()

// Added for Task/ValueTask

namespace Ecliptix.Core.Protocol;

// Define the key type explicitly for clarity
using SessionKey = ValueTuple<PubKeyExchangeOfType, uint>;

/// <summary>
/// Manages a collection of ShieldSessions, providing thread-safe access and lifecycle management.
/// Uses ConcurrentDictionary for map operations and SemaphoreSlim for per-session locking.
/// </summary>
public sealed class ShieldSessionManager : IAsyncDisposable
{
    private static readonly TimeSpan CleanupInterval = TimeSpan.FromMinutes(15); // Adjusted interval
    private readonly ConcurrentDictionary<SessionKey, SessionHolder> _sessions;
    private readonly CancellationTokenSource _cleanupCts;
    private readonly Task _cleanupTask;
    private bool _disposed = false; // Added disposal tracker

    public ShieldSessionManager()
    {
        _sessions = new ConcurrentDictionary<SessionKey, SessionHolder>();
        _cleanupCts = new CancellationTokenSource();
        _cleanupTask = Task.Factory.StartNew(
            () => CleanupTaskLoop(_sessions, _cleanupCts.Token),
            _cleanupCts.Token,
            TaskCreationOptions.LongRunning | TaskCreationOptions.DenyChildAttach,
            TaskScheduler.Default);
        Debug.WriteLine("[ShieldSessionManager] Manager created and cleanup task started."); // Added log
    }

    public static ShieldSessionManager CreateWithCleanupTask()
    {
        return new ShieldSessionManager();
    }

    private SessionHolder? FindSessionHolder(uint sessionId, PubKeyExchangeOfType exchangeType)
    {
        // *** ADD Disposal Check ***
        ObjectDisposedException.ThrowIf(_disposed, this);
        var key = (exchangeType, sessionId);
        _sessions.TryGetValue(key, out var holder);
        return holder;
    }

    public SessionHolder GetSessionHolderOrThrow(uint sessionId, PubKeyExchangeOfType exchangeType)
    {
        // *** ADD Disposal Check ***
        ObjectDisposedException.ThrowIf(_disposed, this);
        var holder = FindSessionHolder(sessionId, exchangeType);
        if (holder == null)
        {
            // Use Debug.WriteLine or proper logging
            Debug.WriteLine(
                $"[ERROR][ShieldSessionManager] Session not found for type {exchangeType} and ID {sessionId}");
            throw new ShieldChainStepException(
                $"Session not found for type {exchangeType} and ID {sessionId}");
        }

        return holder;
    }

    public ShieldSession? FindSession(uint sessionId, PubKeyExchangeOfType exchangeType)
    {
        // *** ADD Disposal Check ***
        ObjectDisposedException.ThrowIf(_disposed, this);
        return FindSessionHolder(sessionId, exchangeType)?.Session;
    }

    public bool HasSessionForType(PubKeyExchangeOfType exchangeType)
    {
        // *** ADD Disposal Check ***
        ObjectDisposedException.ThrowIf(_disposed, this);
        return _sessions.Keys.Any(key => key.Item1 == exchangeType);
    }

    public bool TryInsertSession(uint sessionId, PubKeyExchangeOfType exchangeType, ShieldSession session)
    {
        // *** ADD Disposal Check ***
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(session);
        var key = (exchangeType, sessionId);
        var holder = new SessionHolder(session);
        bool added = _sessions.TryAdd(key, holder);
        if (added)
            Debug.WriteLine(
                $"[INFO][ShieldSessionManager] Inserted session ({exchangeType}, {sessionId}). Count: {_sessions.Count}");
        else // Log if insertion failed (e.g., key already exists)
            Debug.WriteLine(
                $"[WARN][ShieldSessionManager] Failed to insert session ({exchangeType}, {sessionId}) - Key already exists?");
        return added;
    }

    public void InsertSessionOrThrow(uint sessionId, PubKeyExchangeOfType exchangeType, ShieldSession session)
    {
        // *** ADD Disposal Check ***
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (!TryInsertSession(sessionId, exchangeType, session))
        {
            throw new ShieldChainStepException($"Session already exists for type {exchangeType} and ID {sessionId}");
        }
    }

    // *** ADDED RemoveSessionAsync Method ***
    /// <summary>
    /// Removes a session and disposes it along with its lock. Safe to call even if session doesn't exist.
    /// </summary>
    public async Task RemoveSessionAsync(uint sessionId, PubKeyExchangeOfType exchangeType)
    {
        // *** ADD Disposal Check ***
        ObjectDisposedException.ThrowIf(_disposed, this);
        var key = (exchangeType, sessionId);
        if (_sessions.TryRemove(key, out SessionHolder? removedHolder))
        {
            Debug.WriteLine(
                $"[INFO][ShieldSessionManager] Removing session ({exchangeType}, {sessionId}). Count: {_sessions.Count}");
            // Safely dispose the session and its lock
            bool lockAcquired = false;
            try
            {
                // Don't wait indefinitely, maybe the session is stuck? 100ms is reasonable.
                lockAcquired = await removedHolder.Lock.WaitAsync(TimeSpan.FromMilliseconds(100));
                if (lockAcquired)
                {
                    removedHolder.Session.Dispose();
                    Debug.WriteLine($"[DEBUG][ShieldSessionManager] Disposed removed session {key} under lock.");
                }
                else
                {
                    // If lock not acquired, maybe it's already being disposed or stuck. Dispose anyway.
                    Debug.WriteLine(
                        $"[WARN][ShieldSessionManager] Could not acquire lock quickly for removed session {key}. Disposing session anyway.");
                    removedHolder.Session.Dispose(); // Dispose session directly
                }
            }
            catch (ObjectDisposedException)
            {
                Debug.WriteLine(
                    $"[DEBUG][ShieldSessionManager] Session {key} or lock was already disposed during removal.");
                // Ignore, goal is removal/disposal
            }
            catch (Exception ex)
            {
                Debug.WriteLine(
                    $"[ERROR][ShieldSessionManager] Error during disposal of removed session {key}: {ex.Message}");
                // Attempt to dispose session again if lock wasn't acquired
                if (!lockAcquired)
                {
                    try
                    {
                        removedHolder.Session.Dispose();
                    }
                    catch
                    {
                        /* Ignore secondary disposal error */
                    }
                }
            }
            finally
            {
                if (lockAcquired) removedHolder.Lock.Release();
                // Always dispose the semaphore itself after removing the holder
                try
                {
                    removedHolder.Lock.Dispose();
                }
                catch (Exception ex)
                {
                    Debug.WriteLine(
                        $"[ERROR][ShieldSessionManager] Error disposing semaphore for removed session {key}: {ex.Message}");
                }
            }
        }
        else
        {
            Debug.WriteLine(
                $"[DEBUG][ShieldSessionManager] Session ({exchangeType}, {sessionId}) not found for removal (already removed?).");
        }
    }


    public async ValueTask UpdateSessionStateAsync(uint sessionId, PubKeyExchangeOfType exchangeType,
        PubKeyExchangeState state)
    {
        // *** ADD Disposal Check ***
        ObjectDisposedException.ThrowIf(_disposed, this);
        var holder = GetSessionHolderOrThrow(sessionId, exchangeType);
        await holder.Lock.WaitAsync().ConfigureAwait(false); // Use ConfigureAwait
        try
        {
            holder.Session.SetConnectionState(state);
            // Debug.WriteLine($"[DEBUG][ShieldSessionManager] Updated session {key} state to {state}."); // Use Debug or proper log
        }
        finally
        {
            holder.Lock.Release();
        }
    }

    public ShieldSession? FirstSessionByType(PubKeyExchangeOfType exchangeType)
    {
        // *** ADD Disposal Check ***
        ObjectDisposedException.ThrowIf(_disposed, this);
        // Use FirstOrDefault on the KVP collection directly
        var kvp = _sessions.FirstOrDefault(kvp => kvp.Key.Item1 == exchangeType);
        return kvp.Value?.Session; // Return session from the Value (SessionHolder)
    }

    public ShieldSession GetSessionOrThrow(uint sessionId, PubKeyExchangeOfType exchangeType)
    {
        // *** ADD Disposal Check ***
        ObjectDisposedException.ThrowIf(_disposed, this);
        return GetSessionHolderOrThrow(sessionId, exchangeType).Session;
    }

    // --- Cleanup Task ---
    private static async Task CleanupTaskLoop(
        ConcurrentDictionary<SessionKey, SessionHolder> sessions,
        CancellationToken cancellationToken)
    {
        Debug.WriteLine("[INFO][ShieldSessionManager] Cleanup task starting."); // Log start

        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(CleanupInterval, cancellationToken);
            }
            catch (OperationCanceledException)
            {
                Debug.WriteLine(
                    "[INFO][ShieldSessionManager] Cleanup task cancelled via CancellationToken."); // Log cancellation
                break;
            }

            if (cancellationToken.IsCancellationRequested) break; // Check again after delay

            int removedCount = 0;
            var keys = sessions.Keys.ToList(); // Copy keys for safe iteration during removal attempts
            // Debug.WriteLine($"[DEBUG][ShieldSessionManager] Cleanup check running on {keys.Count} sessions...");

            foreach (var key in keys)
            {
                if (cancellationToken.IsCancellationRequested) break;

                if (sessions.TryGetValue(key, out var holder))
                {
                    bool requiresRemoval = false;
                    bool acquiredLock = false;
                    try
                    {
                        // Try lock very briefly, don't block cleanup thread
                        acquiredLock =
                            await holder.Lock.WaitAsync(TimeSpan.FromMilliseconds(50),
                                cancellationToken); // Short timeout
                        if (acquiredLock)
                        {
                            if (holder.Session.IsExpired())
                            {
                                Debug.WriteLine(
                                    $"[DEBUG][ShieldSessionManager] Session {key} marked as expired by cleanup.");
                                requiresRemoval = true;
                            }
                        }
                        // else: Session busy, skip check this cycle
                    }
                    catch (ObjectDisposedException)
                    {
                        requiresRemoval = true;
                    } // Already disposed? Remove.
                    catch (OperationCanceledException)
                    {
                        break;
                    } // Task cancelled
                    catch (Exception ex)
                    {
                        Debug.WriteLine(
                            $"[WARN][ShieldSessionManager] Error checking session {key} expiration: {ex.Message}");
                        requiresRemoval = false; // Skip removal on error
                    }
                    finally
                    {
                        if (acquiredLock) holder.Lock.Release();
                    }

                    if (requiresRemoval)
                    {
                        // Attempt removal - use the dedicated RemoveSessionAsync logic? No, do it here directly
                        // to avoid re-acquiring lock and potential races within cleanup itself.
                        if (sessions.TryRemove(key, out var removedHolder))
                        {
                            Debug.WriteLine(
                                $"[INFO][ShieldSessionManager] Cleanup removing expired session {key}. Count: {sessions.Count}");
                            removedCount++;
                            // Dispose session and lock asynchronously *after* removal
                            Task.Run(() =>
                            {
                                try
                                {
                                    // No need to acquire lock again, just dispose
                                    removedHolder.Session.Dispose();
                                    removedHolder.Lock.Dispose(); // Dispose semaphore too
                                    // Debug.WriteLine($"[DEBUG][ShieldSessionManager] Background disposal of session {key} completed.");
                                }
                                catch (Exception ex)
                                {
                                    Debug.WriteLine(
                                        $"[ERROR][ShieldSessionManager] Exception during background disposal of session {key}: {ex.Message}");
                                }
                            }); // Fire and forget disposal
                        }
                        // else: Already removed by another thread (e.g., RemoveSessionAsync call)
                    }
                }
                // else: Key in list but not dict -> removed concurrently.
            }

            if (removedCount > 0)
            {
                Debug.WriteLine(
                    $"[INFO][ShieldSessionManager] Background cleanup removed {removedCount} expired sessions.");
            }
            // else { Debug.WriteLine("[DEBUG] No expired sessions found during cleanup"); } // Less verbose
        }

        Debug.WriteLine("[INFO][ShieldSessionManager] Cleanup task stopped."); // Log stop
    }

    /// <summary>
    /// Signals the background cleanup task to stop and waits for it to complete.
    /// Also disposes remaining sessions and locks.
    /// </summary>
    public async ValueTask DisposeAsync()
    {
        if (_disposed) return;
        _disposed = true; // Mark disposed early

        Debug.WriteLine("[ShieldSessionManager] DisposeAsync called.");

        // 1. Signal cancellation
        if (!_cleanupCts.IsCancellationRequested)
        {
            Debug.WriteLine("[ShieldSessionManager] Cancelling cleanup task...");
            _cleanupCts.Cancel();
        }

        // 2. Wait for the cleanup task with timeout
        try
        {
            Debug.WriteLine("[ShieldSessionManager] Waiting for cleanup task to finish...");
            // Give cleanup a chance to finish, but don't wait forever
            await _cleanupTask.WaitAsync(TimeSpan.FromSeconds(5), CancellationToken.None).ConfigureAwait(false);
            Debug.WriteLine("[ShieldSessionManager] Cleanup task finished or timed out.");
        }
        catch (TimeoutException)
        {
            Debug.WriteLine("[WARN][ShieldSessionManager] Timeout waiting for cleanup task during disposal.");
        }
        catch (OperationCanceledException)
        {
            Debug.WriteLine("[INFO][ShieldSessionManager] Cleanup task already cancelled during disposal wait.");
        }
        catch (Exception ex)
        {
            Debug.WriteLine(
                $"[ERROR][ShieldSessionManager] Exception waiting for cleanup task during disposal: {ex.Message}");
        }
        finally
        {
            // 3. Dispose CancellationTokenSource
            _cleanupCts.Dispose();
            Debug.WriteLine("[ShieldSessionManager] Cleanup CancellationTokenSource disposed.");

            // 4. Force dispose all remaining sessions and locks
            // This ensures resources are released even if cleanup didn't remove everything
            Debug.WriteLine($"[ShieldSessionManager] Disposing {_sessions.Count} remaining sessions...");
            var remainingKeys = _sessions.Keys.ToList(); // Get keys before clearing
            _sessions.Clear(); // Clear the dictionary

            foreach (var key in remainingKeys) // Iterate over copied keys, dictionary is now empty
            {
                // TryGetValue shouldn't be necessary if we just cleared, but safer? No, iterate holders directly.
                // Let's get holders before clearing instead.
            }

            // --- Revised approach for remaining sessions ---
            var remainingHolders = _sessions.Values.ToList(); // Get holders before clearing
            _sessions.Clear(); // Clear the dictionary

            foreach (var holder in remainingHolders)
            {
                try
                {
                    // Dispose session and lock directly, don't wait
                    holder.Session.Dispose();
                    holder.Lock.Dispose();
                }
                catch (Exception ex)
                {
                    // Log error but continue disposing others
                    Debug.WriteLine(
                        $"[ERROR][ShieldSessionManager] Error disposing remaining session {holder.Session.SessionId} during manager disposal: {ex.Message}");
                }
            }

            Debug.WriteLine("[ShieldSessionManager] Finished disposing remaining sessions.");
        }

        GC.SuppressFinalize(this);
    }

    // Finalizer as a safety net (optional but good practice)
    ~ShieldSessionManager()
    {
        Debug.WriteLine(
            $"[WARN][ShieldSessionManager] Finalizer reached for {this.GetType().Name}. DisposeAsync should be called explicitly.");
        // Avoid async calls. Try to cancel if not already disposed.
        if (!_disposed)
        {
            try
            {
                _cleanupCts?.Cancel();
            }
            catch
            {
                /* Ignore */
            }
            // Don't dispose managed resources here (like _sessions, holders)
        }
    }
}
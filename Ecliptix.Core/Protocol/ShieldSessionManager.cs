using System.Collections.Concurrent;
using System.Diagnostics;
using Ecliptix.Core.Protocol.Utilities;
using Ecliptix.Protobuf.PubKeyExchange;

namespace Ecliptix.Core.Protocol;

public sealed class ShieldSessionManager : IAsyncDisposable
{
    private static readonly TimeSpan DefaultCleanupInterval = TimeSpan.FromMinutes(15);
    private readonly ConcurrentDictionary<(PubKeyExchangeType, uint), SessionHolder> _sessions;
    private readonly CancellationTokenSource _cleanupCts;
    private readonly Task _cleanupTask;
    private bool _disposed;

    public ShieldSessionManager(TimeSpan? cleanupInterval = null)
    {
        _sessions = new ConcurrentDictionary<(PubKeyExchangeType, uint), SessionHolder>();
        _cleanupCts = new CancellationTokenSource();
        _cleanupTask = cleanupInterval.HasValue
            ? Task.Factory.StartNew(
                () => CleanupTaskLoop(_cleanupCts.Token, cleanupInterval.Value).GetAwaiter().GetResult(),
                _cleanupCts.Token,
                TaskCreationOptions.LongRunning | TaskCreationOptions.DenyChildAttach,
                TaskScheduler.Default)
            : Task.CompletedTask;
        Logger.WriteLine(
            $"[ShieldSessionManager] Manager created {(cleanupInterval.HasValue ? "with" : "without")} cleanup task.");
    }

    public static ShieldSessionManager Create() => new ShieldSessionManager();

    public static ShieldSessionManager CreateWithCleanup(TimeSpan cleanupInterval) =>
        new ShieldSessionManager(cleanupInterval);

    public async ValueTask<Result<ConnectSession, string>> FindSession(uint sessionId, PubKeyExchangeType exchangeType)
    {
        if (_disposed)
            return Result<ConnectSession, string>.Err("Session manager is disposed.");
        var key = (exchangeType, sessionId);
        return await Task.Run(() =>
        {
            if (_sessions.TryGetValue(key, out var holder))
            {
                Logger.WriteLine($"[ShieldSessionManager] Found session for {key}.");
                return Result<ConnectSession, string>.Ok(holder.Session);
            }

            Logger.WriteLine($"[ShieldSessionManager] Session not found for {key}.");
            return Result<ConnectSession, string>.Err($"Session not found for type {exchangeType} and ID {sessionId}.");
        });
    }

    public async ValueTask<Result<bool, string>> HasSessionForType(PubKeyExchangeType exchangeType)
    {
        if (_disposed)
            return Result<bool, string>.Err("Session manager is disposed.");
        return await Task.Run(() =>
            Result<bool, string>.Ok(_sessions.Keys.Any(key => key.Item1 == exchangeType)));
    }

    public async ValueTask<Result<bool, string>> TryInsertSession(uint sessionId, PubKeyExchangeType exchangeType,
        ConnectSession session)
    {
        if (_disposed)
            return Result<bool, string>.Err("Session manager is disposed.");
        if (session == null)
            return Result<bool, string>.Err("Session cannot be null.");
        (PubKeyExchangeType exchangeType, uint sessionId) key = (exchangeType, sessionId);
        SessionHolder holder = new(session);
        return await Task.Run(() =>
        {
            bool added = _sessions.TryAdd(key, holder);
            Logger.WriteLine(added
                ? $"[ShieldSessionManager] Inserted session {key}. Count: {_sessions.Count}"
                : $"[ShieldSessionManager] Failed to insert session {key} - Key already exists.");
            return Result<bool, string>.Ok(added);
        });
    }

    public async ValueTask<Result<Unit, string>> InsertSession(uint sessionId, PubKeyExchangeType exchangeType,
        ConnectSession session)
    {
        var tryInsertResult = await TryInsertSession(sessionId, exchangeType, session);
        return tryInsertResult.Bind(added => added
            ? Result<Unit, string>.Ok(Unit.Value)
            : Result<Unit, string>.Err($"Session already exists for type {exchangeType} and ID {sessionId}."));
    }

    public async ValueTask<Result<Unit, string>> RemoveSessionAsync(uint sessionId, PubKeyExchangeType exchangeType)
    {
        if (_disposed)
            return Result<Unit, string>.Err("Session manager is disposed.");
        (PubKeyExchangeType exchangeType, uint sessionId) key = (exchangeType, sessionId);
        return await Task.Run(() =>
        {
            if (_sessions.TryRemove(key, out var holder))
            {
                Logger.WriteLine($"[ShieldSessionManager] Removing session {key}. Count: {_sessions.Count}");
                return DisposeHolderAsync(holder, key);
            }

            Logger.WriteLine($"[ShieldSessionManager] Session {key} not found for removal.");
            return Task.FromResult(
                Result<Unit, string>.Err($"Session not found for type {exchangeType} and ID {sessionId}."));
        });
    }

    public async ValueTask<Result<Unit, string>> UpdateSessionStateAsync(uint sessionId,
        PubKeyExchangeType exchangeType, PubKeyExchangeState state)
    {
        var holderResult = await FindSession(sessionId, exchangeType);
        if (!holderResult.IsOk)
            return Result<Unit, string>.Err(holderResult.UnwrapErr());
        var session = holderResult.Unwrap();
        bool acquiredLock = false;
        try
        {
            acquiredLock = await session.Lock.WaitAsync(TimeSpan.FromSeconds(1));
            if (!acquiredLock)
                return Result<Unit, string>.Err($"Failed to acquire lock for session {sessionId}.");
            return Result<Unit, string>.Try(
                () =>
                {
                    session.SetConnectionState(state);
                    Logger.WriteLine(
                        $"[ShieldSessionManager] Updated session ({exchangeType}, {sessionId}) state to {state}.");
                    return Unit.Value;
                },
                ex => $"Failed to update session state: {ex.Message}");
        }
        finally
        {
            if (acquiredLock)
            {
                try
                {
                    session.Lock.Release();
                }
                catch (ObjectDisposedException)
                {
                    Logger.WriteLine($"[ShieldSessionManager] Lock for session {sessionId} was already disposed.");
                }
            }
        }
    }

    public async ValueTask<Result<ConnectSession, string>> FirstSessionByType(PubKeyExchangeType exchangeType)
    {
        if (_disposed)
            return Result<ConnectSession, string>.Err("Session manager is disposed.");
        return await Task.Run(() =>
        {
            var session = _sessions.FirstOrDefault(kvp => kvp.Key.Item1 == exchangeType).Value?.Session;
            return session != null
                ? Result<ConnectSession, string>.Ok(session)
                : Result<ConnectSession, string>.Err($"No session found for type {exchangeType}.");
        });
    }

    public async ValueTask<Result<ConnectSession, string>> GetSession(uint sessionId, PubKeyExchangeType exchangeType)
    {
        return await FindSession(sessionId, exchangeType);
    }

    private async Task CleanupTaskLoop(CancellationToken cancellationToken, TimeSpan interval)
    {
        Logger.WriteLine("[ShieldSessionManager] Cleanup task starting.");
        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(interval, cancellationToken);
                int removedCount = 0;
                foreach (var key in _sessions.Keys.ToList())
                {
                    if (cancellationToken.IsCancellationRequested) break;
                    if (_sessions.TryGetValue(key, out var holder))
                    {
                        var expiredResult = await CheckExpirationAsync(holder, key, cancellationToken);
                        if (expiredResult.IsOk && expiredResult.Unwrap() && _sessions.TryRemove(key, out _))
                        {
                            removedCount++;
                            _ = Task.Run(() => DisposeHolderAsync(holder, key), cancellationToken);
                        }
                    }
                }

                if (removedCount > 0)
                    Logger.WriteLine($"[ShieldSessionManager] Cleanup removed {removedCount} expired sessions.");
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception ex)
            {
                Logger.WriteLine($"[ShieldSessionManager] Cleanup task error: {ex.Message}");
            }
        }

        Logger.WriteLine("[ShieldSessionManager] Cleanup task stopped.");
    }

    private async Task<Result<bool, string>> CheckExpirationAsync(SessionHolder holder,
        (PubKeyExchangeType, uint) key, CancellationToken cancellationToken)
    {
        bool acquiredLock = false;
        try
        {
            acquiredLock = await holder.Lock.WaitAsync(TimeSpan.FromMilliseconds(50), cancellationToken);
            if (!acquiredLock)
                return Result<bool, string>.Err("Could not acquire lock for expiration check.");
            var expiredResult = holder.Session.IsExpired();
            if (!expiredResult.IsOk)
            {
                Logger.WriteLine(
                    $"[ShieldSessionManager] Error checking expiration for session {key}: {expiredResult.UnwrapErr()}");
                return Result<bool, string>.Err(expiredResult.UnwrapErr().Message);
            }

            Logger.WriteLine($"[ShieldSessionManager] Checking session {key}. Expired: {expiredResult.Unwrap()}");
            return Result<bool, string>.Ok(expiredResult.Unwrap());
        }
        catch (OperationCanceledException)
        {
            return Result<bool, string>.Err("Expiration check cancelled.");
        }
        catch (Exception ex)
        {
            Logger.WriteLine($"[ShieldSessionManager] Error checking expiration for session {key}: {ex.Message}");
            return Result<bool, string>.Err($"Error checking expiration: {ex.Message}");
        }
        finally
        {
            if (acquiredLock)
            {
                try
                {
                    holder.Lock.Release();
                }
                catch (ObjectDisposedException)
                {
                    Logger.WriteLine($"[ShieldSessionManager] Lock for session {key} was already disposed.");
                }
            }
        }
    }

    private async Task<Result<Unit, string>> DisposeHolderAsync(SessionHolder holder, (PubKeyExchangeType, uint) key)
    {
        bool acquiredLock = false;
        try
        {
            acquiredLock = await holder.Lock.WaitAsync(TimeSpan.FromSeconds(1));
            return Result<Unit, string>.Ok(Unit.Value);
        }
        catch (Exception ex)
        {
            Logger.WriteLine($"[ShieldSessionManager] Error acquiring lock for session {key}: {ex.Message}");
            return Result<Unit, string>.Err($"Error disposing session: {ex.Message}");
        }
        finally
        {
            if (acquiredLock)
            {
                try
                {
                    holder.Lock.Release();
                }
                catch (ObjectDisposedException)
                {
                    Logger.WriteLine($"[ShieldSessionManager] Lock for session {key} was already disposed.");
                }
            }

            try
            {
                holder.Session.Dispose();
                Logger.WriteLine($"[ShieldSessionManager] Disposed session {key}.");
                holder.Lock.Dispose();
            }
            catch (ObjectDisposedException)
            {
                Logger.WriteLine($"[ShieldSessionManager] Session or lock for {key} was already disposed.");
            }
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (_disposed) return;
        _disposed = true;
        Logger.WriteLine("[ShieldSessionManager] DisposeAsync called.");

        if (!_cleanupCts.IsCancellationRequested)
        {
            Logger.WriteLine("[ShieldSessionManager] Cancelling cleanup task...");
            _cleanupCts.Cancel();
        }

        try
        {
            await _cleanupTask.WaitAsync(TimeSpan.FromSeconds(5));
            Logger.WriteLine("[ShieldSessionManager] Cleanup task completed.");
        }
        catch (Exception ex)
        {
            Logger.WriteLine($"[ShieldSessionManager] Error waiting for cleanup task: {ex.Message}");
        }
        finally
        {
            _cleanupCts.Dispose();
        }

        foreach (var kvp in _sessions.ToList())
        {
            if (_sessions.TryRemove(kvp.Key, out var holder))
            {
                (await DisposeHolderAsync(holder, kvp.Key)).IgnoreResult();
            }
        }

        _sessions.Clear();
        Logger.WriteLine("[ShieldSessionManager] Disposed all sessions.");
        GC.SuppressFinalize(this);
    }

    private static class Logger
    {
        private static readonly object Lock = new();

        public static void WriteLine(string message)
        {
            lock (Lock)
            {
                Debug.WriteLine($"[{DateTime.UtcNow:HH:mm:ss.fff}] {message}");
            }
        }
    }
}
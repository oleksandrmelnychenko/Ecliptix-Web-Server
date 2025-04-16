using System.Collections.Concurrent;
using System.Diagnostics;
using Ecliptix.Core.Protocol.Utilities;
using Ecliptix.Protobuf.PubKeyExchange;

namespace Ecliptix.Core.Protocol;

public sealed class ShieldSessionManager : IAsyncDisposable
{
    private readonly ConcurrentDictionary<(PubKeyExchangeOfType, uint), SessionHolder> _sessions;
    private readonly CancellationTokenSource _cleanupCts;
    private readonly Task _cleanupTask;
    private bool _disposed;

    public ShieldSessionManager(TimeSpan? cleanupInterval = null)
    {
        _sessions = new ConcurrentDictionary<(PubKeyExchangeOfType, uint), SessionHolder>();
        _cleanupCts = new CancellationTokenSource();
        _cleanupTask = cleanupInterval.HasValue
            ? Task.Factory.StartNew(
                () => CleanupTaskLoop(_cleanupCts.Token, cleanupInterval.Value).GetAwaiter().GetResult(),
                _cleanupCts.Token,
                TaskCreationOptions.LongRunning | TaskCreationOptions.DenyChildAttach,
                TaskScheduler.Default)
            : Task.CompletedTask;
    }

    public static ShieldSessionManager Create() => new();

    public async ValueTask<Result<ShieldSession, string>> FindSession(uint sessionId, PubKeyExchangeOfType exchangeType)
    {
        if (_disposed)
            return Result<ShieldSession, string>.Err("Session manager is disposed.");
        var key = (exchangeType, sessionId);
        return await Task.Run(() =>
        {
            if (_sessions.TryGetValue(key, out var holder))
            {
                return Result<ShieldSession, string>.Ok(holder.Session);
            }

            return Result<ShieldSession, string>.Err($"Session not found for type {exchangeType} and ID {sessionId}.");
        });
    }

    public async ValueTask<Result<bool, string>> HasSessionForType(PubKeyExchangeOfType exchangeType)
    {
        if (_disposed)
            return Result<bool, string>.Err("Session manager is disposed.");
        return await Task.Run(() =>
            Result<bool, string>.Ok(_sessions.Keys.Any(key => key.Item1 == exchangeType)));
    }

    public async ValueTask<Result<bool, string>> TryInsertSession(uint sessionId, PubKeyExchangeOfType exchangeType,
        ShieldSession session)
    {
        if (_disposed)
            return Result<bool, string>.Err("Session manager is disposed.");
        (PubKeyExchangeOfType exchangeType, uint sessionId) key = (exchangeType, sessionId);
        SessionHolder holder = new(session);
        return await Task.Run(() =>
        {
            bool added = _sessions.TryAdd(key, holder);
            return Result<bool, string>.Ok(added);
        });
    }

    public async ValueTask<Result<Unit, string>> InsertSession(uint sessionId, PubKeyExchangeOfType exchangeType,
        ShieldSession session)
    {
        var tryInsertResult = await TryInsertSession(sessionId, exchangeType, session);
        return tryInsertResult.Bind(added => added
            ? Result<Unit, string>.Ok(Unit.Value)
            : Result<Unit, string>.Err($"Session already exists for type {exchangeType} and ID {sessionId}."));
    }

    public async ValueTask<Result<Unit, string>> RemoveSessionAsync(uint sessionId, PubKeyExchangeOfType exchangeType)
    {
        if (_disposed)
            return Result<Unit, string>.Err("Session manager is disposed.");
        (PubKeyExchangeOfType exchangeType, uint sessionId) key = (exchangeType, sessionId);
        return await Task.Run(() =>
        {
            if (_sessions.TryRemove(key, out var holder))
            {
                return DisposeHolderAsync(holder, key);
            }

            return Task.FromResult(
                Result<Unit, string>.Err($"Session not found for type {exchangeType} and ID {sessionId}."));
        });
    }

    public async ValueTask<Result<Unit, string>> UpdateSessionStateAsync(uint sessionId,
        PubKeyExchangeOfType exchangeType, PubKeyExchangeState state)
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
                    return Unit.Value;
                },
                ex => $"Failed to update session state: {ex.Message}");
        }
        finally
        {
            if (acquiredLock)
            {
                
                    session.Lock.Release();
               
            }
        }
    }

    public async ValueTask<Result<ShieldSession, string>> FirstSessionByType(PubKeyExchangeOfType exchangeType)
    {
        if (_disposed)
            return Result<ShieldSession, string>.Err("Session manager is disposed.");
        return await Task.Run(() =>
        {
            var session = _sessions.FirstOrDefault(kvp => kvp.Key.Item1 == exchangeType).Value?.Session;
            return session != null
                ? Result<ShieldSession, string>.Ok(session)
                : Result<ShieldSession, string>.Err($"No session found for type {exchangeType}.");
        });
    }

    public async ValueTask<Result<ShieldSession, string>> GetSession(uint sessionId, PubKeyExchangeOfType exchangeType)
    {
        return await FindSession(sessionId, exchangeType);
    }

    private async Task CleanupTaskLoop(CancellationToken cancellationToken, TimeSpan interval)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(interval, cancellationToken);
                foreach ((PubKeyExchangeOfType, uint) key in _sessions.Keys.ToList())
                {
                    if (cancellationToken.IsCancellationRequested) break;
                    if (_sessions.TryGetValue(key, out var holder))
                    {
                        var expiredResult = await CheckExpirationAsync(holder, key, cancellationToken);
                        if (expiredResult.IsOk && expiredResult.Unwrap() && _sessions.TryRemove(key, out _))
                        {
                            _ = Task.Run(() => DisposeHolderAsync(holder, key), cancellationToken);
                        }
                    }
                }
            }
            catch (OperationCanceledException)
            {
                break;
            }
        }
    }

    private async Task<Result<bool, string>> CheckExpirationAsync(SessionHolder holder,
        (PubKeyExchangeOfType, uint) key, CancellationToken cancellationToken)
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
                return Result<bool, string>.Err(expiredResult.UnwrapErr().Message);
            }

            return Result<bool, string>.Ok(expiredResult.Unwrap());
        }
        catch (OperationCanceledException)
        {
            return Result<bool, string>.Err("Expiration check cancelled.");
        }
        catch (Exception ex)
        {
            return Result<bool, string>.Err($"Error checking expiration: {ex.Message}");
        }
        finally
        {
            if (acquiredLock)
            {
               
                    holder.Lock.Release();
               
            }
        }
    }

    private async Task<Result<Unit, string>> DisposeHolderAsync(SessionHolder holder, (PubKeyExchangeOfType, uint) key)
    {
        bool acquiredLock = false;
        try
        {
            acquiredLock = await holder.Lock.WaitAsync(TimeSpan.FromSeconds(1));
            return Result<Unit, string>.Ok(Unit.Value);
        }
        catch (Exception ex)
        {
            return Result<Unit, string>.Err($"Error disposing session: {ex.Message}");
        }
        finally
        {
            if (acquiredLock)
            {
               holder.Lock.Release();
                
            }

                holder.Session.Dispose();
                holder.Lock.Dispose();
           
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (_disposed) return;
        _disposed = true;

        if (!_cleanupCts.IsCancellationRequested)
        {
            await _cleanupCts.CancelAsync();
        }

        try
        {
            await _cleanupTask.WaitAsync(TimeSpan.FromSeconds(5));
        }
        finally
        {
            _cleanupCts.Dispose();
        }

        foreach (KeyValuePair<(PubKeyExchangeOfType, uint), SessionHolder> kvp in _sessions.ToList())
        {
            if (_sessions.TryRemove(kvp.Key, out var holder))
            {
                (await DisposeHolderAsync(holder, kvp.Key)).IgnoreResult();
            }
        }

        _sessions.Clear();
        GC.SuppressFinalize(this);
    }
}
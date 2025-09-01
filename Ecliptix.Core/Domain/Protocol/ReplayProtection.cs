using System.Collections.Concurrent;
using Ecliptix.Domain.Utilities;

namespace Ecliptix.Core.Domain.Protocol;

public sealed class ReplayProtection : IDisposable
{
    private readonly ConcurrentDictionary<string, DateTime> _processedNonces;
    private readonly ConcurrentDictionary<ulong, MessageWindow> _messageWindows;
    private readonly TimeSpan _nonceLifetime;
    private ulong _maxOutOfOrderWindow;
    private readonly Timer _cleanupTimer;
    private readonly Lock _lock = new();
    private readonly ulong _baseWindow;
    private readonly ulong _maxWindow;
    private int _recentMessageCount;
    private DateTime _lastWindowAdjustment = DateTime.UtcNow;
    private bool _disposed;

    public ReplayProtection(
        TimeSpan nonceLifetime = default,
        ulong maxOutOfOrderWindow = Constants.DefaultMaxOutOfOrderWindow,
        ulong maxWindow = 5000)
    {
        _processedNonces = new ConcurrentDictionary<string, DateTime>();
        _messageWindows = new ConcurrentDictionary<ulong, MessageWindow>();
        _nonceLifetime = nonceLifetime == TimeSpan.Zero ? TimeSpan.FromMinutes(5) : nonceLifetime;
        _baseWindow = maxOutOfOrderWindow;
        _maxOutOfOrderWindow = maxOutOfOrderWindow;
        _maxWindow = maxWindow;

        _cleanupTimer = new Timer(
            callback: _ => {
                CleanupExpiredEntries();
                AdjustWindowSize();
            },
            state: null,
            dueTime: TimeSpan.FromMinutes(1),
            period: TimeSpan.FromMinutes(1)
        );
    }

    public Result<Unit, EcliptixProtocolFailure> CheckAndRecordMessage(
        ReadOnlySpan<byte> nonce,
        ulong messageIndex,
        ulong chainIndex = 0)
    {
        if (_disposed)
            return Result<Unit, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.ObjectDisposed(nameof(ReplayProtection)));

        if (nonce.Length == 0)
            return Result<Unit, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.InvalidInput("Nonce cannot be empty"));

        lock (_lock)
        {
            string nonceKey = Convert.ToBase64String(nonce);

            if (_processedNonces.ContainsKey(nonceKey))
                return Result<Unit, EcliptixProtocolFailure>.Err(
                    EcliptixProtocolFailure.ReplayAttempt($"Message with nonce {nonceKey[..8]}... already processed"));

            MessageWindow window = _messageWindows.GetOrAdd(chainIndex, _ => new MessageWindow());

            Result<Unit, EcliptixProtocolFailure> windowResult = window.CheckAndRecordMessage(messageIndex, _maxOutOfOrderWindow);
            if (windowResult.IsErr)
                return windowResult;

            _processedNonces[nonceKey] = DateTime.UtcNow;
            _recentMessageCount++;

            return Result<Unit, EcliptixProtocolFailure>.Ok(Unit.Value);
        }
    }

    private void CleanupExpiredEntries()
    {
        if (_disposed) return;

        lock (_lock)
        {
            DateTime cutoff = DateTime.UtcNow - _nonceLifetime;
            List<string> expiredKeys = [];

            foreach ((string key, DateTime timestamp) in _processedNonces)
            {
                if (timestamp < cutoff)
                    expiredKeys.Add(key);
            }

            foreach (string key in expiredKeys)
                _processedNonces.TryRemove(key, out _);

            foreach ((ulong chainIndex, MessageWindow window) in _messageWindows.ToArray())
            {
                if (window.IsExpired(TimeSpan.FromHours(1)))
                    _messageWindows.TryRemove(chainIndex, out _);
            }
        }
    }

    private void AdjustWindowSize()
    {
        if (_disposed) return;

        lock (_lock)
        {
            TimeSpan timeSinceLastAdjustment = DateTime.UtcNow - _lastWindowAdjustment;
            if (timeSinceLastAdjustment < TimeSpan.FromMinutes(5))
                return;

            double messagesPerMinute = _recentMessageCount / Math.Max(1, timeSinceLastAdjustment.TotalMinutes);

            if (messagesPerMinute > 100)
                _maxOutOfOrderWindow = Math.Min(_maxWindow, _maxOutOfOrderWindow * 2);
            else if (messagesPerMinute < 10)
                _maxOutOfOrderWindow = Math.Max(_baseWindow, _maxOutOfOrderWindow / 2);

            _recentMessageCount = 0;
            _lastWindowAdjustment = DateTime.UtcNow;
        }
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;

        _cleanupTimer?.Dispose();
        _processedNonces.Clear();
        _messageWindows.Clear();
    }

    public void OnRatchetRotation()
    {
        if (_disposed) return;

        lock (_lock)
        {
            _messageWindows.Clear();
        }
    }
}

internal sealed class MessageWindow
{
    private readonly HashSet<ulong> _processedMessages = [];
    private ulong _highestIndex;
    private DateTime _lastAccess = DateTime.UtcNow;

    public Result<Unit, EcliptixProtocolFailure> CheckAndRecordMessage(ulong messageIndex, ulong maxWindow)
    {
        _lastAccess = DateTime.UtcNow;

        if (_processedMessages.Contains(messageIndex))
            return Result<Unit, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.ReplayAttempt($"Message with index {messageIndex} already processed"));

        if (messageIndex <= _highestIndex && (_highestIndex - messageIndex) > maxWindow)
            return Result<Unit, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.Generic($"Message index {messageIndex} is too old (current highest: {_highestIndex})"));

        _processedMessages.Add(messageIndex);

        if (messageIndex > _highestIndex)
            _highestIndex = messageIndex;

        if (_processedMessages.Count > (int)maxWindow * 2)
        {
            ulong cutoff = _highestIndex > maxWindow ? _highestIndex - maxWindow : 0;
            _processedMessages.RemoveWhere(index => index < cutoff);
        }

        return Result<Unit, EcliptixProtocolFailure>.Ok(Unit.Value);
    }

    public bool IsExpired(TimeSpan maxAge)
    {
        return DateTime.UtcNow - _lastAccess > maxAge;
    }
}
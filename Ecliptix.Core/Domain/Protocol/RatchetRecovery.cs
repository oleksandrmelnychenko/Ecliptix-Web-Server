using Ecliptix.Utilities;

namespace Ecliptix.Core.Domain.Protocol;

public sealed class RatchetRecovery : IDisposable
{
    private readonly Dictionary<uint, RatchetChainKey> _skippedMessageKeys = new();
    private readonly Lock _lock = new();
    private bool _disposed;

    public Result<Option<RatchetChainKey>, EcliptixProtocolFailure> TryRecoverMessageKey(uint messageIndex)
    {
        if (_disposed)
        {
            return Result<Option<RatchetChainKey>, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.ObjectDisposed(nameof(RatchetRecovery)));
        }

        lock (_lock)
        {
            return Result<Option<RatchetChainKey>, EcliptixProtocolFailure>.Ok(
                _skippedMessageKeys.Remove(messageIndex, out RatchetChainKey? key)
                    ? Option<RatchetChainKey>.Some(key)
                    : Option<RatchetChainKey>.None);
        }
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;

        lock (_lock)
        {
            CleanupSkippedKeys();
        }
    }

    private void CleanupSkippedKeys()
    {
        lock (_lock)
        {
            foreach (RatchetChainKey key in _skippedMessageKeys.Values)
            {
                key.Dispose();
            }

            _skippedMessageKeys.Clear();
        }
    }
}

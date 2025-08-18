using Ecliptix.Domain.Utilities;

namespace Ecliptix.Core.Protocol;

public sealed class RatchetRecovery(uint maxSkippedMessages = Constants.DefaultMaxSkippedMessages) : IDisposable
{
    private readonly Dictionary<uint, EcliptixMessageKey> _skippedMessageKeys = new();
    private readonly Lock _lock = new();
    private bool _disposed;

    public Result<Option<EcliptixMessageKey>, EcliptixProtocolFailure> TryRecoverMessageKey(uint messageIndex)
    {
        if (_disposed)
            return Result<Option<EcliptixMessageKey>, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.ObjectDisposed(nameof(RatchetRecovery)));

        lock (_lock)
        {
            return Result<Option<EcliptixMessageKey>, EcliptixProtocolFailure>.Ok(
                _skippedMessageKeys.Remove(messageIndex, out EcliptixMessageKey? key)
                    ? Option<EcliptixMessageKey>.Some(key)
                    : Option<EcliptixMessageKey>.None);
        }
    }

    public Result<Unit, EcliptixProtocolFailure> StoreSkippedMessageKeys(
        byte[] currentChainKey,
        uint fromIndex,
        uint toIndex)
    {
        if (_disposed)
            return Result<Unit, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.ObjectDisposed(nameof(RatchetRecovery)));

        if (toIndex <= fromIndex)
            return Result<Unit, EcliptixProtocolFailure>.Ok(Unit.Value);

        lock (_lock)
        {
            uint skippedCount = toIndex - fromIndex;
            if (_skippedMessageKeys.Count + skippedCount > maxSkippedMessages)
            {
                return Result<Unit, EcliptixProtocolFailure>.Err(
                    EcliptixProtocolFailure.Generic(
                        $"Too many skipped messages: {_skippedMessageKeys.Count + skippedCount} > {maxSkippedMessages}"));
            }

            using ScopedSecureMemoryCollection secureMemory = new();
            byte[] workingChainKey = secureMemory.Allocate(currentChainKey.Length);
            currentChainKey.CopyTo(workingChainKey, 0);

            for (uint messageIndex = fromIndex; messageIndex < toIndex; messageIndex++)
            {
                Result<EcliptixMessageKey, EcliptixProtocolFailure> messageKeyResult = 
                    EcliptixMessageKey.DeriveFromChainKey(workingChainKey, messageIndex);
                
                if (messageKeyResult.IsErr)
                {
                    CleanupSkippedKeys();
                    return Result<Unit, EcliptixProtocolFailure>.Err(messageKeyResult.UnwrapErr());
                }

                _skippedMessageKeys[messageIndex] = messageKeyResult.Unwrap();

                Result<Unit, EcliptixProtocolFailure> advanceResult = AdvanceChainKey(workingChainKey);
                if (advanceResult.IsErr)
                {
                    CleanupSkippedKeys();
                    return Result<Unit, EcliptixProtocolFailure>.Err(advanceResult.UnwrapErr());
                }
            }

            return Result<Unit, EcliptixProtocolFailure>.Ok(Unit.Value);
        }
    }

    private static Result<Unit, EcliptixProtocolFailure> AdvanceChainKey(byte[] chainKey)
    {
        return Result<Unit, EcliptixProtocolFailure>.Try(
            () =>
            {
                byte[] newChainKey = new byte[Constants.X25519KeySize];
                try
                {
                    System.Security.Cryptography.HKDF.DeriveKey(
                        System.Security.Cryptography.HashAlgorithmName.SHA256,
                        ikm: chainKey,
                        output: newChainKey,
                        salt: null,
                        info: Constants.ChainInfo
                    );
                    
                    newChainKey.CopyTo(chainKey, 0);
                }
                finally
                {
                    SodiumInterop.SecureWipe(newChainKey);
                }
            },
            ex => EcliptixProtocolFailure.DeriveKey("Failed to advance chain key using HKDF", ex)
        );
    }

    public void CleanupOldKeys(uint beforeIndex)
    {
        if (_disposed) return;

        lock (_lock)
        {
            List<uint> keysToRemove = _skippedMessageKeys.Keys
                .Where(index => index < beforeIndex)
                .ToList();

            foreach (uint index in keysToRemove)
            {
                if (_skippedMessageKeys.Remove(index, out EcliptixMessageKey? key))
                    key.Dispose();
            }
        }
    }

    private void CleanupSkippedKeys()
    {
        foreach (EcliptixMessageKey key in _skippedMessageKeys.Values)
            key.Dispose();
        _skippedMessageKeys.Clear();
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;

        lock (_lock)
        {
            CleanupSkippedKeys();
        }
    }
}

internal sealed class ScopedSecureMemoryCollection : IDisposable
{
    private readonly List<byte[]> _allocations = [];
    private bool _disposed;

    public byte[] Allocate(int size)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        
        byte[] buffer = new byte[size];
        _allocations.Add(buffer);
        return buffer;
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;

        foreach (byte[] allocation in _allocations)
            SodiumInterop.SecureWipe(allocation);
        
        _allocations.Clear();
    }
}
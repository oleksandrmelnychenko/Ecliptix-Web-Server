using System;
using Microsoft.Extensions.Caching.Memory;

namespace Ecliptix.Core.Infrastructure.Grpc.Security;

public sealed class MemoryServerNonceStore(IMemoryCache cache) : IServerNonceStore
{
    private readonly Lock _sync = new();

    public void Store(uint connectId, byte[] nonce, TimeSpan ttl)
    {
        if (nonce is null)
        {
            throw new ArgumentNullException(nameof(nonce));
        }

        if (nonce.Length == 0)
        {
            throw new ArgumentException("nonce is required", nameof(nonce));
        }

        string cacheKey = BuildCacheKey(connectId);
        byte[] copy = new byte[nonce.Length];
        Buffer.BlockCopy(nonce, 0, copy, 0, nonce.Length);

        lock (_sync)
        {
            cache.Set(cacheKey, copy, new MemoryCacheEntryOptions { AbsoluteExpirationRelativeToNow = ttl });
        }
    }

    public bool TryTake(uint connectId, out byte[] nonce)
    {
        string cacheKey = BuildCacheKey(connectId);
        lock (_sync)
        {
            if (cache.TryGetValue(cacheKey, out byte[]? value))
            {
                cache.Remove(cacheKey);
                nonce = new byte[value!.Length];
                Buffer.BlockCopy(value, 0, nonce, 0, value.Length);
                return true;
            }
        }

        nonce = Array.Empty<byte>();
        return false;
    }

    private static string BuildCacheKey(uint connectId) => $"server_nonce:{connectId}";
}

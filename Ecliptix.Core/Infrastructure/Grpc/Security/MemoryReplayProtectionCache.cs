using System;
using Microsoft.Extensions.Caching.Memory;

namespace Ecliptix.Core.Infrastructure.Grpc.Security;

public sealed class MemoryReplayProtectionCache(IMemoryCache cache) : IReplayProtectionCache
{
    private readonly object _sync = new();

    public bool TryBegin(string scope, string key, TimeSpan ttl)
    {
        if (string.IsNullOrWhiteSpace(scope))
        {
            throw new ArgumentException("scope is required", nameof(scope));
        }

        if (string.IsNullOrWhiteSpace(key))
        {
            throw new ArgumentException("key is required", nameof(key));
        }

        string cacheKey = BuildCacheKey(scope, key);
        lock (_sync)
        {
            if (cache.TryGetValue(cacheKey, out _))
            {
                return false;
            }

            cache.Set(cacheKey, true, new MemoryCacheEntryOptions
            {
                AbsoluteExpirationRelativeToNow = ttl
            });

            return true;
        }
    }

    public void Release(string scope, string key)
    {
        if (string.IsNullOrWhiteSpace(scope) || string.IsNullOrWhiteSpace(key))
        {
            return;
        }

        cache.Remove(BuildCacheKey(scope, key));
    }

    private static string BuildCacheKey(string scope, string key) => $"{scope}:{key}";
}

using System;
using System.Collections.Concurrent;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;
using StackExchange.Redis;
using Ecliptix.Domain.Abstractions;
using Ecliptix.Domain.Utilities;

namespace Ecliptix.Core.Services;

public class DistributedSessionKeyService(
    IDistributedCache distributedCache,
    IMemoryCache memoryCache,
    IDataProtectionProvider dataProtectionProvider,
    IConnectionMultiplexer redis)
    : ISessionKeyService
{
    private readonly IDataProtector _dataProtector = dataProtectionProvider.CreateProtector("SessionKeys");

    private static readonly TimeSpan SessionExpiry   = TimeSpan.FromHours(1);
    private static readonly TimeSpan LocalCacheExpiry = TimeSpan.FromMinutes(5);
    private const  string CacheKeyPrefix = "session:";
    private const  string RedisIndexKey  = "session:index";

    private readonly ConcurrentDictionary<string, byte> _localKeyIndex = new();

    public async Task<Result<Unit, string>> StoreSessionKeyAsync(uint connectId, byte[] sessionKey)
    {
        if (sessionKey is null || sessionKey.Length == 0)
            return Result<Unit, string>.Err("Session key is required");

        string key = BuildCacheKey(connectId);
        byte[]? localCacheCopy = null;

        try
        {
            localCacheCopy = CopyOf(sessionKey);
            byte[] encryptedKey = _dataProtector.Protect(sessionKey);

            DistributedCacheEntryOptions options = new DistributedCacheEntryOptions
            {
                AbsoluteExpirationRelativeToNow = SessionExpiry
            };
            await distributedCache.SetAsync(key, encryptedKey, options).ConfigureAwait(false);

            IDatabase db = redis.GetDatabase();
            _ = await db.SetAddAsync(RedisIndexKey, key).ConfigureAwait(false);

            memoryCache.Set(key, localCacheCopy, BuildMemoryOptions());
            _localKeyIndex[key] = 1;

            Zero(sessionKey);

            return Result<Unit, string>.Ok(Unit.Value);
        }
        catch (Exception ex)
        {
            if (localCacheCopy is not null && !memoryCache.TryGetValue(key, out _))
                Zero(localCacheCopy);
            return Result<Unit, string>.Err($"Failed to store session key: {ex.Message}");
        }
        finally
        {
            Zero(sessionKey);
        }
    }

    public async Task<Result<byte[], string>> GetSessionKeyAsync(uint connectId)
    {
        string key = BuildCacheKey(connectId);

        try
        {
            if (memoryCache.TryGetValue(key, out byte[]? cachedKey) && cachedKey is not null)
            {
                return Result<byte[], string>.Ok(CopyOf(cachedKey));
            }

            byte[]? encryptedKey = await distributedCache.GetAsync(key).ConfigureAwait(false);
            if (encryptedKey is null)
            {
                return Result<byte[], string>.Err("Session key not found");
            }

            byte[] decrypted = _dataProtector.Unprotect(encryptedKey);

            byte[] localCacheCopy = CopyOf(decrypted);
            memoryCache.Set(key, localCacheCopy, BuildMemoryOptions());
            _localKeyIndex[key] = 1;

            byte[] toCaller = CopyOf(decrypted);

            Zero(decrypted);

            return Result<byte[], string>.Ok(toCaller);
        }
        catch (Exception ex)
        {
            return Result<byte[], string>.Err($"Failed to get session key: {ex.Message}");
        }
    }

    public async Task<Result<Unit, string>> InvalidateSessionKeyAsync(uint connectId)
    {
        string key = BuildCacheKey(connectId);

        try
        {
            await distributedCache.RemoveAsync(key).ConfigureAwait(false);
            IDatabase db = redis.GetDatabase();
            _ = await db.SetRemoveAsync(RedisIndexKey, key).ConfigureAwait(false);

            memoryCache.Remove(key);
            _localKeyIndex.TryRemove(key, out _);

            return Result<Unit, string>.Ok(Unit.Value);
        }
        catch (Exception ex)
        {
            return Result<Unit, string>.Err($"Failed to invalidate session key: {ex.Message}");
        }
    }

    public async Task<Result<Unit, string>> InvalidateAllSessionKeysAsync()
    {
        try
        {
            IDatabase db = redis.GetDatabase();

            RedisValue[] members = await db.SetMembersAsync(RedisIndexKey).ConfigureAwait(false);
            if (members.Length > 0)
            {
                RedisKey[] redisKeys = members.Select(m => (RedisKey)m.ToString()).ToArray();
                await db.KeyDeleteAsync(redisKeys).ConfigureAwait(false);
                await db.KeyDeleteAsync(RedisIndexKey).ConfigureAwait(false);
            }

            foreach (string k in _localKeyIndex.Keys)
            {
                memoryCache.Remove(k);
            }
            _localKeyIndex.Clear();

            return Result<Unit, string>.Ok(Unit.Value);
        }
        catch (Exception ex)
        {
            return Result<Unit, string>.Err($"Failed to invalidate all session keys: {ex.Message}");
        }
    }

    public async Task<bool> HasValidSessionKeyAsync(uint connectId)
    {
        string key = BuildCacheKey(connectId);

        if (memoryCache.TryGetValue<byte[]>(key, out byte[]? _))
            return true;

        try
        {
            IDatabase db = redis.GetDatabase();
            return await db.KeyExistsAsync(key).ConfigureAwait(false);
        }
        catch
        {
            Result<byte[], string> result = await GetSessionKeyAsync(connectId).ConfigureAwait(false);
            return result.IsOk;
        }
    }


    private static string BuildCacheKey(uint connectId) => $"{CacheKeyPrefix}{connectId}";

    private static MemoryCacheEntryOptions BuildMemoryOptions() =>
        new()
        {
            AbsoluteExpirationRelativeToNow = LocalCacheExpiry,
            Priority = CacheItemPriority.High,
            PostEvictionCallbacks =
            {
                new PostEvictionCallbackRegistration
                {
                    EvictionCallback = static (_, value, _, __) =>
                    {
                        if (value is byte[] keyBytes)
                        {
                            Zero(keyBytes);
                        }
                    }
                }
            }
        };

    private static byte[] CopyOf(byte[] source)
    {
        byte[] copy = new byte[source.Length];
        Buffer.BlockCopy(source, 0, copy, 0, source.Length);
        return copy;
    }

    private static void Zero(byte[]? bytes)
    {
        if (bytes is null) return;
        CryptographicOperations.ZeroMemory(bytes);
    }
}

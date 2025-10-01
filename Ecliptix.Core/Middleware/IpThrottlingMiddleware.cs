using Microsoft.Extensions.Caching.Distributed;
using Serilog;
using System.Collections.Concurrent;
using System.Net;
using System.Text.Json;
using Ecliptix.Core.Json;
using Ecliptix.Core.Middleware.Models;
using Ecliptix.Core.Configuration;
using AppConstants = Ecliptix.Core.Configuration.ApplicationConstants;

namespace Ecliptix.Core.Middleware;

public class IpThrottlingMiddleware(RequestDelegate next, IDistributedCache cache)
{
    private static readonly ConcurrentDictionary<string, ThrottleInfo> ThrottleData = new();
    private static readonly TimeSpan CleanupInterval = TimeSpan.FromMinutes(ThrottlingConstants.CleanupIntervalMinutes);
    private static DateTime _lastCleanup = DateTime.UtcNow;

    public async Task InvokeAsync(HttpContext context)
    {
        string clientIp = GetClientIpAddress(context);

        PerformCleanupIfNeeded();

        if (await IsIpBlocked(clientIp))
        {
            await HandleBlockedRequest(context, clientIp);
            return;
        }

        if (!CheckRateLimit(clientIp))
        {
            await HandleRateLimitExceeded(context, clientIp);
            return;
        }

        try
        {
            await next(context);

            TrackRequest(clientIp, success: context.Response.StatusCode < SecurityConstants.StatusCodes.BadRequestThreshold);
        }
        catch (Exception)
        {
            TrackRequest(clientIp, success: false);
            throw;
        }
    }

    private static string GetClientIpAddress(HttpContext context)
    {
        string? forwardedFor = context.Request.Headers[SecurityConstants.HttpHeaders.XForwardedFor].FirstOrDefault();
        if (!string.IsNullOrEmpty(forwardedFor))
        {
            string[] ips = forwardedFor.Split(',', StringSplitOptions.RemoveEmptyEntries);
            if (ips.Length > AppConstants.Arrays.InitialValue)
            {
                string firstIp = ips[AppConstants.Arrays.FirstIndex].Trim();
                if (IPAddress.TryParse(firstIp, out _))
                    return firstIp;
            }
        }

        string? realIp = context.Request.Headers[SecurityConstants.HttpHeaders.XRealIP].FirstOrDefault();
        if (!string.IsNullOrEmpty(realIp) && IPAddress.TryParse(realIp, out _))
            return realIp;

        return context.Connection.RemoteIpAddress?.ToString() ?? SecurityConstants.SecurityValues.UnknownIpAddress;
    }

    private async Task<bool> IsIpBlocked(string clientIp)
    {
        try
        {
            string key = $"{ThrottlingConstants.CacheKeys.BlockedIpPrefix}{clientIp}";
            string? blockedData = await cache.GetStringAsync(key);

            if (blockedData == null) return false;
            BlockInfo? blockInfo = JsonSerializer.Deserialize(blockedData, AppJsonSerializerContext.Default.BlockInfo);
            if (blockInfo?.ExpiresAt > DateTime.UtcNow)
            {
                return true;
            }

            await cache.RemoveAsync(key);

            return false;
        }
        catch (Exception ex)
        {
            Log.Warning(ex, "Cache error while checking IP block status for {ClientIp}. Allowing request to proceed.", clientIp);
            return false;
        }
    }

    private static bool CheckRateLimit(string clientIp)
    {
        ThrottleInfo throttleInfo = ThrottleData.GetOrAdd(clientIp, _ => new ThrottleInfo());

        lock (throttleInfo)
        {
            DateTime now = DateTime.UtcNow;

            if (now - throttleInfo.WindowStart >= TimeSpan.FromMinutes(AppConstants.Arrays.SingleMinute))
            {
                throttleInfo.RequestCount = AppConstants.Arrays.WindowResetValue;
                throttleInfo.WindowStart = now;
            }

            throttleInfo.RequestCount++;
            throttleInfo.LastRequest = now;

            return throttleInfo.RequestCount <= ThrottlingConstants.MaxRequestsPerMinute;
        }
    }

    private void TrackRequest(string clientIp, bool success)
    {
        if (!success)
        {
            ThrottleInfo throttleInfo = ThrottleData.GetOrAdd(clientIp, _ => new ThrottleInfo());

            lock (throttleInfo)
            {
                throttleInfo.FailureCount++;
                throttleInfo.LastFailure = DateTime.UtcNow;

                if (throttleInfo.FailureCount >= ThrottlingConstants.MaxFailuresBeforeBlock)
                {
                    _ = Task.Run(async () => await BlockIp(clientIp, ThrottlingConstants.BlockDurationMinutes));
                }
            }
        }
        else
        {
            if (!ThrottleData.TryGetValue(clientIp, out ThrottleInfo? throttleInfo)) return;
            lock (throttleInfo)
            {
                throttleInfo.FailureCount = Math.Max(AppConstants.Arrays.InitialValue, throttleInfo.FailureCount - 1);
            }
        }
    }

    private async Task BlockIp(string clientIp, int durationMinutes)
    {
        BlockInfo blockInfo = new()
        {
            IpAddress = clientIp,
            BlockedAt = DateTime.UtcNow,
            ExpiresAt = DateTime.UtcNow.AddMinutes(durationMinutes),
            Reason = ThrottlingConstants.Messages.TooManyFailedRequests
        };

        try
        {
            string key = $"{ThrottlingConstants.CacheKeys.BlockedIpPrefix}{clientIp}";
            string serializedData = JsonSerializer.Serialize(blockInfo, AppJsonSerializerContext.Default.BlockInfo);
            DistributedCacheEntryOptions options = new()
            {
                AbsoluteExpirationRelativeToNow = TimeSpan.FromMinutes(durationMinutes)
            };

            await cache.SetStringAsync(key, serializedData, options);

            Log.Warning(ThrottlingConstants.Messages.IpBlocked,
                clientIp, durationMinutes, blockInfo.Reason);
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Cache error while attempting to block IP {ClientIp}. IP blocking in distributed cache unavailable.", clientIp);
        }
    }

    private async Task HandleBlockedRequest(HttpContext context, string clientIp)
    {
        context.Response.StatusCode = StatusCodes.Status429TooManyRequests;
        context.Response.Headers[SecurityConstants.HttpHeaders.RetryAfter] = ThrottlingConstants.RetryAfterBlocked;

        Log.Warning(ThrottlingConstants.Messages.BlockedRequest, clientIp);

        await context.Response.WriteAsync(ThrottlingConstants.Messages.IpTemporarilyBlocked);
    }

    private static async Task HandleRateLimitExceeded(HttpContext context, string clientIp)
    {
        context.Response.StatusCode = StatusCodes.Status429TooManyRequests;
        context.Response.Headers[SecurityConstants.HttpHeaders.RetryAfter] = ThrottlingConstants.RetryAfterRateLimit;

        Log.Information(ThrottlingConstants.Messages.RateLimitExceededLog, clientIp);

        await context.Response.WriteAsync(ThrottlingConstants.Messages.RateLimitExceeded);
    }

    private static void PerformCleanupIfNeeded()
    {
        DateTime now = DateTime.UtcNow;
        if (now - _lastCleanup < CleanupInterval)
            return;

        _lastCleanup = now;

        DateTime cutoff = now.AddMinutes(-ThrottlingConstants.CleanupInactiveEntriesAfterMinutes);
        List<string> toRemove = ThrottleData
            .Where(kvp => kvp.Value.LastRequest < cutoff)
            .Select(kvp => kvp.Key)
            .Take(ThrottlingConstants.MaxCleanupBatchSize)
            .ToList();

        foreach (string key in toRemove)
        {
            ThrottleData.TryRemove(key, out _);
        }

        if (toRemove.Count > AppConstants.Arrays.InitialValue)
        {
            Log.Debug(ThrottlingConstants.Messages.CleanupEntries, toRemove.Count);
        }
    }
}
using Microsoft.Extensions.Caching.Distributed;
using Serilog;
using System.Collections.Concurrent;
using System.Net;
using System.Text.Json;
using Ecliptix.Core.Json;
using Ecliptix.Core.Middleware.Models;

namespace Ecliptix.Core.Middleware;

public class IpThrottlingMiddleware(RequestDelegate next, IDistributedCache cache)
{
    private static readonly ConcurrentDictionary<string, ThrottleInfo> ThrottleData = new();
    private static readonly TimeSpan CleanupInterval = TimeSpan.FromMinutes(5);
    private static DateTime _lastCleanup = DateTime.UtcNow;

    private const int MaxRequestsPerMinute = 60;
    private const int MaxFailuresBeforeBlock = 5;
    private const int BlockDurationMinutes = 15;

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

            TrackRequest(clientIp, success: context.Response.StatusCode < 400);
        }
        catch (Exception)
        {
            TrackRequest(clientIp, success: false);
            throw;
        }
    }

    private static string GetClientIpAddress(HttpContext context)
    {
        string? forwardedFor = context.Request.Headers["X-Forwarded-For"].FirstOrDefault();
        if (!string.IsNullOrEmpty(forwardedFor))
        {
            string[] ips = forwardedFor.Split(',', StringSplitOptions.RemoveEmptyEntries);
            if (ips.Length > 0)
            {
                string firstIp = ips[0].Trim();
                if (IPAddress.TryParse(firstIp, out _))
                    return firstIp;
            }
        }

        string? realIp = context.Request.Headers["X-Real-IP"].FirstOrDefault();
        if (!string.IsNullOrEmpty(realIp) && IPAddress.TryParse(realIp, out _))
            return realIp;

        return context.Connection.RemoteIpAddress?.ToString() ?? "unknown";
    }

    private async Task<bool> IsIpBlocked(string clientIp)
    {
        string key = $"blocked_ip:{clientIp}";
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

    private static bool CheckRateLimit(string clientIp)
    {
        ThrottleInfo throttleInfo = ThrottleData.GetOrAdd(clientIp, _ => new ThrottleInfo());

        lock (throttleInfo)
        {
            DateTime now = DateTime.UtcNow;

            if (now - throttleInfo.WindowStart >= TimeSpan.FromMinutes(1))
            {
                throttleInfo.RequestCount = 0;
                throttleInfo.WindowStart = now;
            }

            throttleInfo.RequestCount++;
            throttleInfo.LastRequest = now;

            return throttleInfo.RequestCount <= MaxRequestsPerMinute;
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

                if (throttleInfo.FailureCount >= MaxFailuresBeforeBlock)
                {
                    _ = Task.Run(async () => await BlockIp(clientIp, BlockDurationMinutes));
                }
            }
        }
        else
        {
            if (!ThrottleData.TryGetValue(clientIp, out ThrottleInfo? throttleInfo)) return;
            lock (throttleInfo)
            {
                throttleInfo.FailureCount = Math.Max(0, throttleInfo.FailureCount - 1);
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
            Reason = "Too many failed requests"
        };

        string key = $"blocked_ip:{clientIp}";
        string serializedData = JsonSerializer.Serialize(blockInfo, AppJsonSerializerContext.Default.BlockInfo);
        DistributedCacheEntryOptions options = new()
        {
            AbsoluteExpirationRelativeToNow = TimeSpan.FromMinutes(durationMinutes)
        };

        await cache.SetStringAsync(key, serializedData, options);

        Log.Warning("IP address {IpAddress} blocked for {Duration} minutes due to {Reason}",
            clientIp, durationMinutes, blockInfo.Reason);
    }

    private async Task HandleBlockedRequest(HttpContext context, string clientIp)
    {
        context.Response.StatusCode = StatusCodes.Status429TooManyRequests;
        context.Response.Headers["Retry-After"] = "900";

        Log.Warning("Blocked request from {IpAddress}", clientIp);

        await context.Response.WriteAsync("IP address temporarily blocked due to suspicious activity");
    }

    private static async Task HandleRateLimitExceeded(HttpContext context, string clientIp)
    {
        context.Response.StatusCode = StatusCodes.Status429TooManyRequests;
        context.Response.Headers["Retry-After"] = "60";

        Log.Information("Rate limit exceeded for {IpAddress}", clientIp);

        await context.Response.WriteAsync("Rate limit exceeded. Please try again later.");
    }

    private static void PerformCleanupIfNeeded()
    {
        DateTime now = DateTime.UtcNow;
        if (now - _lastCleanup < CleanupInterval)
            return;

        _lastCleanup = now;

        DateTime cutoff = now.AddMinutes(-30);
        List<string> toRemove = ThrottleData
            .Where(kvp => kvp.Value.LastRequest < cutoff)
            .Select(kvp => kvp.Key)
            .Take(1000)
            .ToList();

        foreach (string key in toRemove)
        {
            ThrottleData.TryRemove(key, out _);
        }

        if (toRemove.Count > 0)
        {
            Log.Debug("Cleaned up {Count} old throttle entries", toRemove.Count);
        }
    }
}
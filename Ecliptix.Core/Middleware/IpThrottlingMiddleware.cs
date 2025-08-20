using Microsoft.Extensions.Caching.Distributed;
using Serilog;
using System.Collections.Concurrent;
using System.Net;
using System.Text.Json;

namespace Ecliptix.Core.Middleware;

public class IpThrottlingMiddleware
{
    private readonly RequestDelegate _next;
    private readonly IDistributedCache _cache;
    private static readonly ConcurrentDictionary<string, ThrottleInfo> _throttleData = new();
    private static readonly TimeSpan CleanupInterval = TimeSpan.FromMinutes(5);
    private static DateTime _lastCleanup = DateTime.UtcNow;

    // Configuration
    private const int MaxRequestsPerMinute = 60;
    private const int MaxFailuresBeforeBlock = 5;
    private const int BlockDurationMinutes = 15;

    public IpThrottlingMiddleware(RequestDelegate next, IDistributedCache cache)
    {
        _next = next;
        _cache = cache;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        var clientIp = GetClientIpAddress(context);
        
        // Perform periodic cleanup
        PerformCleanupIfNeeded();

        // Check if IP is blocked
        if (await IsIpBlocked(clientIp))
        {
            await HandleBlockedRequest(context, clientIp);
            return;
        }

        // Check rate limiting
        if (!await CheckRateLimit(clientIp))
        {
            await HandleRateLimitExceeded(context, clientIp);
            return;
        }

        var originalStatusCode = context.Response.StatusCode;
        
        try
        {
            await _next(context);
            
            // Track successful requests
            await TrackRequest(clientIp, success: context.Response.StatusCode < 400);
        }
        catch (Exception)
        {
            // Track failed requests
            await TrackRequest(clientIp, success: false);
            throw;
        }
    }

    private static string GetClientIpAddress(HttpContext context)
    {
        // Check for forwarded IP headers first
        var forwardedFor = context.Request.Headers["X-Forwarded-For"].FirstOrDefault();
        if (!string.IsNullOrEmpty(forwardedFor))
        {
            var ips = forwardedFor.Split(',', StringSplitOptions.RemoveEmptyEntries);
            if (ips.Length > 0)
            {
                var firstIp = ips[0].Trim();
                if (IPAddress.TryParse(firstIp, out _))
                    return firstIp;
            }
        }

        var realIp = context.Request.Headers["X-Real-IP"].FirstOrDefault();
        if (!string.IsNullOrEmpty(realIp) && IPAddress.TryParse(realIp, out _))
            return realIp;

        return context.Connection.RemoteIpAddress?.ToString() ?? "unknown";
    }

    private async Task<bool> IsIpBlocked(string clientIp)
    {
        var key = $"blocked_ip:{clientIp}";
        var blockedData = await _cache.GetStringAsync(key);
        
        if (blockedData != null)
        {
            var blockInfo = JsonSerializer.Deserialize<BlockInfo>(blockedData);
            if (blockInfo?.ExpiresAt > DateTime.UtcNow)
            {
                return true;
            }
            else
            {
                // Block expired, remove it
                await _cache.RemoveAsync(key);
            }
        }

        return false;
    }

    private async Task<bool> CheckRateLimit(string clientIp)
    {
        var throttleInfo = _throttleData.GetOrAdd(clientIp, _ => new ThrottleInfo());
        
        lock (throttleInfo)
        {
            var now = DateTime.UtcNow;
            
            // Reset counter if window has passed
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

    private async Task TrackRequest(string clientIp, bool success)
    {
        if (!success)
        {
            var throttleInfo = _throttleData.GetOrAdd(clientIp, _ => new ThrottleInfo());
            
            lock (throttleInfo)
            {
                throttleInfo.FailureCount++;
                throttleInfo.LastFailure = DateTime.UtcNow;
                
                // Block IP if too many failures
                if (throttleInfo.FailureCount >= MaxFailuresBeforeBlock)
                {
                    _ = Task.Run(async () => await BlockIp(clientIp, BlockDurationMinutes));
                }
            }
        }
        else
        {
            // Reset failure count on successful request
            if (_throttleData.TryGetValue(clientIp, out var throttleInfo))
            {
                lock (throttleInfo)
                {
                    throttleInfo.FailureCount = Math.Max(0, throttleInfo.FailureCount - 1);
                }
            }
        }
    }

    private async Task BlockIp(string clientIp, int durationMinutes)
    {
        var blockInfo = new BlockInfo
        {
            IpAddress = clientIp,
            BlockedAt = DateTime.UtcNow,
            ExpiresAt = DateTime.UtcNow.AddMinutes(durationMinutes),
            Reason = "Too many failed requests"
        };

        var key = $"blocked_ip:{clientIp}";
        var serializedData = JsonSerializer.Serialize(blockInfo);
        var options = new DistributedCacheEntryOptions
        {
            AbsoluteExpirationRelativeToNow = TimeSpan.FromMinutes(durationMinutes)
        };

        await _cache.SetStringAsync(key, serializedData, options);
        
        Log.Warning("IP address {IpAddress} blocked for {Duration} minutes due to {Reason}", 
            clientIp, durationMinutes, blockInfo.Reason);
    }

    private async Task HandleBlockedRequest(HttpContext context, string clientIp)
    {
        context.Response.StatusCode = StatusCodes.Status429TooManyRequests;
        context.Response.Headers["Retry-After"] = "900"; // 15 minutes
        
        Log.Warning("Blocked request from {IpAddress}", clientIp);
        
        await context.Response.WriteAsync("IP address temporarily blocked due to suspicious activity");
    }

    private async Task HandleRateLimitExceeded(HttpContext context, string clientIp)
    {
        context.Response.StatusCode = StatusCodes.Status429TooManyRequests;
        context.Response.Headers["Retry-After"] = "60"; // 1 minute
        
        Log.Information("Rate limit exceeded for {IpAddress}", clientIp);
        
        await context.Response.WriteAsync("Rate limit exceeded. Please try again later.");
    }

    private static void PerformCleanupIfNeeded()
    {
        var now = DateTime.UtcNow;
        if (now - _lastCleanup < CleanupInterval)
            return;

        _lastCleanup = now;
        
        // Cleanup old throttle data
        var cutoff = now.AddMinutes(-30);
        var toRemove = _throttleData
            .Where(kvp => kvp.Value.LastRequest < cutoff)
            .Select(kvp => kvp.Key)
            .Take(1000)
            .ToList();

        foreach (var key in toRemove)
        {
            _throttleData.TryRemove(key, out _);
        }

        if (toRemove.Count > 0)
        {
            Log.Debug("Cleaned up {Count} old throttle entries", toRemove.Count);
        }
    }

    private class ThrottleInfo
    {
        public int RequestCount { get; set; }
        public int FailureCount { get; set; }
        public DateTime WindowStart { get; set; } = DateTime.UtcNow;
        public DateTime LastRequest { get; set; } = DateTime.UtcNow;
        public DateTime LastFailure { get; set; }
    }

    private class BlockInfo
    {
        public string IpAddress { get; set; } = string.Empty;
        public DateTime BlockedAt { get; set; }
        public DateTime ExpiresAt { get; set; }
        public string Reason { get; set; } = string.Empty;
    }
}
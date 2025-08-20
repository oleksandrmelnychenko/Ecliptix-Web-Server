using Grpc.Core;
using Grpc.Core.Interceptors;
using Microsoft.Extensions.Caching.Distributed;
using Serilog;
using System.Collections.Concurrent;

namespace Ecliptix.Core.Interceptors;

public class SecurityInterceptor(IDistributedCache cache) : Interceptor
{
    private readonly IDistributedCache _cache = cache;
    private static readonly ConcurrentDictionary<string, DateTime> LastRequestTimes = new();
    private static readonly TimeSpan MinTimeBetweenRequests = TimeSpan.FromMilliseconds(100);

    public override async Task<TResponse> UnaryServerHandler<TRequest, TResponse>(
        TRequest request,
        ServerCallContext context,
        UnaryServerMethod<TRequest, TResponse> continuation)
    {
        string clientIp = context.GetHttpContext().Connection.RemoteIpAddress?.ToString() ?? "unknown";
        string methodName = context.Method;

        try
        {
            if (!ValidateRequestTiming(clientIp))
            {
                Log.Warning("Request timing validation failed for {ClientIp} on {Method}", clientIp, methodName);
                throw new RpcException(new Status(StatusCode.ResourceExhausted, "Too many requests"));
            }

            if (context.RequestHeaders.Any(h => h.Key.Contains("connectid", StringComparison.OrdinalIgnoreCase)))
            {
                if (!await ValidateConnectId(context))
                {
                    Log.Warning("ConnectId validation failed for {ClientIp} on {Method}", clientIp, methodName);
                    throw new RpcException(new Status(StatusCode.InvalidArgument, "Invalid connection identifier"));
                }
            }

            LogSecurityEvent(context, "REQUEST_PROCESSED");

            TResponse response = await continuation(request, context);

            LogSecurityEvent(context, "REQUEST_COMPLETED");

            return response;
        }
        catch (RpcException)
        {
            LogSecurityEvent(context, "REQUEST_FAILED");
            throw;
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Unexpected error in security interceptor for {ClientIp} on {Method}", clientIp, methodName);
            LogSecurityEvent(context, "REQUEST_ERROR");
            throw new RpcException(new Status(StatusCode.Internal, "Internal server error"));
        }
    }

    private static bool ValidateRequestTiming(string clientIdentifier)
    {
        DateTime now = DateTime.UtcNow;

        if (LastRequestTimes.TryGetValue(clientIdentifier, out var lastTime))
        {
            if (now - lastTime < MinTimeBetweenRequests)
            {
                return false;
            }
        }

        LastRequestTimes.AddOrUpdate(clientIdentifier, now, (_, _) => now);

        if (LastRequestTimes.Count > 10000)
        {
            DateTime cutoff = now.AddMinutes(-5);
            List<string> toRemove = LastRequestTimes
                .Where(kvp => kvp.Value < cutoff)
                .Select(kvp => kvp.Key)
                .Take(1000)
                .ToList();

            foreach (string key in toRemove)
            {
                LastRequestTimes.TryRemove(key, out _);
            }
        }

        return true;
    }

    private static async Task<bool> ValidateConnectId(ServerCallContext context)
    {
        try
        {
            Metadata.Entry? connectIdHeader = context.RequestHeaders
                .FirstOrDefault(h => h.Key.Contains("connectid", StringComparison.OrdinalIgnoreCase));

            if (connectIdHeader == null)
                return true;

            string connectIdString = connectIdHeader.Value;

            if (!uint.TryParse(connectIdString, out var connectId))
            {
                Log.Warning("Invalid ConnectId format: {ConnectId}", connectIdString);
                return false;
            }

            if (connectId is 0 or > uint.MaxValue - 1000)
            {
                Log.Warning("ConnectId out of valid range: {ConnectId}", connectId);
                return false;
            }

            return true;
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Error validating ConnectId");
            return false;
        }
    }

    private static void LogSecurityEvent(ServerCallContext context, string eventType)
    {
        string clientIp = context.GetHttpContext().Connection.RemoteIpAddress?.ToString() ?? "unknown";
        string methodName = context.Method;
        string userAgent = context.GetHttpContext().Request.Headers.UserAgent.ToString();

        Log.Information("Security Event: {EventType} | Method: {Method} | Client: {ClientIp} | UserAgent: {UserAgent}",
            eventType, methodName, clientIp, userAgent);
    }
}
using System.Collections.Concurrent;
using Ecliptix.Core.Infrastructure.Grpc.Constants;
using Grpc.Core;
using Grpc.Core.Interceptors;
using Microsoft.Extensions.Caching.Distributed;
using Serilog;

namespace Ecliptix.Core.Infrastructure.Grpc.Interceptors;

public class SecurityInterceptor(IDistributedCache cache) : Interceptor
{
    private readonly IDistributedCache _cache = cache;
    private static readonly ConcurrentDictionary<string, DateTime> LastRequestTimes = new();
    private static readonly TimeSpan MinTimeBetweenRequests = TimeSpan.FromMilliseconds(InterceptorConstants.Thresholds.MinTimeBetweenRequestsMs);

    public override async Task<TResponse> UnaryServerHandler<TRequest, TResponse>(
        TRequest request,
        ServerCallContext context,
        UnaryServerMethod<TRequest, TResponse> continuation)
    {
        string clientIp = context.GetHttpContext().Connection.RemoteIpAddress?.ToString() ?? InterceptorConstants.Connections.Unknown;
        string methodName = context.Method;

        try
        {
            if (!ValidateRequestTiming(clientIp))
            {
                throw new RpcException(new Status(StatusCode.ResourceExhausted, InterceptorConstants.StatusMessages.TooManyRequests));
            }

            if (context.RequestHeaders.Any(h => h.Key.Contains(InterceptorConstants.Headers.ConnectIdKey, StringComparison.OrdinalIgnoreCase)))
            {
                if (!await ValidateConnectId(context))
                {
                    throw new RpcException(new Status(StatusCode.InvalidArgument, InterceptorConstants.StatusMessages.InvalidConnectionIdentifier));
                }
            }

            TResponse response = await continuation(request, context);

            return response;
        }
        catch (RpcException)
        {
            throw;
        }
        catch (Exception ex)
        {
            Log.Error(ex, InterceptorConstants.LogMessages.UnexpectedSecurityError, clientIp, methodName);
            throw new RpcException(new Status(StatusCode.Internal, InterceptorConstants.StatusMessages.InternalServerError));
        }
    }

    private static bool ValidateRequestTiming(string clientIdentifier)
    {
        DateTime now = DateTime.UtcNow;

        if (LastRequestTimes.TryGetValue(clientIdentifier, out DateTime lastTime))
        {
            if (now - lastTime < MinTimeBetweenRequests)
            {
                return false;
            }
        }

        LastRequestTimes.AddOrUpdate(clientIdentifier, now, (_, _) => now);

        if (LastRequestTimes.Count > InterceptorConstants.Limits.MaxLastRequestTimesCount)
        {
            DateTime cutoff = now.AddMinutes(-InterceptorConstants.Thresholds.CacheCleanupIntervalMinutes);
            List<string> toRemove = LastRequestTimes
                .Where(kvp => kvp.Value < cutoff)
                .Select(kvp => kvp.Key)
                .Take(InterceptorConstants.Limits.LargeCleanupBatchSize)
                .ToList();

            foreach (string key in toRemove)
            {
                LastRequestTimes.TryRemove(key, out _);
            }
        }

        return true;
    }

    private static Task<bool> ValidateConnectId(ServerCallContext context)
    {
        try
        {
            Metadata.Entry? connectIdHeader = context.RequestHeaders
                .FirstOrDefault(h => h.Key.Contains(InterceptorConstants.Headers.ConnectIdKey, StringComparison.OrdinalIgnoreCase));

            if (connectIdHeader == null)
                return Task.FromResult(true);

            string connectIdString = connectIdHeader.Value;

            if (!uint.TryParse(connectIdString, out uint connectId))
            {
                return Task.FromResult(false);
            }

            if (connectId < InterceptorConstants.Limits.MinConnectId || connectId > InterceptorConstants.Limits.MaxConnectId)
            {
                return Task.FromResult(false);
            }

            return Task.FromResult(true);
        }
        catch (Exception ex)
        {
            Log.Error(ex, InterceptorConstants.LogMessages.ErrorValidatingConnectId);
            return Task.FromResult(false);
        }
    }

}
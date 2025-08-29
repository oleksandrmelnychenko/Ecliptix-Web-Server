using Grpc.Core;
using Microsoft.Extensions.Primitives;
using Serilog;

namespace Ecliptix.Core.Middleware;

public class SecurityMiddleware(RequestDelegate next)
{
    private static readonly HashSet<string> AllowedContentTypes =
    [
        "application/grpc",
        "application/grpc+proto",
        "application/json"
    ];

    public async Task InvokeAsync(HttpContext context)
    {
        AddSecurityHeaders(context);

        if (context.Request.Path.StartsWithSegments("/grpc") ||
            context.Request.ContentType?.StartsWith("application/grpc") == true)
        {
            if (!ValidateContentType(context))
            {
                context.Response.StatusCode = StatusCodes.Status415UnsupportedMediaType;
                await context.Response.WriteAsync("Unsupported content type");
                return;
            }

            if (!ValidateHeaders(context))
            {
                context.Response.StatusCode = StatusCodes.Status400BadRequest;
                await context.Response.WriteAsync("Invalid headers");
                return;
            }
        }

        LogSecurityInfo(context);

        try
        {
            await next(context);
        }
        catch (RpcException ex) when (ex.StatusCode == StatusCode.ResourceExhausted)
        {
            Log.Warning("Resource exhaustion detected from {IpAddress}: {Message}",
                context.Connection.RemoteIpAddress?.ToString(), ex.Message);
            throw;
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Unhandled exception in security middleware from {IpAddress}",
                context.Connection.RemoteIpAddress?.ToString());
            throw;
        }
    }

    private static void AddSecurityHeaders(HttpContext context)
    {
        IHeaderDictionary headers = context.Response.Headers;

        headers["X-Content-Type-Options"] = "nosniff";
        headers["X-Frame-Options"] = "DENY";
        headers["X-XSS-Protection"] = "1; mode=block";
        headers["Referrer-Policy"] = "strict-origin-when-cross-origin";
        headers["X-Robots-Tag"] = "noindex, nofollow";

        headers.Remove("Server");
    }

    private static bool ValidateContentType(HttpContext context)
    {
        string? contentType = context.Request.ContentType;
        return string.IsNullOrEmpty(contentType) || AllowedContentTypes.Any(allowed =>
            contentType.StartsWith(allowed, StringComparison.OrdinalIgnoreCase));
    }

    private static bool ValidateHeaders(HttpContext context)
    {
        IHeaderDictionary headers = context.Request.Headers;

        foreach (KeyValuePair<string, StringValues> header in headers)
        {
            if (header.Value.Any(v => v != null && v.Length > 8192))
            {
                Log.Warning("Suspicious header detected - excessive length: {HeaderName}", header.Key);
                return false;
            }

            if (!ContainsSuspiciousContent(header.Key)) continue;
            Log.Warning("Suspicious header name detected: {HeaderName}", header.Key);
            return false;
        }

        return true;
    }

    private static bool ContainsSuspiciousContent(string value)
    {
        if (string.IsNullOrEmpty(value))
            return false;

        string lowerValue = value.ToLowerInvariant();
        return lowerValue.Contains("script") ||
               lowerValue.Contains("<") ||
               lowerValue.Contains(">") ||
               lowerValue.Contains("javascript") ||
               lowerValue.Contains("vbscript") ||
               lowerValue.Contains("onload") ||
               lowerValue.Contains("onerror");
    }

    private static void LogSecurityInfo(HttpContext context)
    {
        if (!Log.IsEnabled(Serilog.Events.LogEventLevel.Debug)) return;
        object info = new
        {
            IpAddress = context.Connection.RemoteIpAddress?.ToString(),
            UserAgent = context.Request.Headers.UserAgent.ToString(),
            Path = context.Request.Path.ToString(),
            Method = context.Request.Method,
            ContentType = context.Request.ContentType,
            ContentLength = context.Request.ContentLength,
            Timestamp = DateTimeOffset.UtcNow
        };

        Log.Debug("Security middleware processing request: {@RequestInfo}", info);
    }
}
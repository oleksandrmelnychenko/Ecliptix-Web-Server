using Grpc.Core;
using Serilog;
using System.Text.Json;

namespace Ecliptix.Core.Middleware;

public class SecurityMiddleware
{
    private readonly RequestDelegate _next;
    private readonly IConfiguration _configuration;
    private static readonly HashSet<string> AllowedContentTypes = new()
    {
        "application/grpc",
        "application/grpc+proto",
        "application/json"
    };

    public SecurityMiddleware(RequestDelegate next, IConfiguration configuration)
    {
        _next = next;
        _configuration = configuration;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        // Add security headers
        AddSecurityHeaders(context);

        // Validate content type for gRPC requests
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

        // Log security-relevant information
        LogSecurityInfo(context);

        try
        {
            await _next(context);
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
        var headers = context.Response.Headers;
        
        // Security headers
        headers["X-Content-Type-Options"] = "nosniff";
        headers["X-Frame-Options"] = "DENY";
        headers["X-XSS-Protection"] = "1; mode=block";
        headers["Referrer-Policy"] = "strict-origin-when-cross-origin";
        headers["X-Robots-Tag"] = "noindex, nofollow";
        
        // Remove server information
        headers.Remove("Server");
    }

    private static bool ValidateContentType(HttpContext context)
    {
        string? contentType = context.Request.ContentType;
        if (string.IsNullOrEmpty(contentType))
            return true; // Allow GET requests without content type

        return AllowedContentTypes.Any(allowed => contentType.StartsWith(allowed, StringComparison.OrdinalIgnoreCase));
    }

    private static bool ValidateHeaders(HttpContext context)
    {
        var headers = context.Request.Headers;

        // Check for suspicious header patterns
        foreach (var header in headers)
        {
            // Check for excessively long header values
            if (header.Value.Any(v => v != null && v.Length > 8192))
            {
                Log.Warning("Suspicious header detected - excessive length: {HeaderName}", header.Key);
                return false;
            }

            // Check for potentially malicious header names
            if (ContainsSuspiciousContent(header.Key))
            {
                Log.Warning("Suspicious header name detected: {HeaderName}", header.Key);
                return false;
            }
        }

        return true;
    }

    private static bool ContainsSuspiciousContent(string value)
    {
        if (string.IsNullOrEmpty(value))
            return false;

        // Check for common injection patterns
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
        if (Log.IsEnabled(Serilog.Events.LogEventLevel.Debug))
        {
            var info = new
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
}
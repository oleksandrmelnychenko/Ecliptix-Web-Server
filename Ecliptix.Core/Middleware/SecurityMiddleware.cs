using Grpc.Core;
using Microsoft.Extensions.Primitives;
using Serilog;
using Ecliptix.Core.Configuration;

namespace Ecliptix.Core.Middleware;

internal sealed class SecurityMiddleware(RequestDelegate next)
{
    private static readonly HashSet<string> AllowedContentTypes =
    [
        SecurityConstants.ContentTypes.ApplicationGrpc,
        SecurityConstants.ContentTypes.ApplicationGrpcProto,
        SecurityConstants.ContentTypes.ApplicationJson
    ];

    public async Task InvokeAsync(HttpContext context)
    {
        AddSecurityHeaders(context);

        if (context.Request.Path.StartsWithSegments(SecurityConstants.Paths.Grpc) ||
            context.Request.ContentType?.StartsWith(SecurityConstants.ContentTypes.ApplicationGrpc) == true)
        {
            if (!ValidateContentType(context))
            {
                context.Response.StatusCode = StatusCodes.Status415UnsupportedMediaType;
                await context.Response.WriteAsync(SecurityConstants.StatusMessages.UnsupportedContentType);
                return;
            }

            if (!ValidateHeaders(context))
            {
                context.Response.StatusCode = StatusCodes.Status400BadRequest;
                await context.Response.WriteAsync(SecurityConstants.StatusMessages.InvalidHeaders);
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
            throw;
        }
    }

    private static void AddSecurityHeaders(HttpContext context)
    {
        IHeaderDictionary headers = context.Response.Headers;

        headers["X-Content-Type-Options"] = SecurityConstants.SecurityValues.NoSniff;
        headers["X-Frame-Options"] = SecurityConstants.SecurityValues.DenyFrameOptions;
        headers["X-XSS-Protection"] = SecurityConstants.SecurityValues.XssProtectionValue;
        headers["Referrer-Policy"] = SecurityConstants.SecurityValues.StrictOriginWhenCrossOrigin;
        headers["X-Robots-Tag"] = SecurityConstants.SecurityValues.NoIndexNoFollow;

        headers.Remove(SecurityConstants.SecurityValues.ServerHeaderName);
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
            if (header.Value.Any(v => v != null && v.Length > SecurityConstants.Limits.MaxHeaderLengthBytes))
            {

                return false;
            }

            if (!ContainsSuspiciousContent(header.Key)) continue;

            return false;
        }

        return true;
    }

    private static bool ContainsSuspiciousContent(string value)
    {
        if (string.IsNullOrEmpty(value))
            return false;

        string lowerValue = value.ToLowerInvariant();
        return lowerValue.Contains(SecurityConstants.SuspiciousContent.Script) ||
               lowerValue.Contains(SecurityConstants.SuspiciousContent.LessThan) ||
               lowerValue.Contains(SecurityConstants.SuspiciousContent.GreaterThan) ||
               lowerValue.Contains(SecurityConstants.SuspiciousContent.Javascript) ||
               lowerValue.Contains(SecurityConstants.SuspiciousContent.VbScript) ||
               lowerValue.Contains(SecurityConstants.SuspiciousContent.OnLoad) ||
               lowerValue.Contains(SecurityConstants.SuspiciousContent.OnError);
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

    }
}
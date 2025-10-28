using System.Globalization;
using System.Security.Authentication;
using Ecliptix.Core.Configuration;
using Ecliptix.Core.Infrastructure.Grpc.Constants;
using Ecliptix.Core.Infrastructure.Grpc.Utilities.Utilities;
using Ecliptix.Domain;
using Ecliptix.Utilities;
using Grpc.Core;
using Grpc.Core.Interceptors;
using Serilog;

namespace Ecliptix.Core.Infrastructure.Grpc.Interceptors;

public sealed class FailureHandlingInterceptor(ILocalizationProvider localizationProvider) : Interceptor
{
    public override async Task<TResponse> UnaryServerHandler<TRequest, TResponse>(
        TRequest request,
        ServerCallContext context,
        UnaryServerMethod<TRequest, TResponse> continuation)
    {
        try
        {
            return await continuation(request, context);
        }
        catch (RpcException rpcEx) when (HasErrorMetadata(rpcEx))
        {
            throw;
        }
        catch (Exception ex)
        {
            throw HandleException(ex, context);
        }
    }

    public override async Task ServerStreamingServerHandler<TRequest, TResponse>(
        TRequest request,
        IServerStreamWriter<TResponse> responseStream,
        ServerCallContext context,
        ServerStreamingServerMethod<TRequest, TResponse> continuation)
    {
        try
        {
            SafeStreamWriter<TResponse> wrappedStream = new(responseStream, context, this);
            await continuation(request, wrappedStream, context);
        }
        catch (RpcException rpcEx) when (HasErrorMetadata(rpcEx))
        {
            throw;
        }
        catch (Exception ex)
        {
            throw HandleException(ex, context);
        }
    }

    private RpcException HandleException(Exception exception, ServerCallContext context)
    {
        if (exception is RpcException rpcException && HasErrorMetadata(rpcException))
        {
            return rpcException;
        }

        GrpcErrorDescriptor descriptor = ResolveDescriptor(exception);
        string locale = ResolveLocale(context);
        string correlationId = ResolveCorrelationId(context);

        (string message, GrpcErrorDescriptor effectiveDescriptor) = LocalizeMessage(descriptor, locale);

        Metadata trailers = CreateTrailers(effectiveDescriptor, locale, correlationId);
        LogException(exception, context, effectiveDescriptor, correlationId);

        Status status = effectiveDescriptor.CreateStatus(message);
        return new RpcException(status, trailers);
    }

    private static bool HasErrorMetadata(RpcException rpcException) =>
        rpcException.Trailers?.GetValue(ErrorMetadataConstants.ErrorCode) is not null;

    private static GrpcErrorDescriptor ResolveDescriptor(Exception exception) =>
        exception switch
        {
            GrpcFailureException failure => failure.Descriptor,
            RpcException rpcException => MapStatusCode(rpcException.Status.StatusCode),
            OperationCanceledException => new GrpcErrorDescriptor(
                ErrorCode.Cancelled,
                StatusCode.Cancelled,
                ErrorI18NKeys.Cancelled,
                Retryable: true),
            TimeoutException => new GrpcErrorDescriptor(
                ErrorCode.DeadlineExceeded,
                StatusCode.DeadlineExceeded,
                ErrorI18NKeys.DeadlineExceeded,
                Retryable: true),
            AuthenticationException => new GrpcErrorDescriptor(
                ErrorCode.Unauthenticated,
                StatusCode.Unauthenticated,
                ErrorI18NKeys.Unauthenticated),
            _ => new GrpcErrorDescriptor(
                ErrorCode.InternalError,
                StatusCode.Internal,
                ErrorI18NKeys.Internal)
        };

    private static GrpcErrorDescriptor MapStatusCode(StatusCode statusCode) =>
        statusCode switch
        {
            StatusCode.InvalidArgument or StatusCode.OutOfRange => new GrpcErrorDescriptor(
                ErrorCode.ValidationFailed,
                StatusCode.InvalidArgument,
                ErrorI18NKeys.Validation),
            StatusCode.NotFound => new GrpcErrorDescriptor(
                ErrorCode.NotFound,
                StatusCode.NotFound,
                ErrorI18NKeys.NotFound),
            StatusCode.AlreadyExists => new GrpcErrorDescriptor(
                ErrorCode.AlreadyExists,
                StatusCode.AlreadyExists,
                ErrorI18NKeys.AlreadyExists),
            StatusCode.Unauthenticated => new GrpcErrorDescriptor(
                ErrorCode.Unauthenticated,
                StatusCode.Unauthenticated,
                ErrorI18NKeys.Unauthenticated),
            StatusCode.PermissionDenied => new GrpcErrorDescriptor(
                ErrorCode.PermissionDenied,
                StatusCode.PermissionDenied,
                ErrorI18NKeys.PermissionDenied),
            StatusCode.FailedPrecondition => new GrpcErrorDescriptor(
                ErrorCode.PreconditionFailed,
                StatusCode.FailedPrecondition,
                ErrorI18NKeys.PreconditionFailed),
            StatusCode.Aborted => new GrpcErrorDescriptor(
                ErrorCode.Conflict,
                StatusCode.Aborted,
                ErrorI18NKeys.Conflict),
            StatusCode.ResourceExhausted => new GrpcErrorDescriptor(
                ErrorCode.ResourceExhausted,
                StatusCode.ResourceExhausted,
                ErrorI18NKeys.ResourceExhausted),
            StatusCode.Unavailable => new GrpcErrorDescriptor(
                ErrorCode.ServiceUnavailable,
                StatusCode.Unavailable,
                ErrorI18NKeys.ServiceUnavailable,
                Retryable: true),
            StatusCode.DeadlineExceeded => new GrpcErrorDescriptor(
                ErrorCode.DeadlineExceeded,
                StatusCode.DeadlineExceeded,
                ErrorI18NKeys.DeadlineExceeded,
                Retryable: true),
            StatusCode.Cancelled => new GrpcErrorDescriptor(
                ErrorCode.Cancelled,
                StatusCode.Cancelled,
                ErrorI18NKeys.Cancelled,
                Retryable: true),
            _ => new GrpcErrorDescriptor(
                ErrorCode.InternalError,
                StatusCode.Internal,
                ErrorI18NKeys.Internal)
        };

    private (string Message, GrpcErrorDescriptor Descriptor) LocalizeMessage(
        GrpcErrorDescriptor descriptor,
        string locale)
    {
        string localized = localizationProvider.Localize(descriptor.I18nKey, locale);
        if (!string.Equals(localized, descriptor.I18nKey, StringComparison.Ordinal))
        {
            return (localized, descriptor);
        }

        string fallbackKey = GetFallbackKey(descriptor.ErrorCode);
        if (!string.Equals(fallbackKey, descriptor.I18nKey, StringComparison.Ordinal))
        {
            string fallbackMessage = localizationProvider.Localize(fallbackKey, locale);
            if (!string.Equals(fallbackMessage, fallbackKey, StringComparison.Ordinal))
            {
                return (fallbackMessage, descriptor with { I18nKey = fallbackKey });
            }
        }

        string safeMessage = localizationProvider.Localize(ErrorI18NKeys.Internal, locale);
        return (safeMessage, descriptor with { I18nKey = ErrorI18NKeys.Internal });
    }

    private static string GetFallbackKey(ErrorCode errorCode) =>
        errorCode switch
        {
            ErrorCode.ValidationFailed => ErrorI18NKeys.Validation,
            ErrorCode.MaxAttemptsReached => ErrorI18NKeys.MaxAttempts,
            ErrorCode.InvalidMobileNumber => ErrorI18NKeys.InvalidMobile,
            ErrorCode.OtpExpired => ErrorI18NKeys.OtpExpired,
            ErrorCode.NotFound => ErrorI18NKeys.NotFound,
            ErrorCode.AlreadyExists => ErrorI18NKeys.AlreadyExists,
            ErrorCode.Unauthenticated => ErrorI18NKeys.Unauthenticated,
            ErrorCode.PermissionDenied => ErrorI18NKeys.PermissionDenied,
            ErrorCode.PreconditionFailed => ErrorI18NKeys.PreconditionFailed,
            ErrorCode.Conflict => ErrorI18NKeys.Conflict,
            ErrorCode.ResourceExhausted => ErrorI18NKeys.ResourceExhausted,
            ErrorCode.ServiceUnavailable => ErrorI18NKeys.ServiceUnavailable,
            ErrorCode.DependencyUnavailable => ErrorI18NKeys.DependencyUnavailable,
            ErrorCode.DeadlineExceeded => ErrorI18NKeys.DeadlineExceeded,
            ErrorCode.Cancelled => ErrorI18NKeys.Cancelled,
            ErrorCode.InternalError => ErrorI18NKeys.Internal,
            ErrorCode.DatabaseUnavailable => ErrorI18NKeys.DatabaseUnavailable,
            _ => ErrorI18NKeys.Internal
        };

    private static string ResolveLocale(ServerCallContext context)
    {
        try
        {
            return GrpcMetadataHandler.GetRequestedLocale(context.RequestHeaders);
        }
        catch
        {
            return CultureInfo.GetCultureInfo("en-US").Name;
        }
    }

    private static string ResolveCorrelationId(ServerCallContext context)
    {
        string? requestId = context.RequestHeaders.GetValue(MetadataConstants.Keys.RequestId);
        if (!string.IsNullOrEmpty(requestId))
        {
            return requestId;
        }

        if (context.UserState.TryGetValue(GrpcMetadataHandler.UniqueConnectId, out object? value) &&
            value is uint connectId)
        {
            return connectId.ToString(CultureInfo.InvariantCulture);
        }

        string? httpCorrelation = context.GetHttpContext()?.TraceIdentifier;
        return string.IsNullOrEmpty(httpCorrelation) ? Guid.NewGuid().ToString("N") : httpCorrelation;
    }

    private static Metadata CreateTrailers(
        GrpcErrorDescriptor descriptor,
        string locale,
        string correlationId)
    {
        Metadata metadata = new()
        {
            { ErrorMetadataConstants.ErrorCode, descriptor.ErrorCode.ToString() },
            { ErrorMetadataConstants.I18nKey, descriptor.I18nKey },
            { ErrorMetadataConstants.Locale, locale },
            { ErrorMetadataConstants.CorrelationId, correlationId }
        };

        if (descriptor.Retryable)
        {
            metadata.Add(ErrorMetadataConstants.Retryable, bool.TrueString.ToLowerInvariant());
        }

        if (descriptor.RetryAfterMilliseconds.HasValue)
        {
            metadata.Add(
                ErrorMetadataConstants.RetryAfterMilliseconds,
                descriptor.RetryAfterMilliseconds.Value.ToString(CultureInfo.InvariantCulture));
        }

        return metadata;
    }

    private static void LogException(
        Exception exception,
        ServerCallContext context,
        GrpcErrorDescriptor descriptor,
        string correlationId)
    {
        Serilog.ILogger logger = Log.ForContext("CorrelationId", correlationId)
            .ForContext("GrpcMethod", context.Method)
            .ForContext("ErrorCode", descriptor.ErrorCode)
            .ForContext("StatusCode", descriptor.StatusCode);

        if (exception is GrpcFailureException { StructuredLogPayload: not null } failure)
        {
            logger = logger.ForContext("Details", failure.StructuredLogPayload, true);
        }

        if (descriptor.StatusCode == StatusCode.Internal)
        {
            logger.Error(exception, InterceptorConstants.LogMessages.GrpcUnhandledException, context.Method);
        }
        else
        {
            logger.Warning(exception, InterceptorConstants.LogMessages.GrpcUnhandledException, context.Method);
        }
    }

    private class SafeStreamWriter<TResponse>(
        IServerStreamWriter<TResponse> innerWriter,
        ServerCallContext context,
        FailureHandlingInterceptor interceptor)
        : IServerStreamWriter<TResponse>
    {
        public WriteOptions? WriteOptions
        {
            get => innerWriter.WriteOptions;
            set => innerWriter.WriteOptions = value;
        }

        public async Task WriteAsync(TResponse message)
        {
            try
            {
                await innerWriter.WriteAsync(message);
            }
            catch (RpcException rpcEx) when (HasErrorMetadata(rpcEx))
            {
                throw;
            }
            catch (Exception ex)
            {
                throw interceptor.HandleException(ex, context);
            }
        }
    }
}

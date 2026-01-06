using Grpc.Core;

namespace Ecliptix.SharedKernel;

public interface IFailureBase
{
    object ToStructuredLog();
    Status ToGrpcStatus();
    GrpcErrorDescriptor ToGrpcDescriptor();
    ClientErrorInfo ToClientError();
    bool IsUserFacing { get; }
    bool Retryable { get; }
    ErrorSurface Surface { get; }
    string PublicErrorCode { get; }
    string? UserMessageKey { get; }
    string? UserMessageFallback { get; }
    string? TechnicalDetails { get; }
}

public abstract record FailureBase(string Message, Exception? InnerException = null) : IFailureBase
{
    protected DateTime Timestamp { get; } = DateTime.UtcNow;

    public virtual bool IsUserFacing => false;
    public virtual bool Retryable => false;
    public virtual ErrorSurface Surface => ErrorSurface.System;
    public virtual string PublicErrorCode => ErrorCode.InternalError.ToString();
    public virtual string? UserMessageKey => null;
    public virtual string? UserMessageFallback => null;
    public virtual string? TechnicalDetails => Message;

    public abstract object ToStructuredLog();

    public virtual Status ToGrpcStatus()
    {
        ClientErrorInfo clientError = ToClientError();
        GrpcErrorDescriptor descriptor = ToGrpcDescriptor();
        return descriptor.CreateStatus(clientError.MessageKey);
    }

    public abstract GrpcErrorDescriptor ToGrpcDescriptor();

    public virtual ClientErrorInfo ToClientError()
    {
        GrpcErrorDescriptor descriptor = ToGrpcDescriptor();
        string messageKey = ResolveUserMessageKey(descriptor);

        return new ClientErrorInfo(
            descriptor.ErrorCode,
            messageKey,
            Retryable || descriptor.Retryable,
            Surface,
            PublicErrorCode,
            UserMessageFallback);
    }

    protected virtual string ResolveUserMessageKey(GrpcErrorDescriptor descriptor)
    {
        if (Surface == ErrorSurface.System && !IsUserFacing)
        {
            return string.IsNullOrWhiteSpace(UserMessageKey)
                ? ErrorI18NKeys.Internal
                : UserMessageKey!;
        }

        if (!string.IsNullOrWhiteSpace(UserMessageKey))
        {
            return UserMessageKey!;
        }

        return string.IsNullOrWhiteSpace(descriptor.I18nKey)
            ? ErrorI18NKeys.Internal
            : descriptor.I18nKey;
    }
}

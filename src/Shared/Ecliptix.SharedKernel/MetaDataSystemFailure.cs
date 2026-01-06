using Grpc.Core;

namespace Ecliptix.SharedKernel;

public sealed record MetaDataSystemFailure(
    MetaDataSystemFailureType FailureType,
    string Message,
    Exception? InnerException = null)
    : FailureBase(Message, InnerException)
{
    public override bool IsUserFacing => FailureType switch
    {
        MetaDataSystemFailureType.RequiredComponentNotFound => true,
        _ => false
    };

    public override bool Retryable => false;

    public override ErrorSurface Surface => ErrorSurface.System;

    public override string PublicErrorCode => FailureType switch
    {
        MetaDataSystemFailureType.RequiredComponentNotFound => "metadata.component_not_found",
        _ => "metadata.internal"
    };

    public override string? UserMessageKey => FailureType switch
    {
        MetaDataSystemFailureType.RequiredComponentNotFound => ErrorI18NKeys.PreconditionFailed,
        _ => ErrorI18NKeys.Internal
    };
    public override object ToStructuredLog()
    {
        return new
        {
            ProtocolFailureType = FailureType.ToString(),
            Message,
            InnerException,
            Timestamp,
            IsUserFacing,
            Retryable,
            Surface = Surface.ToString(),
            PublicErrorCode
        };
    }

    public override GrpcErrorDescriptor ToGrpcDescriptor()
    {
        return FailureType switch
        {
            MetaDataSystemFailureType.RequiredComponentNotFound => new GrpcErrorDescriptor(
                ErrorCode.PreconditionFailed,
                StatusCode.FailedPrecondition,
                UserMessageKey ?? ErrorI18NKeys.PreconditionFailed),
            _ => new GrpcErrorDescriptor(
                ErrorCode.InternalError,
                StatusCode.Internal,
                UserMessageKey ?? ErrorI18NKeys.Internal)
        };
    }

    public static MetaDataSystemFailure ComponentNotFound(string details)
    {
        return new MetaDataSystemFailure(MetaDataSystemFailureType.RequiredComponentNotFound, details);
    }
}

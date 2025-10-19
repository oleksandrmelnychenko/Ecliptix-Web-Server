using Grpc.Core;

namespace Ecliptix.Utilities;

public sealed record MetaDataSystemFailure(
    MetaDataSystemFailureType FailureType,
    string Message,
    Exception? InnerException = null)
    : FailureBase(Message, InnerException)
{
    public override object ToStructuredLog()
    {
        return new
        {
            ProtocolFailureType = FailureType.ToString(),
            Message,
            InnerException,
            Timestamp
        };
    }

    public override GrpcErrorDescriptor ToGrpcDescriptor()
    {
        return FailureType switch
        {
            MetaDataSystemFailureType.RequiredComponentNotFound => new GrpcErrorDescriptor(
                ErrorCode.PreconditionFailed,
                StatusCode.FailedPrecondition,
                ErrorI18nKeys.PreconditionFailed),
            _ => new GrpcErrorDescriptor(
                ErrorCode.InternalError,
                StatusCode.Internal,
                ErrorI18nKeys.Internal)
        };
    }

    public static MetaDataSystemFailure ComponentNotFound(string details)
    {
        return new MetaDataSystemFailure(MetaDataSystemFailureType.RequiredComponentNotFound, details);
    }
}

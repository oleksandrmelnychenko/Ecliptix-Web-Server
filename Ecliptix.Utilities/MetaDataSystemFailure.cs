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

    public override Status ToGrpcStatus()
    {
        StatusCode statusCode = FailureType switch
        {
            MetaDataSystemFailureType.RequiredComponentNotFound => StatusCode.NotFound,
            _ => StatusCode.Internal
        };

        return new Status(statusCode, Message);
    }

    public static MetaDataSystemFailure ComponentNotFound(string details)
    {
        return new MetaDataSystemFailure(MetaDataSystemFailureType.RequiredComponentNotFound, details);
    }
}
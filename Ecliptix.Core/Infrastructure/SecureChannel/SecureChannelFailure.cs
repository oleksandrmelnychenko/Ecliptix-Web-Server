using Ecliptix.Security.Certificate.Pinning.Failures;
using Ecliptix.Utilities;
using Grpc.Core;

namespace Ecliptix.Core.Infrastructure.SecureChannel;

public sealed record SecureChannelFailure(
    SecureChannelFailureType FailureType,
    string Message,
    Exception? InnerException = null)
    : FailureBase(Message, InnerException)
{

    public static SecureChannelFailure CryptographicError(string message)
        => new(SecureChannelFailureType.CryptographicError, message);

    public static SecureChannelFailure ProtocolError(string message)
        => new(SecureChannelFailureType.ProtocolError, message);

    public static SecureChannelFailure InvalidPayload(string message)
        => new(SecureChannelFailureType.InvalidPayload, message);

    public static SecureChannelFailure ActorCommunicationError(string message)
        => new(SecureChannelFailureType.ActorCommunicationError, message);

    public static SecureChannelFailure FromCertificateFailure(CertificatePinningFailure failure)
        => new(SecureChannelFailureType.CryptographicError, failure.Message);

    public static SecureChannelFailure SigningFailed(string message)
        => new(SecureChannelFailureType.CryptographicError, message);

    public override Status ToGrpcStatus()
    {
        StatusCode statusCode = FailureType switch
        {
            SecureChannelFailureType.InvalidPayload => StatusCode.InvalidArgument,
            SecureChannelFailureType.CryptographicError => StatusCode.InvalidArgument,
            SecureChannelFailureType.ProtocolError => StatusCode.Internal,
            SecureChannelFailureType.ActorCommunicationError => StatusCode.Internal,
            _ => StatusCode.Internal
        };

        return new Status(statusCode, Message);
    }

    public override object ToStructuredLog()
    {
        return new
        {
            FailureType = FailureType.ToString(),
            Message,
            InnerException,
            Timestamp
        };
    }

    public RpcException ToRpcException()
    {
        return new RpcException(ToGrpcStatus());
    }
}

public enum SecureChannelFailureType
{
    InvalidPayload,
    CryptographicError,
    ProtocolError,
    ActorCommunicationError
}
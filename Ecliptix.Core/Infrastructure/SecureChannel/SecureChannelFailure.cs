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

    public override GrpcErrorDescriptor ToGrpcDescriptor() =>
        FailureType switch
        {
            SecureChannelFailureType.InvalidPayload => new GrpcErrorDescriptor(
                ErrorCode.ValidationFailed,
                StatusCode.InvalidArgument,
                ErrorI18NKeys.Validation),
            SecureChannelFailureType.CryptographicError => new GrpcErrorDescriptor(
                ErrorCode.DependencyUnavailable,
                StatusCode.Unavailable,
                ErrorI18NKeys.DependencyUnavailable,
                Retryable: true),
            SecureChannelFailureType.ActorCommunicationError => new GrpcErrorDescriptor(
                ErrorCode.ServiceUnavailable,
                StatusCode.Unavailable,
                ErrorI18NKeys.ServiceUnavailable,
                Retryable: true),
            _ => new GrpcErrorDescriptor(
                ErrorCode.InternalError,
                StatusCode.Internal,
                ErrorI18NKeys.Internal)
        };

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
}

public enum SecureChannelFailureType
{
    InvalidPayload,
    CryptographicError,
    ProtocolError,
    ActorCommunicationError
}

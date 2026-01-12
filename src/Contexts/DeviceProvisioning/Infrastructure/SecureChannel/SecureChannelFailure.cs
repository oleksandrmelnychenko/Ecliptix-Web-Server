using Ecliptix.Security.Certificate.Pinning.Failures;
using Grpc.Core;
using Ecliptix.SharedKernel;

namespace Ecliptix.DeviceProvisioning.Infrastructure.SecureChannel;

public sealed record SecureChannelFailure(
    SecureChannelFailureType FailureType,
    string Message,
    Exception? InnerException = null)
    : FailureBase(Message, InnerException)
{
    public override bool IsUserFacing => FailureType switch
    {
        SecureChannelFailureType.InvalidPayload => true,
        _ => false
    };

    public override bool Retryable => FailureType switch
    {
        SecureChannelFailureType.CryptographicError or SecureChannelFailureType.ActorCommunicationError => true,
        _ => false
    };

    public override ErrorSurface Surface => ErrorSurface.System;

    public override string PublicErrorCode => FailureType switch
    {
        SecureChannelFailureType.InvalidPayload => "secure_channel.invalid_payload",
        SecureChannelFailureType.CryptographicError => "secure_channel.crypto_error",
        SecureChannelFailureType.ActorCommunicationError => "secure_channel.actor_error",
        _ => "secure_channel.internal"
    };

    public override string? UserMessageKey => FailureType switch
    {
        SecureChannelFailureType.InvalidPayload => SecureChannelMessageKeys.InvalidPayload,
        SecureChannelFailureType.CryptographicError => SecureChannelMessageKeys.CryptoError,
        SecureChannelFailureType.ActorCommunicationError => SecureChannelMessageKeys.ActorError,
        SecureChannelFailureType.ProtocolError => SecureChannelMessageKeys.ProtocolError,
        _ => ErrorI18NKeys.Internal
    };

    public static SecureChannelFailure ProtocolError(string details)
        => new(SecureChannelFailureType.ProtocolError,
            $"{SecureChannelMessageKeys.ProtocolError}: {details}");

    public static SecureChannelFailure InvalidPayload(string details)
        => new(SecureChannelFailureType.InvalidPayload,
            $"{SecureChannelMessageKeys.InvalidPayload}: {details}");

    public static SecureChannelFailure ActorCommunicationError(string details)
        => new(SecureChannelFailureType.ActorCommunicationError,
            $"{SecureChannelMessageKeys.ActorError}: {details}");

    public static SecureChannelFailure FromCertificateFailure(CertificatePinningFailure failure)
        => new(SecureChannelFailureType.CryptographicError,
            $"{SecureChannelMessageKeys.CryptoError}: {failure.Message}");

    public override GrpcErrorDescriptor ToGrpcDescriptor() =>
        FailureType switch
        {
            SecureChannelFailureType.InvalidPayload => new GrpcErrorDescriptor(
                ErrorCode.ValidationFailed,
                StatusCode.InvalidArgument,
                UserMessageKey ?? ErrorI18NKeys.Validation),
            SecureChannelFailureType.CryptographicError => new GrpcErrorDescriptor(
                ErrorCode.DependencyUnavailable,
                StatusCode.Unavailable,
                UserMessageKey ?? ErrorI18NKeys.DependencyUnavailable,
                Retryable: true),
            SecureChannelFailureType.ActorCommunicationError => new GrpcErrorDescriptor(
                ErrorCode.ServiceUnavailable,
                StatusCode.Unavailable,
                UserMessageKey ?? ErrorI18NKeys.ServiceUnavailable,
                Retryable: true),
            _ => new GrpcErrorDescriptor(
                ErrorCode.InternalError,
                StatusCode.Internal,
                UserMessageKey ?? ErrorI18NKeys.Internal)
        };

    public override object ToStructuredLog()
    {
        return new
        {
            FailureType = FailureType.ToString(),
            Message,
            InnerException,
            Timestamp,
            IsUserFacing,
            Retryable,
            Surface = Surface.ToString(),
            PublicErrorCode
        };
    }
}

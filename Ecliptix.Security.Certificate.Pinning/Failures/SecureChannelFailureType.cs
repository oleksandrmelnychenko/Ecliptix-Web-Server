namespace Ecliptix.Security.Certificate.Pinning.Failures;

public enum SecureChannelFailureType
{
    InvalidPayload,
    CryptographicError,
    ProtocolError,
    ActorCommunicationError
}

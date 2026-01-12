namespace Ecliptix.DeviceProvisioning.Infrastructure.SecureChannel;

public enum SecureChannelFailureType
{
    InvalidPayload,
    CryptographicError,
    ProtocolError,
    ActorCommunicationError
}

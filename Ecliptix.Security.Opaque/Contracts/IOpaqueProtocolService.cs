using Ecliptix.Utilities;
using Ecliptix.Protobuf.Membership;
using Ecliptix.Security.Opaque.Models;

namespace Ecliptix.Security.Opaque.Contracts;

public interface IOpaqueProtocolService
{
    (byte[] Response, byte[] MaskingKey) ProcessOprfRequest(byte[] oprfRequest);

    (byte[] Response, byte[] MaskingKey, byte[] SessionKey) ProcessOprfRequestWithSessionKey(byte[] oprfRequest);

    Result<(OpaqueSignInInitResponse Response, byte[] ServerMac), OpaqueFailure> InitiateSignIn(
        OpaqueSignInInitRequest request, MembershipOpaqueQueryRecord queryRecord);

    Result<(SodiumSecureMemoryHandle SessionKeyHandle, OpaqueSignInFinalizeResponse Response), OpaqueFailure> CompleteSignIn(
        OpaqueSignInFinalizeRequest request,
        byte[] serverMac);

    Result<byte[], OpaqueFailure> CompleteRegistrationWithSessionKey(byte[] peerRegistrationRecord);
}
using Ecliptix.Utilities;
using Ecliptix.Protobuf.Membership;
using Ecliptix.Security.Opaque.Models;

namespace Ecliptix.Security.Opaque.Contracts;

public interface IOpaqueProtocolService
{
    (byte[] Response, byte[] MaskingKey) ProcessOprfRequest(byte[] oprfRequest);

    Result<(OpaqueSignInInitResponse Response, byte[] ServerMac), OpaqueFailure> InitiateSignIn(
        OpaqueSignInInitRequest request, MembershipOpaqueQueryRecord queryRecord);

    Result<OpaqueSignInFinalizeResponse, OpaqueFailure> CompleteSignIn(OpaqueSignInFinalizeRequest request,
        byte[]? serverMac = null);

    Result<byte[], OpaqueFailure> CompleteRegistrationWithSessionKey(byte[] peerRegistrationRecord);

    Result<AuthContextTokenResponse, OpaqueFailure> GenerateAuthenticationContext(Guid membershipId,
        Guid mobileNumberId);
}
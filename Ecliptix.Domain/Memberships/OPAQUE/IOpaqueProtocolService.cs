using Ecliptix.Domain.Utilities;
using Ecliptix.Protobuf.Membership;

namespace Ecliptix.Domain.Memberships.OPAQUE;

public interface IOpaqueProtocolService
{
    byte[] ProcessOprfRequest(byte[] oprfRequest);
    byte[] ProcessOprfRequest(ReadOnlySpan<byte> oprfRequest);

    (byte[] Response, byte[] MaskingKey) ProcessOprfRequestWithMaskingKey(byte[] oprfRequest);
    (byte[] Response, byte[] MaskingKey) ProcessOprfRequestWithMaskingKey(ReadOnlySpan<byte> oprfRequest);

    Result<OpaqueSignInInitResponse, OpaqueFailure> InitiateSignIn(OpaqueSignInInitRequest request, MembershipOpaqueQueryRecord queryRecord);
    Result<(OpaqueSignInInitResponse Response, byte[] ServerMac), OpaqueFailure> InitiateSignInWithServerMac(OpaqueSignInInitRequest request, MembershipOpaqueQueryRecord queryRecord);

    Result<OpaqueSignInFinalizeResponse, OpaqueFailure> FinalizeSignIn(OpaqueSignInFinalizeRequest request);
    Result<OpaqueSignInFinalizeResponse, OpaqueFailure> FinalizeSignIn(OpaqueSignInFinalizeRequest request, byte[] serverMac);

    Result<Unit, OpaqueFailure> CompleteRegistration(
        byte[] peerRegistrationRecord);

    Result<byte[], OpaqueFailure> CompleteRegistrationWithSessionKey(byte[] peerRegistrationRecord);

    Result<AuthContextTokenResponse, OpaqueFailure> GenerateAuthenticationContext(Guid membershipId, Guid mobileNumberId);
}
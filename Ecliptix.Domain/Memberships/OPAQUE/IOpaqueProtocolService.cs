using Ecliptix.Domain.Utilities;
using Ecliptix.Protobuf.Membership;

namespace Ecliptix.Domain.Memberships.OPAQUE;

public interface IOpaqueProtocolService
{
    byte[] ProcessOprfRequest(byte[] oprfRequest);
    byte[] ProcessOprfRequest(ReadOnlySpan<byte> oprfRequest);

    byte[] GetPublicKey();

    Result<OpaqueSignInInitResponse, OpaqueFailure> InitiateSignIn(OpaqueSignInInitRequest request,MembershipOpaqueQueryRecord queryRecord);

    Result<OpaqueSignInFinalizeResponse, OpaqueFailure> FinalizeSignIn(OpaqueSignInFinalizeRequest request);

    Result<Unit, OpaqueFailure> CompleteRegistration(
        byte[] peerRegistrationRecord);

    Result<AuthContextTokenResponse, OpaqueFailure> GenerateAuthenticationContext(Guid membershipId, Guid mobileNumberId);
}
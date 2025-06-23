using Ecliptix.Domain.Utilities;
using Ecliptix.Protobuf.Membership;

namespace Ecliptix.Domain.Memberships.OPAQUE;

public interface IOpaqueProtocolService
{
    byte[] ProcessOprfRequest(byte[] oprfRequest);

    string GetPublicKey();

    Result<OpaqueSignInInitResponse, OpaqueFailure> InitiateSignIn(OpaqueSignInInitRequest request,MembershipOpaqueQueryRecord queryRecord);

    Result<OpaqueSignInFinalizeResponse, OpaqueFailure> FinalizeSignIn(OpaqueSignInFinalizeRequest request);
}
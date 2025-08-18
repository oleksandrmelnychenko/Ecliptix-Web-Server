using Ecliptix.Domain.Utilities;
using Ecliptix.Protobuf.Membership;

namespace Ecliptix.Domain.Memberships.OPAQUE;

public interface IOpaqueProtocolService
{
    byte[] ProcessOprfRequest(byte[] oprfRequest);

    byte[] GetPublicKey();

    Result<OpaqueSignInInitResponse, OpaqueFailure> InitiateSignIn(OpaqueSignInInitRequest request,MembershipOpaqueQueryRecord queryRecord);

    Result<OpaqueSignInFinalizeResponse, OpaqueFailure> FinalizeSignIn(OpaqueSignInFinalizeRequest request);

    Result<Unit, OpaqueFailure> CompleteRegistration(
        byte[] peerRegistrationRecord);

    // Password Change Operations
    Result<OpaquePasswordChangeInitResponse, OpaqueFailure> InitiatePasswordChange(
        OpaquePasswordChangeInitRequest request, MembershipOpaqueQueryRecord queryRecord);

    Result<OpaquePasswordChangeCompleteResponse, OpaqueFailure> CompletePasswordChange(
        OpaquePasswordChangeCompleteRequest request);

    // Session Management
    Result<SessionValidationResponse, OpaqueFailure> ValidateSession(SessionValidationRequest request);

    Result<InvalidateSessionResponse, OpaqueFailure> InvalidateSession(InvalidateSessionRequest request);

    Result<InvalidateAllSessionsResponse, OpaqueFailure> InvalidateAllSessions(InvalidateAllSessionsRequest request);

    // Account Recovery
    Result<AccountRecoveryInitResponse, OpaqueFailure> InitiateAccountRecovery(AccountRecoveryInitRequest request);

    Result<AccountRecoveryCompleteResponse, OpaqueFailure> CompleteAccountRecovery(AccountRecoveryCompleteRequest request);
}
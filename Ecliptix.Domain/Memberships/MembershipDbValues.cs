using Ecliptix.Domain.Status;

namespace Ecliptix.Domain.Memberships;

internal static class MembershipDbValues
{
    internal const string StatusActive = StatusCatalog.Membership.Active;
    internal const string StatusInactive = StatusCatalog.Membership.Inactive;

    internal const string CreationStatusOtpVerified = StatusCatalog.MembershipCreation.OtpVerified;
    internal const string CreationStatusSecureKeySet = StatusCatalog.MembershipCreation.SecureKeySet;
    internal const string CreationStatusPassphraseSet = StatusCatalog.MembershipCreation.PassphraseSet;

    internal const string OutcomeMembershipCreation = "membership_creation";
    internal const string OutcomeSuccess = "success";
    internal const string OutcomeCreated = "created";
    internal const string OutcomeRateLimitExceeded = "rate_limit_exceeded";

    internal const string FlowStatusVerified = StatusCatalog.VerificationFlow.Verified;
    internal const string FlowStatusExpired = StatusCatalog.VerificationFlow.Expired;
}

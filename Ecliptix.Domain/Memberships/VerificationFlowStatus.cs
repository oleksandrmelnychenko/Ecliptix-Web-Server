namespace Ecliptix.Domain.Memberships;

public enum VerificationFlowStatus
{
    Pending,
    Verified,
    Failed,
    Expired,
    MaxAttemptsReached
}

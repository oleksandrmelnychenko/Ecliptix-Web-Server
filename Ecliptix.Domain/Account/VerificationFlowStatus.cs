namespace Ecliptix.Domain.Account;

public enum VerificationFlowStatus
{
    Pending,
    Verified,
    Failed,
    Expired,
    MaxAttemptsReached
}
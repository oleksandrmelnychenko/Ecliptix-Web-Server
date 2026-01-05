using Ecliptix.IdentityAccess.Domain.Memberships.Persistors.QueryRecords;

namespace Ecliptix.IdentityAccess.Domain.Memberships.WorkerActors.VerificationFlow.PersistenceModels;

internal sealed record VerificationFlowPersistentState(
    VerificationFlowQueryRecord? VerificationFlow,
    OtpQueryRecord? ActiveOtp,
    DateTimeOffset? SessionDeadline,
    bool SessionTimerPaused,
    long OtpSendAttempts,
    bool CleanupCompleted,
    bool IsCompleting,
    bool TimersStarted);

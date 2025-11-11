using Ecliptix.Domain.Memberships.Persistors.QueryRecords;

namespace Ecliptix.Domain.Memberships.WorkerActors.VerificationFlow.PersistenceModels;

internal sealed record VerificationFlowPersistentState(
    VerificationFlowQueryRecord? VerificationFlow,
    OtpQueryRecord? ActiveOtp,
    DateTimeOffset? SessionDeadline,
    bool SessionTimerPaused,
    long OtpSendAttempts,
    bool CleanupCompleted,
    bool IsCompleting,
    bool TimersStarted);

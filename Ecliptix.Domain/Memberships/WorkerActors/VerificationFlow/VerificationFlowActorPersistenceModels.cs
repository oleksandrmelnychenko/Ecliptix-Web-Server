using Ecliptix.Domain.Memberships.Persistors.QueryRecords;

namespace Ecliptix.Domain.Memberships.WorkerActors.VerificationFlow;

internal sealed record VerificationFlowPersistentState(
    VerificationFlowQueryRecord? VerificationFlow,
    OtpQueryRecord? ActiveOtp,
    DateTimeOffset? SessionDeadline,
    bool SessionTimerPaused,
    long OtpSendAttempts,
    bool CleanupCompleted,
    bool IsCompleting,
    bool TimersStarted);

internal sealed record VerificationFlowStatePersistedEvent(VerificationFlowPersistentState State);

internal sealed record VerificationFlowActorSnapshot(VerificationFlowPersistentState State);

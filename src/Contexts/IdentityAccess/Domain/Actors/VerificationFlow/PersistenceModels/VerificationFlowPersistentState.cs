using Ecliptix.IdentityAccess.Domain.Persistors.QueryRecords;

namespace Ecliptix.IdentityAccess.Domain.Actors.VerificationFlow.PersistenceModels;

internal sealed record VerificationFlowPersistentState(
    VerificationFlowQueryRecord? VerificationFlow,
    OtpQueryRecord? ActiveOtp,
    DateTimeOffset? SessionDeadline,
    bool SessionTimerPaused,
    long OtpSendAttempts,
    bool CleanupCompleted,
    bool IsCompleting,
    bool TimersStarted);

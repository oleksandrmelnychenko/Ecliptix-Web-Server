using Ecliptix.IdentityAccess.Domain.Memberships.Otp;
using Ecliptix.IdentityAccess.Domain.Persistors.QueryRecords;

namespace Ecliptix.IdentityAccess.Domain.Memberships.ActorEvents;

public record CreateOtpActorEvent(OtpQueryRecord OtpRecord, CancellationToken CancellationToken = default)
    : ICancellableActorEvent;

public record GetOtpAttemptCountActorEvent(
    Guid OtpUniqueId,
    CancellationToken CancellationToken = default
) : ICancellableActorEvent;

public record IncrementOtpAttemptCountActorEvent(
    Guid OtpUniqueId,
    CancellationToken CancellationToken = default
) : ICancellableActorEvent;

public record LogFailedOtpAttemptActorEvent(
    Guid OtpUniqueId,
    string FailureReason,
    CancellationToken CancellationToken = default
) : ICancellableActorEvent;

public record RequestResendOtpActorEvent(
    Guid FlowUniqueId,
    CancellationToken CancellationToken = default
) : ICancellableActorEvent;

public record StartOtpTimerEvent;

public record UpdateOtpStatusActorEvent(
    Guid OtpIdentified,
    OtpStatus Status,
    CancellationToken CancellationToken = default
) : ICancellableActorEvent;

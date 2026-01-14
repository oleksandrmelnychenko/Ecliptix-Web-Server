using Ecliptix.IdentityAccess.Domain.Memberships.Otp;
using Ecliptix.IdentityAccess.Domain.Persistors.QueryRecords;
using Ecliptix.SharedKernel.Actors;

namespace Ecliptix.IdentityAccess.Domain.Actors.VerificationFlow;

public record CreateOtpCommand(OtpQueryRecord OtpRecord, CancellationToken CancellationToken = default)
    : ICancellableActorEvent;

public record GetOtpAttemptCountQuery(
    Guid OtpUniqueId,
    CancellationToken CancellationToken = default
) : ICancellableActorEvent;

public record IncrementOtpAttemptCountCommand(
    Guid OtpUniqueId,
    CancellationToken CancellationToken = default
) : ICancellableActorEvent;

public record RecordFailedOtpAttemptCommand(
    Guid OtpUniqueId,
    string FailureReason,
    CancellationToken CancellationToken = default
) : ICancellableActorEvent;

public record RequestResendOtpCommand(
    Guid FlowUniqueId,
    CancellationToken CancellationToken = default
) : ICancellableActorEvent;

public record StartOtpTimerEvent;

public record UpdateOtpStatusCommand(
    Guid OtpIdentified,
    OtpStatus Status,
    CancellationToken CancellationToken = default
) : ICancellableActorEvent;

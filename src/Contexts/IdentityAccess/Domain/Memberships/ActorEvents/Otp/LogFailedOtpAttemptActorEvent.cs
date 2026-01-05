using Ecliptix.IdentityAccess.Domain.Memberships.ActorEvents.Common;

namespace Ecliptix.IdentityAccess.Domain.Memberships.ActorEvents.Otp;

public record LogFailedOtpAttemptActorEvent(
    Guid OtpUniqueId,
    string FailureReason,
    CancellationToken CancellationToken = default
) : ICancellableActorEvent;

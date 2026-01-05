using Ecliptix.IdentityAccess.Domain.Memberships.ActorEvents.Common;

namespace Ecliptix.IdentityAccess.Domain.Memberships.ActorEvents.Otp;

public record IncrementOtpAttemptCountActorEvent(
    Guid OtpUniqueId,
    CancellationToken CancellationToken = default
) : ICancellableActorEvent;

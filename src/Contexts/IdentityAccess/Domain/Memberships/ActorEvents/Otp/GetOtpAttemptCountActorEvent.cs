using Ecliptix.IdentityAccess.Domain.Memberships.ActorEvents.Common;

namespace Ecliptix.IdentityAccess.Domain.Memberships.ActorEvents.Otp;

public record GetOtpAttemptCountActorEvent(
    Guid OtpUniqueId,
    CancellationToken CancellationToken = default
) : ICancellableActorEvent;

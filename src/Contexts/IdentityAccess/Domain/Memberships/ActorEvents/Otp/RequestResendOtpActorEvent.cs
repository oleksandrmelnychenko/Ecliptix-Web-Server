using Ecliptix.IdentityAccess.Domain.Memberships.ActorEvents.Common;

namespace Ecliptix.IdentityAccess.Domain.Memberships.ActorEvents.Otp;

public record RequestResendOtpActorEvent(
    Guid FlowUniqueId,
    CancellationToken CancellationToken = default
) : ICancellableActorEvent;

using Ecliptix.IdentityAccess.Domain.Memberships.ActorEvents.Common;

namespace Ecliptix.IdentityAccess.Domain.Memberships.ActorEvents.MobileNumber;

public record GetMobileNumberActorEvent(
    Guid MobileNumberIdentifier,
    CancellationToken CancellationToken = default
) : ICancellableActorEvent;

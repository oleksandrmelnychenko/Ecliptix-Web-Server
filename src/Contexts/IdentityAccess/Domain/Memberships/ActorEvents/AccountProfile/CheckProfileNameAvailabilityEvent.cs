using Ecliptix.IdentityAccess.Domain.Memberships.ActorEvents.Common;

namespace Ecliptix.IdentityAccess.Domain.Memberships.ActorEvents.AccountProfile;

public record CheckProfileNameAvailabilityEvent(
    string ProfileName,
    CancellationToken CancellationToken
) : ICancellableActorEvent;

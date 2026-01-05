using Ecliptix.IdentityAccess.Domain.Memberships.ActorEvents.Common;

namespace Ecliptix.IdentityAccess.Domain.Memberships.ActorEvents.Account;

public record CheckExistingMembershipActorEvent(
    Guid MobileNumberId,
    CancellationToken CancellationToken = default
) : ICancellableActorEvent;

using Ecliptix.Domain.Memberships.ActorEvents.Common;

namespace Ecliptix.Domain.Memberships.ActorEvents.Account;

public record CheckExistingMembershipActorEvent(
    Guid MobileNumberId,
    CancellationToken CancellationToken = default
) : ICancellableActorEvent;

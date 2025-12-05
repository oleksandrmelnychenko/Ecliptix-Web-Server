using Ecliptix.Domain.Memberships.ActorEvents.Common;

namespace Ecliptix.Domain.Memberships.ActorEvents.MobileNumber;

public record GetMobileNumberActorEvent(
    Guid MobileNumberIdentifier,
    CancellationToken CancellationToken = default
) : ICancellableActorEvent;

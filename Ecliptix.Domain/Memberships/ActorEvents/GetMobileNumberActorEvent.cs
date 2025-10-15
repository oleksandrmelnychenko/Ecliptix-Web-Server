using System.Threading;

namespace Ecliptix.Domain.Memberships.ActorEvents;

public record GetMobileNumberActorEvent(
    Guid MobileNumberIdentifier,
    CancellationToken CancellationToken = default
) : ICancellableActorEvent;

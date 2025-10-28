namespace Ecliptix.Domain.Memberships.ActorEvents.Common;

public interface ICancellableActorEvent
{
    CancellationToken CancellationToken { get; }
}

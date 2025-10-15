using System.Threading;

namespace Ecliptix.Domain.Memberships.ActorEvents;

public interface ICancellableActorEvent
{
    CancellationToken CancellationToken { get; }
}

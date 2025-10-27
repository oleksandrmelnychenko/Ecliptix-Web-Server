using System.Collections.Concurrent;
using Akka.Actor;

namespace Ecliptix.Core;

public sealed class ActorRegistry : IEcliptixActorRegistry
{
    private readonly ConcurrentDictionary<int, IActorRef> _actors = new();

    public void Register(int actorId, IActorRef actorRef)
    {
        _actors[actorId] = actorRef;
    }

    public IActorRef Get(int actorId)
    {
        return _actors.TryGetValue(actorId, out IActorRef? actorRef)
            ? actorRef
            : throw new InvalidOperationException(
                $"Actor with ID {actorId} ({ActorTypeMap.GetActorName(actorId)}) not registered.");
    }
}

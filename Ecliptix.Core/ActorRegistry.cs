using System.Collections.Concurrent;
using Akka.Actor;

namespace Ecliptix.Core;

public sealed class ActorRegistry : IEcliptixActorRegistry
{
    private readonly ConcurrentDictionary<Type, IActorRef> _actors = new();

    public void Register<TActor>(IActorRef actorRef) where TActor : ActorBase
    {
        _actors[typeof(TActor)] = actorRef;
    }

    public IActorRef Get<TActor>() where TActor : ActorBase
    {
        if (_actors.TryGetValue(typeof(TActor), out var actorRef))
            return actorRef;

        throw new InvalidOperationException($"Actor of type {typeof(TActor).Name} not registered.");
    }
}
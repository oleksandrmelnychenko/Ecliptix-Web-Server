using Akka.Actor;

namespace Ecliptix.Core;

public interface IEcliptixActorRegistry
{
    void Register<TActor>(IActorRef actorRef) where TActor : ActorBase;
    IActorRef Get<TActor>() where TActor : ActorBase;
}
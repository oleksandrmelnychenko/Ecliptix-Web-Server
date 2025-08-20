using Akka.Actor;

namespace Ecliptix.Core;

public interface IEcliptixActorRegistry
{
    void Register(int actorId, IActorRef actorRef);
    
    IActorRef Get(int actorId);
}
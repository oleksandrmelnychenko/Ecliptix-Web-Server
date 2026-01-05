using Akka.Actor;

namespace Ecliptix.SharedKernel.Actors;

public interface IEcliptixActorRegistry
{
    void Register(int actorId, IActorRef actorRef);

    IActorRef Get(int actorId);
}

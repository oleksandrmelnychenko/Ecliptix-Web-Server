using Akka.Actor;

namespace Ecliptix.Domain.Memberships.ActorEvents.VerificationFlow;

public record FlowCompletedGracefullyActorEvent(IActorRef ActorRef);

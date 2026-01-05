using Akka.Actor;

namespace Ecliptix.IdentityAccess.Domain.Memberships.ActorEvents.VerificationFlow;

public record FlowCompletedGracefullyActorEvent(IActorRef ActorRef);

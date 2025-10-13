using Ecliptix.Domain.Account;

namespace Ecliptix.Domain.Memberships.ActorEvents;

public record UpdateVerificationFlowStatusActorEvent(Guid FlowIdentifier, VerificationFlowStatus Status);
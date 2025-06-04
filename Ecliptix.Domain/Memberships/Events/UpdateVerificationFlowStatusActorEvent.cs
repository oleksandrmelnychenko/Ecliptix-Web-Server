namespace Ecliptix.Domain.Memberships.Events;

public record UpdateVerificationFlowStatusActorEvent(Guid FlowIdentifier, VerificationFlowStatus Status);
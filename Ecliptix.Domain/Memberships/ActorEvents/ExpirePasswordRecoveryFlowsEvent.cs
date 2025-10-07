namespace Ecliptix.Domain.Memberships.ActorEvents;

public record ExpirePasswordRecoveryFlowsEvent(Guid MembershipIdentifier);

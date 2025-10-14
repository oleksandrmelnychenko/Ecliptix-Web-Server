namespace Ecliptix.Domain.Memberships.ActorEvents;

public record CreateDefaultAccountEvent(Guid MembershipId);

public record GetAccountsForMembershipEvent(Guid MembershipId);

public record SwitchAccountEvent(Guid MembershipId, Guid DeviceId, Guid NewAccountId);

using System.Threading;

namespace Ecliptix.Domain.Memberships.ActorEvents;

public record CreateDefaultAccountEvent(Guid MembershipId, CancellationToken CancellationToken = default)
    : ICancellableActorEvent;

public record GetAccountsForMembershipEvent(Guid MembershipId, CancellationToken CancellationToken = default)
    : ICancellableActorEvent;

public record SwitchAccountEvent(Guid MembershipId, Guid DeviceId, Guid NewAccountId,
    CancellationToken CancellationToken = default) : ICancellableActorEvent;

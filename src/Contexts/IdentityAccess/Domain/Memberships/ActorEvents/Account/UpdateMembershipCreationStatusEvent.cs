using Ecliptix.IdentityAccess.Domain.Memberships.ActorEvents.Common;

namespace Ecliptix.IdentityAccess.Domain.Memberships.ActorEvents.Account;

public record UpdateMembershipCreationStatusEvent(
    Guid MembershipIdentifier,
    MembershipCreationStatus CreationStatus,
    CancellationToken CancellationToken = default
) : ICancellableActorEvent;

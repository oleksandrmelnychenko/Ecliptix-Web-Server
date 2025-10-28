using Ecliptix.Domain.Memberships.ActorEvents.Common;
using Ecliptix.Domain.Schema.Entities;

namespace Ecliptix.Domain.Memberships.ActorEvents.Account;

public record UpdateMembershipCreationStatusEvent(
    Guid MembershipIdentifier,
    MembershipCreationStatus CreationStatus,
    CancellationToken CancellationToken = default
) : ICancellableActorEvent;

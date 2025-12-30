using Ecliptix.Domain.Memberships.ActorEvents.Common;

namespace Ecliptix.Domain.Memberships.ActorEvents.Membership;

public record CompleteRegistrationRecordActorEvent(
    Guid MembershipIdentifier,
    byte[] PeerRegistrationRecord,
    CancellationToken CancellationToken = default) : ICancellableActorEvent;

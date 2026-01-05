using Ecliptix.IdentityAccess.Domain.Memberships.ActorEvents.Common;

namespace Ecliptix.IdentityAccess.Domain.Memberships.ActorEvents.Membership;

public record CompleteRegistrationRecordActorEvent(
    Guid MembershipIdentifier,
    byte[] PeerRegistrationRecord,
    CancellationToken CancellationToken = default) : ICancellableActorEvent;

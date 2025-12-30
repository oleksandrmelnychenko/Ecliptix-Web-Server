using Ecliptix.Domain.Memberships.ActorEvents.Common;

namespace Ecliptix.Domain.Memberships.ActorEvents.Membership;

public record OprfCompleteRecoverySecureKeyEvent(
    Guid MembershipIdentifier,
    byte[] PeerRecoveryRecord,
    CancellationToken CancellationToken = default) : ICancellableActorEvent;

using Ecliptix.IdentityAccess.Domain.Memberships.ActorEvents.Common;

namespace Ecliptix.IdentityAccess.Domain.Memberships.ActorEvents.Membership;

public record OprfCompleteRecoverySecureKeyEvent(
    Guid MembershipIdentifier,
    byte[] PeerRecoveryRecord,
    CancellationToken CancellationToken = default) : ICancellableActorEvent;

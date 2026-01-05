using Ecliptix.IdentityAccess.Domain.Memberships.ActorEvents.Common;

namespace Ecliptix.IdentityAccess.Domain.Memberships.ActorEvents.Membership;

public record OprfInitRecoverySecureKeyEvent(
    Guid MembershipIdentifier,
    byte[] OprfRequest,
    string CultureName,
    CancellationToken CancellationToken = default) : ICancellableActorEvent;

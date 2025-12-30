using Ecliptix.Domain.Memberships.ActorEvents.Common;

namespace Ecliptix.Domain.Memberships.ActorEvents.Membership;

public record UpdateAccountSecureKeyEvent(
    Guid MembershipIdentifier,
    byte[] SecureKey,
    byte[] MaskingKey,
    int OpaqueKeyVersion = 1,
    Guid? AccountId = null,
    CancellationToken CancellationToken = default) : ICancellableActorEvent;

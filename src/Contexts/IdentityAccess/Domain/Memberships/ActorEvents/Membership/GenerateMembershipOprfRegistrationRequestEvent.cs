using Ecliptix.IdentityAccess.Domain.Memberships.ActorEvents.Common;

namespace Ecliptix.IdentityAccess.Domain.Memberships.ActorEvents.Membership;

public record GenerateMembershipOprfRegistrationRequestEvent(
    Guid MembershipIdentifier,
    byte[]? OprfRequest,
    CancellationToken CancellationToken = default) : ICancellableActorEvent;

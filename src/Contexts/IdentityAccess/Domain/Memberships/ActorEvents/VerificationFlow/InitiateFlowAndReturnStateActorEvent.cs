using Ecliptix.IdentityAccess.Domain.Memberships.ActorEvents.Common;

namespace Ecliptix.IdentityAccess.Domain.Memberships.ActorEvents.VerificationFlow;

public record InitiateFlowAndReturnStateActorEvent(
    Guid AppDeviceId,
    Guid MobileNumberUniqueId,
    VerificationPurpose Purpose,
    uint? ConnectId,
    CancellationToken CancellationToken = default
) : ICancellableActorEvent;

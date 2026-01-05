using Ecliptix.IdentityAccess.Domain.Memberships.ActorEvents.Common;

namespace Ecliptix.IdentityAccess.Domain.Memberships.ActorEvents.VerificationFlow;

public record VerifyMobileForSecretKeyRecoveryActorEvent(
    string MobileNumber,
    string? RegionCode,
    CancellationToken CancellationToken = default
) : ICancellableActorEvent;

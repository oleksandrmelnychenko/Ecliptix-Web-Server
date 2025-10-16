using System.Threading;

namespace Ecliptix.Domain.Memberships.ActorEvents;

public record VerifyMobileForSecretKeyRecoveryActorEvent(
    string MobileNumber,
    string? RegionCode,
    CancellationToken CancellationToken = default
) : ICancellableActorEvent;

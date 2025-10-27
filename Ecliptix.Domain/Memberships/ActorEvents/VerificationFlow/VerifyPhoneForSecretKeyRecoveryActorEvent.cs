using System.Threading;
using Ecliptix.Domain.Memberships.ActorEvents.Common;

namespace Ecliptix.Domain.Memberships.ActorEvents.VerificationFlow;

public record VerifyMobileForSecretKeyRecoveryActorEvent(
    string MobileNumber,
    string? RegionCode,
    CancellationToken CancellationToken = default
) : ICancellableActorEvent;

using Ecliptix.IdentityAccess.Domain.Memberships.ActorEvents.Common;

namespace Ecliptix.IdentityAccess.Domain.Memberships.ActorEvents.VerificationFlow;

public record VerifyFlowActorEvent(
    uint ConnectId,
    string OneTimePassword,
    string CultureName,
    CancellationToken CancellationToken = default
) : ICancellableActorEvent;

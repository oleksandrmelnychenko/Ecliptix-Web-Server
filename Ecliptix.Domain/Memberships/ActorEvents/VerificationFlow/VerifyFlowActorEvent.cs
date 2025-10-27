using System.Threading;
using Ecliptix.Domain.Memberships.ActorEvents.Common;

namespace Ecliptix.Domain.Memberships.ActorEvents.VerificationFlow;

public record VerifyFlowActorEvent(
    uint ConnectId,
    string OneTimePassword,
    string CultureName,
    CancellationToken CancellationToken = default
) : ICancellableActorEvent;

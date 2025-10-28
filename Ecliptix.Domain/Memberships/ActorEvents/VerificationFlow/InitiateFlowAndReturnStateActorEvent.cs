using System.Threading;
using Ecliptix.Domain.Memberships.ActorEvents.Common;
using Ecliptix.Protobuf.Membership;

namespace Ecliptix.Domain.Memberships.ActorEvents.VerificationFlow;

public record InitiateFlowAndReturnStateActorEvent(
    Guid AppDeviceId,
    Guid MobileNumberUniqueId,
    VerificationPurpose Purpose,
    uint? ConnectId,
    CancellationToken CancellationToken = default
) : ICancellableActorEvent;

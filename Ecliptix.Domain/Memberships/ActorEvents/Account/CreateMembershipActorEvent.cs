using Ecliptix.Domain.Memberships.ActorEvents.Common;
using Ecliptix.Protobuf.Membership;

namespace Ecliptix.Domain.Memberships.ActorEvents.Account;

public record CreateMembershipActorEvent(
    uint ConnectId,
    Guid VerificationFlowIdentifier,
    Guid OtpIdentifier,
    Membership.Types.CreationStatus CreationStatus,
    CancellationToken CancellationToken = default
) : ICancellableActorEvent;

using Ecliptix.IdentityAccess.Domain.Memberships.ActorEvents.Common;
using ProtoMembership = Ecliptix.Protobuf.Membership.Membership;

namespace Ecliptix.IdentityAccess.Domain.Memberships.ActorEvents.Account;

public record CreateMembershipActorEvent(
    uint ConnectId,
    Guid VerificationFlowIdentifier,
    Guid OtpIdentifier,
    ProtoMembership.Types.CreationStatus CreationStatus,
    CancellationToken CancellationToken = default
) : ICancellableActorEvent;

using Ecliptix.Protobuf.Membership;
using Ecliptix.SharedKernel.Actors;
using ProtoMembership = Ecliptix.Protobuf.Membership.Membership;

namespace Ecliptix.IdentityAccess.Domain.Memberships.ActorEvents;

public record CheckExistingMembershipActorEvent(
    Guid MobileNumberId,
    CancellationToken CancellationToken = default
) : ICancellableActorEvent;

public record CreateDefaultAccountEvent(
    Guid MembershipId,
    Guid? AccountId = null,
    CancellationToken CancellationToken = default
) : ICancellableActorEvent;

public record CreateMembershipActorEvent(
    uint ConnectId,
    Guid VerificationFlowIdentifier,
    Guid OtpIdentifier,
    ProtoMembership.Types.CreationStatus CreationStatus,
    CancellationToken CancellationToken = default
) : ICancellableActorEvent;

public record GetAccountsByMembershipIdEvent(
    Guid MembershipId,
    CancellationToken CancellationToken = default
) : ICancellableActorEvent;

public record GetDefaultAccountIdEvent(
    Guid MembershipId,
    CancellationToken CancellationToken = default
) : ICancellableActorEvent;

public record GetMembershipByUniqueIdEvent(
    Guid MembershipUniqueId,
    CancellationToken CancellationToken = default
) : ICancellableActorEvent;

public record GetMembershipByVerificationFlowEvent(
    Guid VerificationFlowId,
    CancellationToken CancellationToken = default
) : ICancellableActorEvent;

public record SignInMembershipActorEvent(
    uint ConnectId,
    string MobileNumber,
    Guid DeviceId,
    OpaqueSignInInitRequest OpaqueSignInInitRequest,
    string CultureName,
    CancellationToken CancellationToken = default
) : ICancellableActorEvent;

public record UpdateMembershipCreationStatusEvent(
    Guid MembershipIdentifier,
    MembershipCreationStatus CreationStatus,
    CancellationToken CancellationToken = default
) : ICancellableActorEvent;

public record UpdateMembershipVerificationFlowEvent(
    Guid VerificationFlowId,
    OtpVerificationPurpose Purpose,
    VerificationFlowStatus FlowStatus,
    CancellationToken CancellationToken = default
) : ICancellableActorEvent;

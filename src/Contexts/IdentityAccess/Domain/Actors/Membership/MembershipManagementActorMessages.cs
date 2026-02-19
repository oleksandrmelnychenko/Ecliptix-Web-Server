using Ecliptix.IdentityAccess.Domain.Memberships;
using Ecliptix.Protobuf.Membership;
using Ecliptix.SharedKernel.Actors;
using ProtoMembership = Ecliptix.Protobuf.Membership.Membership;

namespace Ecliptix.IdentityAccess.Domain.Actors.Membership;

public record ExistsMembershipQuery(
    Guid MobileNumberId,
    CancellationToken CancellationToken = default
) : ICancellableActorEvent;

public record CreateDefaultAccountCommand(
    Guid MembershipId,
    Guid? AccountId = null,
    CancellationToken CancellationToken = default
) : ICancellableActorEvent;

public record CreateMembershipCommand(
    uint ConnectId,
    Guid VerificationFlowIdentifier,
    Guid OtpIdentifier,
    ProtoMembership.Types.CreationStatus CreationStatus,
    CancellationToken CancellationToken = default
) : ICancellableActorEvent;

public record GetAccountsByMembershipIdQuery(
    Guid MembershipId,
    CancellationToken CancellationToken = default
) : ICancellableActorEvent;

public record GetDefaultAccountIdQuery(
    Guid MembershipId,
    CancellationToken CancellationToken = default
) : ICancellableActorEvent;

public record GetMembershipByUniqueIdQuery(
    Guid MembershipUniqueId,
    CancellationToken CancellationToken = default
) : ICancellableActorEvent;

public record GetMembershipByVerificationFlowQuery(
    Guid VerificationFlowId,
    CancellationToken CancellationToken = default
) : ICancellableActorEvent;

public record SignInMembershipCommand(
    uint ConnectId,
    string MobileNumber,
    Guid DeviceId,
    Guid AppInstanceId,
    OpaqueSignInInitRequest OpaqueSignInInitRequest,
    string CultureName,
    CancellationToken CancellationToken = default
) : ICancellableActorEvent;

public record UpdateMembershipCreationStatusCommand(
    Guid MembershipIdentifier,
    MembershipCreationStatus CreationStatus,
    CancellationToken CancellationToken = default
) : ICancellableActorEvent;

public record UpdateMembershipVerificationFlowCommand(
    Guid VerificationFlowId,
    Memberships.OtpVerificationPurpose Purpose,
    VerificationFlowStatus FlowStatus,
    CancellationToken CancellationToken = default
) : ICancellableActorEvent;

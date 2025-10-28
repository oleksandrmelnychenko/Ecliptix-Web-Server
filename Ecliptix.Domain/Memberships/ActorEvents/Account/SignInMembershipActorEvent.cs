using System.Threading;
using Ecliptix.Domain.Memberships.ActorEvents.Common;
using Ecliptix.Protobuf.Membership;

namespace Ecliptix.Domain.Memberships.ActorEvents.Account;

public record SignInMembershipActorEvent(
    uint ConnectId,
    string MobileNumber,
    Guid DeviceId,
    OpaqueSignInInitRequest OpaqueSignInInitRequest,
    string CultureName,
    CancellationToken CancellationToken = default
) : ICancellableActorEvent;

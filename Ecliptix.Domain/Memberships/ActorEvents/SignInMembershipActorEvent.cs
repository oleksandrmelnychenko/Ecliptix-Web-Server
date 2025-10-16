using System.Threading;
using Ecliptix.Protobuf.Membership;

namespace Ecliptix.Domain.Memberships.ActorEvents;

public record SignInMembershipActorEvent(
    uint ConnectId,
    string MobileNumber,
    Guid DeviceId,
    OpaqueSignInInitRequest OpaqueSignInInitRequest,
    string CultureName,
    CancellationToken CancellationToken = default
) : ICancellableActorEvent;

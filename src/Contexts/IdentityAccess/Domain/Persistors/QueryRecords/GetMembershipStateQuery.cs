using Ecliptix.SharedKernel.Actors;

namespace Ecliptix.IdentityAccess.Domain.Persistors.QueryRecords;

public record GetMembershipStateQuery(
    Guid MembershipId,
    Guid RequestingDeviceId,
    CancellationToken CancellationToken
) : ICancellableActorEvent;

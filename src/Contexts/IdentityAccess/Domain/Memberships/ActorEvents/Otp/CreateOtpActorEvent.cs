using Ecliptix.IdentityAccess.Domain.Memberships.ActorEvents.Common;
using Ecliptix.IdentityAccess.Domain.Persistors.QueryRecords;

namespace Ecliptix.IdentityAccess.Domain.Memberships.ActorEvents.Otp;

public record CreateOtpActorEvent(OtpQueryRecord OtpRecord, CancellationToken CancellationToken = default)
    : ICancellableActorEvent;

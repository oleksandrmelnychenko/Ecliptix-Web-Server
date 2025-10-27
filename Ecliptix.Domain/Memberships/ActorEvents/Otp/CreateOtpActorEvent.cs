using System.Threading;
using Ecliptix.Domain.Memberships.ActorEvents.Common;
using Ecliptix.Domain.Memberships.Persistors.QueryRecords;

namespace Ecliptix.Domain.Memberships.ActorEvents.Otp;

public record CreateOtpActorEvent(OtpQueryRecord OtpRecord, CancellationToken CancellationToken = default)
    : ICancellableActorEvent;

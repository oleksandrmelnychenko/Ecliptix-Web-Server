using Ecliptix.Domain.Memberships.Persistors.QueryRecords;

namespace Ecliptix.Domain.Memberships.ActorEvents;

public record CreateOtpActorEvent(OtpQueryRecord OtpRecord);
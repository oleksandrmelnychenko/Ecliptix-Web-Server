using Ecliptix.Domain.Memberships.Persistors.QueryRecords;

namespace Ecliptix.Domain.Account.ActorEvents;

public record CreateOtpActorEvent(OtpQueryRecord OtpRecord);
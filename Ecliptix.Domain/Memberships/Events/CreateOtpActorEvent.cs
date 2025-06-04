using Ecliptix.Domain.Memberships.Persistors.QueryRecords;

namespace Ecliptix.Domain.Memberships.Events;

public record CreateOtpActorEvent(OtpQueryRecord OtpRecord);
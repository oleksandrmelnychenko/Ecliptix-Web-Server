namespace Ecliptix.Domain.Memberships.WorkerActors.Membership.PersistenceModels;

internal sealed record RecoverySessionSnapshot(Guid MembershipId, byte[] SessionKey, DateTimeOffset StartedAt);

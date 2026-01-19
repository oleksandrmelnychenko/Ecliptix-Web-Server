namespace Ecliptix.IdentityAccess.Domain.Actors.Membership.PersistenceModels;

internal sealed record RecoverySessionSnapshot(Guid MembershipId, DateTimeOffset StartedAt, int OpaqueKeyVersion = 1);

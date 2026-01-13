namespace Ecliptix.IdentityAccess.Domain.Actors.Membership.PersistenceModels;

internal sealed record RecoverySessionSnapshot(Guid MembershipId, byte[] SessionKey, DateTimeOffset StartedAt, int OpaqueKeyVersion = 1);

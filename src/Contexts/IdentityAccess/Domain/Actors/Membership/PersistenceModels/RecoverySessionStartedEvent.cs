namespace Ecliptix.IdentityAccess.Domain.Actors.Membership.PersistenceModels;

internal sealed record RecoverySessionStartedEvent(
    Guid MembershipId,
    byte[] AccountIdBytes,
    DateTimeOffset StartedAt,
    int OpaqueKeyVersion = 1);

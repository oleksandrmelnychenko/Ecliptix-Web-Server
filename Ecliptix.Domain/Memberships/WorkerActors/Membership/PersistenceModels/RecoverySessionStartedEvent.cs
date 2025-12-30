namespace Ecliptix.Domain.Memberships.WorkerActors.Membership.PersistenceModels;

internal sealed record RecoverySessionStartedEvent(
    Guid MembershipId,
    byte[] MaskingKey,
    byte[] SessionKey,
    DateTimeOffset StartedAt,
    int OpaqueKeyVersion = 1);

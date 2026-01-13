namespace Ecliptix.IdentityAccess.Domain.Actors.Membership.PersistenceModels;

internal sealed record RecoverySessionStartedEvent(
    Guid MembershipId,
    byte[] MaskingKey,
    byte[] SessionKey,
    DateTimeOffset StartedAt,
    int OpaqueKeyVersion = 1);

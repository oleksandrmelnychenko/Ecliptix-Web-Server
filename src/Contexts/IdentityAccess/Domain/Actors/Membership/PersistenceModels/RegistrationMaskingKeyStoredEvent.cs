namespace Ecliptix.IdentityAccess.Domain.Actors.Membership.PersistenceModels;

internal sealed record RegistrationMaskingKeyStoredEvent(Guid MembershipId, byte[] MaskingKey, int OpaqueKeyVersion = 1);

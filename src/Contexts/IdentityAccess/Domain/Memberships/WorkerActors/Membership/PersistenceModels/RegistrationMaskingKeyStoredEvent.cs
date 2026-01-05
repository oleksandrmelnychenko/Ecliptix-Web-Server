namespace Ecliptix.IdentityAccess.Domain.Memberships.WorkerActors.Membership.PersistenceModels;

internal sealed record RegistrationMaskingKeyStoredEvent(Guid MembershipId, byte[] MaskingKey, int OpaqueKeyVersion = 1);

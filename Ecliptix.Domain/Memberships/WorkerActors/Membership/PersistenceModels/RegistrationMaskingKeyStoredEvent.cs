namespace Ecliptix.Domain.Memberships.WorkerActors.Membership.PersistenceModels;

internal sealed record RegistrationMaskingKeyStoredEvent(Guid MembershipId, byte[] MaskingKey);

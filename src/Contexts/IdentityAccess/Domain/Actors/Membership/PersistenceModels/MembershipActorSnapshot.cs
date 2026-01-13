namespace Ecliptix.IdentityAccess.Domain.Actors.Membership.PersistenceModels;

internal sealed record MembershipActorSnapshot(
    List<PendingSignInStoredEvent> PendingSignIns,
    List<RegistrationMaskingKeyStoredEvent> PendingMaskingKeys,
    List<RecoverySessionSnapshot> RecoverySessions);

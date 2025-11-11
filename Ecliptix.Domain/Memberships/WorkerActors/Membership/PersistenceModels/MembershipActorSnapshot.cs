namespace Ecliptix.Domain.Memberships.WorkerActors.Membership.PersistenceModels;

internal sealed record MembershipActorSnapshot(
    List<PendingSignInStoredEvent> PendingSignIns,
    List<RegistrationMaskingKeyStoredEvent> PendingMaskingKeys,
    List<RecoverySessionSnapshot> RecoverySessions);

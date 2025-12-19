namespace Ecliptix.Core;

public static class ActorIds
{
    public const int EcliptixProtocolSystemActor = 1;
    public const int AppDevicePersistorActor = 2;
    public const int VerificationFlowPersistorActor = 3;
    public const int VerificationFlowManagerActor = 4;
    public const int MembershipPersistorActor = 5;
    public const int MembershipActor = 6;
    public const int MasterKeySharePersistorActor = 7;
    public const int LogoutAuditPersistorActor = 8;
    public const int AccountPersistorActor = 9;
    public const int PasswordRecoveryPersistorActor = 10;
    public const int MembershipRelationPersistorActor = 11;
    public const int MembershipRelationActor = 12;
    public const int AccountProfileActor = 13;
    public const int AccountProfilePersistorActor = 14;
}

public static class ActorTypeMap
{
    private static readonly Dictionary<int, string> ActorNames = new()
    {
        { ActorIds.EcliptixProtocolSystemActor, "EcliptixProtocolSystemActor" },
        { ActorIds.AppDevicePersistorActor, "AppDevicePersistorActor" },
        { ActorIds.VerificationFlowPersistorActor, "VerificationFlowPersistorActor" },
        { ActorIds.VerificationFlowManagerActor, "VerificationFlowManagerActor" },
        { ActorIds.MembershipPersistorActor, "MembershipPersistorActor" },
        { ActorIds.MembershipActor, "MembershipActor" },
        { ActorIds.MasterKeySharePersistorActor, "MasterKeySharePersistorActor" },
        { ActorIds.LogoutAuditPersistorActor, "LogoutAuditPersistorActor" },
        { ActorIds.AccountPersistorActor, "AccountPersistorActor" },
        { ActorIds.PasswordRecoveryPersistorActor, "PasswordRecoveryPersistorActor" },
        { ActorIds.MembershipRelationPersistorActor, "MembershipRelationPersistorActor" },
        { ActorIds.MembershipRelationActor, "MembershipRelationActor" },
        { ActorIds.AccountProfileActor, "AccountProfileActor" },
        { ActorIds.AccountProfilePersistorActor, "AccountProfilePersistorActor" },
    };

    public static string GetActorName(int actorId)
    {
        return ActorNames.TryGetValue(actorId, out string? name) ? name
            : throw new ArgumentException($"Unknown actor ID: {actorId}");
    }
}

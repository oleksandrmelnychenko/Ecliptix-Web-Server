namespace Ecliptix.Core;

/// <summary>
/// AOT-safe actor identifiers to replace reflection-based type lookups
/// </summary>
public static class ActorIds
{
    public const int EcliptixProtocolSystemActor = 1;
    public const int AppDevicePersistorActor = 2; 
    public const int VerificationFlowPersistorActor = 3;
    public const int VerificationFlowManagerActor = 4;
    public const int MembershipPersistorActor = 5;
    public const int MembershipActor = 6;
}

/// <summary>
/// AOT-safe actor type mappings for factory pattern
/// </summary>
public static class ActorTypeMap
{
    private static readonly Dictionary<int, string> _actorNames = new()
    {
        { ActorIds.EcliptixProtocolSystemActor, "EcliptixProtocolSystemActor" },
        { ActorIds.AppDevicePersistorActor, "AppDevicePersistorActor" },
        { ActorIds.VerificationFlowPersistorActor, "VerificationFlowPersistorActor" },
        { ActorIds.VerificationFlowManagerActor, "VerificationFlowManagerActor" },
        { ActorIds.MembershipPersistorActor, "MembershipPersistorActor" },
        { ActorIds.MembershipActor, "MembershipActor" }
    };
    
    public static string GetActorName(int actorId)
    {
        return _actorNames.TryGetValue(actorId, out var name) ? name 
            : throw new ArgumentException($"Unknown actor ID: {actorId}");
    }
}
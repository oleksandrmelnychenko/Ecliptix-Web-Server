namespace Ecliptix.IdentityAccess.Domain.Memberships.ActorEvents.VerificationFlow;

public sealed class FlowTerminationAcknowledged
{
    public static readonly FlowTerminationAcknowledged Instance = new();
    private FlowTerminationAcknowledged()
    {
    }
}

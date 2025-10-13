namespace Ecliptix.Domain.Memberships.ActorEvents;

/// <summary>
/// Event to update the membership's VerificationFlowId for password recovery flows
/// </summary>
public record UpdateMembershipVerificationFlowEvent(
    Guid VerificationFlowId,
    string Purpose,
    string FlowStatus);

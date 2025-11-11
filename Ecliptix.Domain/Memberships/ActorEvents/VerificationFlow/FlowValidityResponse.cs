namespace Ecliptix.Domain.Memberships.ActorEvents.VerificationFlow;

public sealed record FlowValidityResponse(bool IsValid, uint RemainingSeconds);

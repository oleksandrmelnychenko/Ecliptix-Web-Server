using Ecliptix.Protobuf.Membership;

namespace Ecliptix.Domain.Memberships.ActorEvents.Membership;

public record SignInCompleteEvent(uint ConnectId, OpaqueSignInFinalizeRequest Request);

using Ecliptix.Protobuf.Membership;

namespace Ecliptix.IdentityAccess.Domain.Memberships.ActorEvents.Membership;

public record SignInCompleteEvent(uint ConnectId, OpaqueSignInFinalizeRequest Request);

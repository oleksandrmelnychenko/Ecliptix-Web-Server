using Ecliptix.Protobuf.Membership;

namespace Ecliptix.Domain.Memberships.ActorEvents;

public record SignInMembershipActorEvent(uint ConnectId, string MobileNumber, OpaqueSignInInitRequest OpaqueSignInInitRequest, string CultureName);
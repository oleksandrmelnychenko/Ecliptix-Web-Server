using Ecliptix.Protobuf.Membership;

namespace Ecliptix.Domain.Memberships.ActorEvents;

public record SignInMembershipActorEvent(string PhoneNumber, OpaqueSignInInitRequest OpaqueSignInInitRequest, string CultureName);
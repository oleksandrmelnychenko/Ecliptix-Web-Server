using Ecliptix.Protobuf.Account;

namespace Ecliptix.Domain.Memberships.ActorEvents;

public record SignInMembershipActorEvent(uint ConnectId, string MobileNumber, OpaqueSignInInitRequest
    OpaqueSignInInitRequest, string CultureName);
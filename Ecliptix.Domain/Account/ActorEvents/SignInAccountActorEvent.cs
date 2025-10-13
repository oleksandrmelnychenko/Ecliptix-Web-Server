using Ecliptix.Protobuf.Account;

namespace Ecliptix.Domain.Account.ActorEvents;

public record SignInAccountActorEvent(uint ConnectId, string MobileNumber, OpaqueSignInInitRequest
    OpaqueSignInInitRequest, string CultureName);
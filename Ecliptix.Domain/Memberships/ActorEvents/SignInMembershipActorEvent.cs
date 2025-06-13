namespace Ecliptix.Domain.Memberships.ActorEvents;

public record SignInMembershipActorEvent(string PhoneNumber, byte[] SecureKey,string CultureName);
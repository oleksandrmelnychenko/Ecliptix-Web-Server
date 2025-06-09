namespace Ecliptix.Domain.Memberships;

public record SignInMembershipActorEvent(string PhoneNumber, byte[] SecureKey,string CultureName);
namespace Ecliptix.IdentityAccess.Domain.Memberships;

public enum MembershipCreationStatus
{
    Unspecified = 0,
    OtpVerified = 1,
    SecureKeySet = 2,
    ProfileSet = 3,
    PassphraseSet = 4
}

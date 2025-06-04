namespace Ecliptix.Domain.Memberships.Persistors.Utilities;

internal static class OperationNames
{
    public const string UpdateOtpStatus = "UpdateOtpStatus";
    public const string GetPhoneNumber = "GetPhoneNumber";
    public const string CreateVerificationSession = "CreateVerificationSession";
    public const string GetVerificationSession = "GetVerificationSession";
    public const string UpdateSessionStatus = "UpdateSessionStatus";
    public const string CreateOtpRecord = "CreateOtpRecord";
    public const string EnsurePhoneNumber = "EnsurePhoneNumber";
    public const string SignInMembership = "SignInMembership";
    public const string UpdateMembershipSecureKey = "UpdateMembershipSecureKey";
    public const string CreateMembership = "CreateMembership";
}
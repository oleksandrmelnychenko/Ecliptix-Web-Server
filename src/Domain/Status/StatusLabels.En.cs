using System.Collections.Frozen;

namespace Ecliptix.Domain;

public static partial class StatusLabels
{
    public static IReadOnlyDictionary<string, string> En { get; } = CreateEnglish();

    private static IReadOnlyDictionary<string, string> CreateEnglish()
    {
        Dictionary<string, string> dictionary = new(StringComparer.Ordinal)
        {
            [StatusCatalog.Common.Active] = "Active",
            [StatusCatalog.Common.Archived] = "Archived",
            [StatusCatalog.Common.Blocked] = "Blocked",
            [StatusCatalog.Common.Expired] = "Expired",
            [StatusCatalog.Common.Failed] = "Failed",
            [StatusCatalog.Common.Inactive] = "Inactive",
            [StatusCatalog.Common.Invalid] = "Invalid",
            [StatusCatalog.VerificationPurpose.Login] = "Login",
            [StatusCatalog.MembershipCreation.OtpVerified] = "OTP Verified",
            [StatusCatalog.VerificationPurpose.PasswordRecovery] = "Password Recovery",
            [StatusCatalog.MembershipCreation.PassphraseSet] = "Passphrase Set",
            [StatusCatalog.Common.Pending] = "Pending",
            [StatusCatalog.VerificationPurpose.Registration] = "Registration",
            [StatusCatalog.MembershipCreation.SecureKeySet] = "Secure Key Set",
            [StatusCatalog.Common.Suspended] = "Suspended",
            [StatusCatalog.VerificationPurpose.Unspecified] = "Unspecified",
            [StatusCatalog.VerificationPurpose.UpdatePhone] = "Update Phone",
            [StatusCatalog.Common.Used] = "Used",
            [StatusCatalog.Common.Verified] = "Verified"
        };

        return dictionary.ToFrozenDictionary(StringComparer.Ordinal);
    }
}

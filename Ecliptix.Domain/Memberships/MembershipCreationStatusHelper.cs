using Ecliptix.Domain.Status;
using Ecliptix.Protobuf.Membership;

namespace Ecliptix.Domain.Memberships;

public static class MembershipCreationStatusHelper
{
    private static readonly Dictionary<Membership.Types.CreationStatus, string> ReverseCreationStatusMap;

    private static readonly Dictionary<string, Membership.Types.CreationStatus> CreationStatusMap = new(StringComparer.Ordinal)
    {
        [StatusCatalog.MembershipCreation.OtpVerified] = Membership.Types.CreationStatus.OtpVerified,
        [StatusCatalog.MembershipCreation.SecureKeySet] = Membership.Types.CreationStatus.SecureKeySet,
        [StatusCatalog.MembershipCreation.PassphraseSet] = Membership.Types.CreationStatus.PassphraseSet
    };

    static MembershipCreationStatusHelper()
    {
        ReverseCreationStatusMap = CreationStatusMap.ToDictionary(
            kvp => kvp.Value,
            kvp => kvp.Key
        );
    }

    public static string GetCreationStatusString(Membership.Types.CreationStatus status)
    {
        if (ReverseCreationStatusMap.TryGetValue(status, out string? statusString)) return statusString;

        throw new ArgumentException($"No mapping found for enum value: {status}", nameof(status));
    }

    public static Membership.Types.CreationStatus GetCreationStatusEnum(string statusString)
    {
        if (string.IsNullOrEmpty(statusString))
            throw new ArgumentException("Status string cannot be null or empty.", nameof(statusString));

        if (CreationStatusMap.TryGetValue(statusString, out Membership.Types.CreationStatus status)) return status;

        throw new ArgumentException($"No mapping found for status string: {statusString}", nameof(statusString));
    }
}

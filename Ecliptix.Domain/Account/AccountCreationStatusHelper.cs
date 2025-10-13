using AccountProto = Ecliptix.Protobuf.Account.Account;

namespace Ecliptix.Domain.Account;

public static class AccountCreationStatusHelper
{
    private static readonly Dictionary<AccountProto.Types.CreationStatus, string> ReverseCreationStatusMap;

    private static readonly Dictionary<string, AccountProto.Types.CreationStatus> CreationStatusMap = new()
    {
        ["otp_verified"] = AccountProto.Types.CreationStatus.OtpVerified,
        ["secure_key_set"] = AccountProto.Types.CreationStatus.SecureKeySet,
        ["passphrase_set"] = AccountProto.Types.CreationStatus.PassphraseSet
    };

    static AccountCreationStatusHelper()
    {
        ReverseCreationStatusMap = CreationStatusMap.ToDictionary(
            kvp => kvp.Value,
            kvp => kvp.Key
        );
    }

    public static string GetCreationStatusString(AccountProto.Types.CreationStatus status)
    {
        if (ReverseCreationStatusMap.TryGetValue(status, out string? statusString)) return statusString;

        throw new ArgumentException($"No mapping found for enum value: {status}", nameof(status));
    }

    public static AccountProto.Types.CreationStatus GetCreationStatusEnum(string statusString)
    {
        if (string.IsNullOrEmpty(statusString))
            throw new ArgumentException("Status string cannot be null or empty.", nameof(statusString));

        if (CreationStatusMap.TryGetValue(statusString, out AccountProto.Types.CreationStatus status)) return status;

        throw new ArgumentException($"No mapping found for status string: {statusString}", nameof(statusString));
    }
}
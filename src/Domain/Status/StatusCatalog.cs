using System.Collections.Frozen;
using System.Reflection;

namespace Ecliptix.Domain;

public static class StatusCatalog
{
    public static class Common
    {
        public const string Active = "active";
        public const string Archived = "archived";
        public const string Blocked = "blocked";
        public const string Expired = "expired";
        public const string Failed = "failed";
        public const string Inactive = "inactive";
        public const string Invalid = "invalid";
        public const string Pending = "pending";
        public const string Suspended = "suspended";
        public const string Used = "used";
        public const string Verified = "verified";
    }

    public static class Membership
    {
        public const string Active = Common.Active;
        public const string Inactive = Common.Inactive;
    }

    public static class MembershipCreation
    {
        public const string OtpVerified = "otp_verified";
        public const string PassphraseSet = "passphrase_set";
        public const string SecureKeySet = "secure_key_set";
    }

    public static class VerificationFlow
    {
        public const string Pending = Common.Pending;
        public const string Verified = Common.Verified;
        public const string Expired = Common.Expired;
    }

    public static class Otp
    {
        public const string Active = Common.Active;
        public const string Invalid = Common.Invalid;
        public const string Expired = Common.Expired;
        public const string Used = Common.Used;
    }

    public static class VerificationPurpose
    {
        public const string Unspecified = "unspecified";
        public const string Registration = "registration";
        public const string Login = "login";
        public const string PasswordRecovery = "password_recovery";
        public const string UpdatePhone = "update_phone";
    }

    private static readonly Lazy<IReadOnlySet<string>> CachedCodes = new(BuildAllCodes,
        LazyThreadSafetyMode.ExecutionAndPublication);

    public static IEnumerable<string> AllCodes => CachedCodes.Value;

    private static IReadOnlySet<string> BuildAllCodes()
    {
        HashSet<string> codes = new(StringComparer.Ordinal);
        CollectConstants(typeof(StatusCatalog), codes);
        return codes.Count == 0
            ? FrozenSet<string>.Empty
            : codes.ToFrozenSet(StringComparer.Ordinal);
    }

    private static void CollectConstants(Type type, ISet<string> sink)
    {
        foreach (FieldInfo field in type.GetFields(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static |
                                                   BindingFlags.DeclaredOnly))
        {
            if (!field.IsLiteral || field.FieldType != typeof(string))
            {
                continue;
            }

            if (field.GetRawConstantValue() is string value)
            {
                sink.Add(value);
            }
        }

        foreach (Type nested in type.GetNestedTypes(BindingFlags.Public | BindingFlags.NonPublic))
        {
            CollectConstants(nested, sink);
        }
    }
}
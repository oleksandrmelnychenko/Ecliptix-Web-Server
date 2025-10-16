using System.Collections.Frozen;

namespace Ecliptix.Domain;

public static partial class StatusLabels
{
    public static IReadOnlyDictionary<string, string> Uk { get; } = CreateUkrainian();

    private static IReadOnlyDictionary<string, string> CreateUkrainian()
    {
        Dictionary<string, string> dictionary = new(StringComparer.Ordinal)
        {
            [StatusCatalog.Common.Active] = "Активний",
            [StatusCatalog.Common.Archived] = "Заархівовано",
            [StatusCatalog.Common.Blocked] = "Заблоковано",
            [StatusCatalog.Common.Expired] = "Прострочено",
            [StatusCatalog.Common.Failed] = "Неуспішно",
            [StatusCatalog.Common.Inactive] = "Неактивний",
            [StatusCatalog.Common.Invalid] = "Недійсний",
            [StatusCatalog.VerificationPurpose.Login] = "Вхід",
            [StatusCatalog.MembershipCreation.OtpVerified] = "OTP підтверджено",
            [StatusCatalog.VerificationPurpose.PasswordRecovery] = "Відновлення пароля",
            [StatusCatalog.MembershipCreation.PassphraseSet] = "Парольну фразу встановлено",
            [StatusCatalog.Common.Pending] = "В очікуванні",
            [StatusCatalog.VerificationPurpose.Registration] = "Реєстрація",
            [StatusCatalog.MembershipCreation.SecureKeySet] = "Захищений ключ встановлено",
            [StatusCatalog.Common.Suspended] = "Призупинено",
            [StatusCatalog.VerificationPurpose.Unspecified] = "Не вказано",
            [StatusCatalog.VerificationPurpose.UpdatePhone] = "Оновлення номера телефону",
            [StatusCatalog.Common.Used] = "Використано",
            [StatusCatalog.Common.Verified] = "Підтверджено"
        };

        return dictionary.ToFrozenDictionary(StringComparer.Ordinal);
    }
}
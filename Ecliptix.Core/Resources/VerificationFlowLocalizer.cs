using System.Collections.Frozen;
using System.Globalization;
using Ecliptix.Domain;

namespace Ecliptix.Core.Resources;

public sealed class VerificationFlowLocalizer : ILocalizationProvider
{
    private readonly CultureInfo _defaultSystemCultureInfo = CultureInfo.GetCultureInfo("en-US");

    private static readonly FrozenDictionary<string, FrozenDictionary<string, string>> Resources =
        new Dictionary<string, FrozenDictionary<string, string>>
        {
            ["en-US"] = new Dictionary<string, string>
            {
                ["verification_flow_conflict_resolved_to_existing"] = "Existing session found; please continue.",
                ["verification_flow_conflict_unresolved"] = "Session conflict; please try again.",
                ["verification_flow_reused_and_updated"] = "Existing session updated; please continue.",
                ["verification_flow_conflict"] = "Active session exists; finish or cancel first.",
                ["flow_expired"] = "Session expired; start a new one.",
                ["verification_flow_not_found"] = "Session not found; start over.",
                ["verification_flow_not_verified"] = "Session not verified; please complete verification.",
                ["verification_session_not_found"] = "Verification details not found; please retry.",
                ["otp_invalid"] = "Invalid OTP; try again.",
                ["otp_expired"] = "OTP expired; request a new one.",
                ["otp_generation_failed"] = "OTP couldn't be generated; try again.",
                ["otp_max_attempts_reached"] = "Too many OTP attempts; wait or contact support.",
                ["otp_not_verified"] = "OTP not verified; please enter the code.",
                ["phone_invalid"] = "Invalid phone number; please check.",
                ["sms_send_failed"] = "SMS failed; check number or retry.",
                ["data_concurrency_conflict"] = "Data updated; refresh and retry.",
                ["data_access_failed"] = "Data access issue; try again later.",
                ["security_rate_limit_exceeded"] = "Too many verification attempts. Please try again in 30-60 minutes.",
                ["security_suspicious_activity"] = "Unusual activity detected; access restricted.",
                ["membership_too_many_attempts"] = "Too many membership attempts; wait {0} min or contact support.",
                ["signin_too_many_attempts"] = "Too many sign-in attempts; wait {0} min or contact support.",
                ["activity_status_invalid"] = "Invalid activity status.",
                ["app_device_created_but_invalid_id"] = "Device registered but ID issue; contact support.",
                ["app_device_invalid_id"] = "Invalid app device ID.",
                ["associated"] = "Phone number associated successfully.",
                ["phone_cannot_be_empty"] = "Phone number cannot be empty.",
                ["created_and_associated"] = "Phone number created and associated.",
                ["exists"] = "Phone number already exists.",
                ["phone_number_not_found"] = "Phone number not found for login.",
                ["phone_not_found"] = "Phone number not found.",
                ["validation_failed"] = "Form errors; check highlighted fields.",
                ["invalid_credentials"] = "Invalid username or password.",
                ["password_complexity_requirements"] =
                    "Password must be {0}+ chars with upper, lower, number, special.",
                ["password_empty"] = "Password required.",
                ["password_hash_error"] = "Password processing error; retry.",
                ["password_hash_input_empty"] = "Password processing failed; retry.",
                ["password_invalid_chars"] = "Invalid characters in password.",
                ["password_config_hash_algorithm_unsupported"] = "Password setup error; contact support.",
                ["password_config_iterations_invalid"] = "Password setup issue; contact support.",
                ["password_config_salt_size_invalid"] = "Password config issue; contact support.",
                ["password_missing_digit"] = "Add a number.",
                ["password_missing_lowercase"] = "Add lowercase letter.",
                ["password_missing_special_char"] = "Add special character.",
                ["password_missing_uppercase"] = "Add uppercase letter.",
                ["password_too_short"] = "Password too short; min {0} chars.",
                ["password_verify_base64_error"] = "Verification error; retry.",
                ["password_verify_error"] = "Verification failed; retry.",
                ["password_verify_hash_size_mismatch"] = "Verification mismatch; retry.",
                ["password_verify_input_empty"] = "Verification failed; retry.",
                ["password_verify_invalid_format"] = "Format error in verification; retry.",
                ["password_verify_mismatch"] = "Incorrect password.",
                ["password_verify_salt_size_mismatch"] = "Verification mismatch; retry.",
                ["password_verify_stored_hash_empty"] = "Verification issue; retry.",
                ["inactive_membership"] = "Membership is inactive.",
                ["invalid_secure_key"] = "Invalid secure key provided.",
                ["membership_already_exists"] = "Membership already exists.",
                ["membership_not_found"] = "Membership not found.",
                ["secure_key_cannot_be_empty"] = "Secure key cannot be empty.",
                ["secure_key_not_set"] = "Secure key not set up for this membership.",
                ["secure_key_too_long"] = "Secure key is too long.",
                ["secure_key_updated"] = "Secure key updated successfully.",
                ["created"] = "Successfully created.",
                ["generic_error"] = "Unexpected error; try again later.",
                ["generic_no_result_returned"] = "No result returned; try again.",
                ["generic_success"] = "Operation successful.",
                ["generic_unexpected_outcome"] = "Unexpected outcome occurred; try again.",
                ["phone_parsing_invalid_country_code"] = "Invalid country code in phone number.",
                ["phone_parsing_too_short"] = "Phone number is too short.",
                ["phone_parsing_too_long"] = "Phone number is too long.",
                ["phone_parsing_invalid_number"] = "Phone number format is invalid.",
                ["phone_parsing_possible_but_local_only"] =
                    "Number might be valid locally; add country code or region.",
                ["phone_parsing_generic_error"] = "Error parsing phone number.",
                ["phone_validation_unexpected_error"] = "Unexpected error validating phone number.",
                ["authentication_code_is"] = "Your verification code is",
                ["resend_cooldown_active"] = "Please wait a moment before requesting a new code",
                ["max_otp_attempts_reached"] =
                    "You've reached the maximum number of OTP requests. Please try again later"
            }.ToFrozenDictionary(),

            ["uk-UA"] = new Dictionary<string, string>
            {
                ["verification_flow_conflict_resolved_to_existing"] =
                    "Знайдено активну сесію; будь ласка, продовжуйте.",
                ["verification_flow_conflict_unresolved"] = "Конфлікт сесій; будь ласка, спробуйте ще раз.",
                ["verification_flow_reused_and_updated"] = "Існуючу сесію оновлено; будь ласка, продовжуйте.",
                ["verification_flow_conflict"] = "Активна сесія існує, завершіть або скасуйте її.",
                ["flow_expired"] = "Сесія закінчилася, почніть нову.",
                ["verification_flow_not_found"] = "Сесію не знайдено, почніть знову.",
                ["verification_flow_not_verified"] = "Сесію не підтверджено; будь ласка, завершіть перевірку.",
                ["verification_session_not_found"] = "Дані для перевірки не знайдено; будь ласка, повторіть спробу.",
                ["otp_invalid"] = "Неправильний OTP; спробуйте ще раз.",
                ["otp_expired"] = "OTP закінчився; запросіть новий.",
                ["otp_generation_failed"] = "Не вдалося згенерувати OTP; спробуйте ще раз.",
                ["otp_max_attempts_reached"] = "Забагато спроб OTP; зачекайте або зв'яжіться з підтримкою.",
                ["otp_not_verified"] = "OTP не підтверджено; будь ласка, введіть код.",
                ["phone_invalid"] = "Неправильний номер телефону; будь ласка, перевірте.",
                ["sms_send_failed"] = "SMS не вдалося; перевірте номер або повторіть спробу.",
                ["data_concurrency_conflict"] = "Дані оновлено; оновіть і повторіть спробу.",
                ["data_access_failed"] = "Проблема з доступом до даних; спробуйте пізніше.",
                ["security_rate_limit_exceeded"] = "Забагато спроб верифікації. Спробуйте знову через 30-60 хвилин.",
                ["security_suspicious_activity"] = "Виявлено незвичайну активність; доступ обмежено.",
                ["membership_too_many_attempts"] =
                    "Забагато спроб членства; зачекайте {0} хв або зв'яжіться з підтримкою.",
                ["signin_too_many_attempts"] = "Забагато спроб входу; зачекайте {0} хв або зв'яжіться з підтримкою.",
                ["activity_status_invalid"] = "Неправильний статус активності.",
                ["app_device_created_but_invalid_id"] =
                    "Пристрій зареєстровано, але проблема з ID; зв'яжіться з підтримкою.",
                ["app_device_invalid_id"] = "Неправильний ID пристрою застосунку.",
                ["associated"] = "Номер телефону успішно пов'язано.",
                ["phone_cannot_be_empty"] = "Номер телефону не може бути пустим.",
                ["created_and_associated"] = "Номер телефону створено і пов'язано.",
                ["exists"] = "Номер телефону вже існує.",
                ["phone_number_not_found"] = "Номер телефону не знайдено для входу.",
                ["phone_not_found"] = "Номер телефону не знайдено.",
                ["validation_failed"] = "Помилки форми; перевірте виділені поля.",
                ["invalid_credentials"] = "Неправильне ім'я користувача або пароль.",
                ["password_complexity_requirements"] =
                    "Пароль повинен містити {0}+ символів з великими, малими літерами, цифрами, спецсимволами.",
                ["password_empty"] = "Пароль обов'язковий.",
                ["password_hash_error"] = "Помилка обробки пароля; повторіть спробу.",
                ["password_hash_input_empty"] = "Обробка пароля не вдалася; повторіть спробу.",
                ["password_invalid_chars"] = "Неправильні символи в паролі.",
                ["password_config_hash_algorithm_unsupported"] =
                    "Помилка налаштування пароля; зв'яжіться з підтримкою.",
                ["password_config_iterations_invalid"] = "Проблема налаштування пароля; зв'яжіться з підтримкою.",
                ["password_config_salt_size_invalid"] = "Проблема конфігурації пароля; зв'яжіться з підтримкою.",
                ["password_missing_digit"] = "Додайте цифру.",
                ["password_missing_lowercase"] = "Додайте малу літеру.",
                ["password_missing_special_char"] = "Додайте спецсимвол.",
                ["password_missing_uppercase"] = "Додайте велику літеру.",
                ["password_too_short"] = "Пароль занадто короткий; мін {0} символів.",
                ["password_verify_base64_error"] = "Помилка перевірки; повторіть спробу.",
                ["password_verify_error"] = "Перевірка не вдалася; повторіть спробу.",
                ["password_verify_hash_size_mismatch"] = "Невідповідність перевірки; повторіть спробу.",
                ["password_verify_input_empty"] = "Перевірка не вдалася; повторіть спробу.",
                ["password_verify_invalid_format"] = "Помилка формату при перевірці; повторіть спробу.",
                ["password_verify_mismatch"] = "Неправильний пароль.",
                ["password_verify_salt_size_mismatch"] = "Невідповідність перевірки; повторіть спробу.",
                ["password_verify_stored_hash_empty"] = "Проблема перевірки; повторіть спробу.",
                ["inactive_membership"] = "Членство неактивне.",
                ["invalid_secure_key"] = "Надано неправильний безпечний ключ.",
                ["membership_already_exists"] = "Членство вже існує.",
                ["membership_not_found"] = "Членство не знайдено.",
                ["secure_key_cannot_be_empty"] = "Безпечний ключ не може бути пустим.",
                ["secure_key_not_set"] = "Безпечний ключ не налаштовано для цього членства.",
                ["secure_key_too_long"] = "Безпечний ключ занадто довгий.",
                ["secure_key_updated"] = "Безпечний ключ успішно оновлено.",
                ["created"] = "Успішно створено.",
                ["generic_error"] = "Неочікувана помилка; спробуйте пізніше.",
                ["generic_no_result_returned"] = "Результат не повернуто; спробуйте ще раз.",
                ["generic_success"] = "Операція успішна.",
                ["generic_unexpected_outcome"] = "Сталася неочікувана подія; спробуйте ще раз.",
                ["phone_parsing_invalid_country_code"] = "Неправильний код країни в номері телефону.",
                ["phone_parsing_too_short"] = "Номер телефону занадто короткий.",
                ["phone_parsing_too_long"] = "Номер телефону занадто довгий.",
                ["phone_parsing_invalid_number"] = "Формат номера телефону неправильний.",
                ["phone_parsing_possible_but_local_only"] =
                    "Номер може бути дійсним локально; додайте код країни або регіон.",
                ["phone_parsing_generic_error"] = "Помилка аналізу номера телефону.",
                ["phone_validation_unexpected_error"] = "Неочікувана помилка при валідації номера телефону.",
                ["authentication_code_is"] = "Ваш код перевірки",
                ["resend_cooldown_active"] = "Будь ласка, зачекайте хвилинку перед запитом нового коду",
                ["max_otp_attempts_reached"] =
                    "Ви досягли максимальної кількості запитів OTP. Будь ласка, спробуйте пізніше"
            }.ToFrozenDictionary()
        }.ToFrozenDictionary();

    public string Localize(string key, string cultureName)
    {
        string normalizedCulture = NormalizeCultureName(cultureName);

        if (Resources.TryGetValue(normalizedCulture, out FrozenDictionary<string, string>? cultureResources) &&
            cultureResources.TryGetValue(key, out string? localizedString))
        {
            return localizedString;
        }

        if (Resources.TryGetValue("en-US", out FrozenDictionary<string, string>? defaultResources) &&
            defaultResources.TryGetValue(key, out string? defaultString))
        {
            return defaultString;
        }

        return key;
    }

    public string Localize(string key)
    {
        return Localize(key, _defaultSystemCultureInfo.Name);
    }

    private static string NormalizeCultureName(string cultureName)
    {
        return cultureName.ToLowerInvariant() switch
        {
            "en" or "en-us" or "english" => "en-US",
            "uk" or "uk-ua" or "ukrainian" => "uk-UA",
            _ => "en-US"
        };
    }
}
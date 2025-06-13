using Ecliptix.Domain.Memberships.Failures;
using Ecliptix.Domain.Utilities;
using PhoneNumbers;

namespace Ecliptix.Domain.Memberships.PhoneNumberValidation;

public class PhoneNumberValidator(ILocalizationProvider localizationProvider) : IPhoneNumberValidator
{
    private readonly PhoneNumberUtil _phoneNumberUtil = PhoneNumberUtil.GetInstance();

    public Result<PhoneNumberValidationResult, VerificationFlowFailure> ValidatePhoneNumber(
        string phoneNumber, string cultureName, string? defaultRegion = null)
    {
        if (string.IsNullOrWhiteSpace(phoneNumber))
        {
            string message = localizationProvider.Localize(VerificationFlowMessageKeys.PhoneNumberEmpty, cultureName);
            return Result<PhoneNumberValidationResult, VerificationFlowFailure>.Err(
                VerificationFlowFailure.PhoneNumberInvalid(message)
            );
        }

        if (!string.IsNullOrEmpty(defaultRegion) &&
            !_phoneNumberUtil.GetSupportedRegions().Contains(defaultRegion))
        {
            string message =
                localizationProvider.Localize(VerificationFlowMessageKeys.InvalidDefaultRegion, cultureName);
            return Result<PhoneNumberValidationResult, VerificationFlowFailure>.Err(
                VerificationFlowFailure.Generic(message)
            );
        }

        return ParsePhoneNumber(phoneNumber, cultureName, defaultRegion)
            .Bind(parsedNumberDetails =>
                ValidateLibPhoneNumber(parsedNumberDetails.PhoneNumber, parsedNumberDetails.E164Format, cultureName))
            .MapErr(failure => failure);
    }

    private Result<ParsedNumberDetails, VerificationFlowFailure> ParsePhoneNumber(
        string phoneNumberStr, string cultureName, string? defaultRegion)
    {
        return Result<ParsedNumberDetails, VerificationFlowFailure>.Try(() =>
        {
            PhoneNumber parsedPhoneNumber = _phoneNumberUtil.Parse(phoneNumberStr, defaultRegion);
            string e164Format = _phoneNumberUtil.Format(parsedPhoneNumber, PhoneNumberFormat.E164);
            return new ParsedNumberDetails(parsedPhoneNumber, e164Format);
        }, ex =>
        {
            if (ex is NumberParseException npe)
            {
                string errorKey = npe.ErrorType switch
                {
                    ErrorType.INVALID_COUNTRY_CODE => VerificationFlowMessageKeys.PhoneParsingInvalidCountryCode,
                    ErrorType.NOT_A_NUMBER => VerificationFlowMessageKeys.PhoneParsingInvalidNumber,
                    ErrorType.TOO_SHORT_AFTER_IDD => VerificationFlowMessageKeys.PhoneParsingTooShort,
                    ErrorType.TOO_SHORT_NSN => VerificationFlowMessageKeys.PhoneParsingTooShort,
                    ErrorType.TOO_LONG => VerificationFlowMessageKeys.PhoneParsingTooLong,
                    _ => VerificationFlowMessageKeys.PhoneParsingGenericError
                };

                string message = localizationProvider.Localize(errorKey, cultureName);
                return VerificationFlowFailure.PhoneNumberInvalid(message, npe);
            }

            string genericMessage =
                localizationProvider.Localize(VerificationFlowMessageKeys.PhoneParsingGenericError, cultureName);
            return VerificationFlowFailure.Generic(genericMessage, ex);
        });
    }

    private Result<PhoneNumberValidationResult, VerificationFlowFailure> ValidateLibPhoneNumber(
        PhoneNumber parsedPhoneNumber, string e164Format, string cultureName)
    {
        return Result<PhoneNumberValidationResult, VerificationFlowFailure>.Try(() =>
        {
            if (!_phoneNumberUtil.IsValidNumber(parsedPhoneNumber))
            {
                PhoneNumberUtil.ValidationResult possibility =
                    _phoneNumberUtil.IsPossibleNumberWithReason(parsedPhoneNumber);
                ValidationFailureReason internalReason = MapLibValidationReasonToInternalReason(possibility);

                string messageKey = MapLibValidationReasonToMessageKey(possibility);
                string message = localizationProvider.Localize(messageKey, cultureName);

                return PhoneNumberValidationResult.CreateInvalid(message, internalReason, e164Format);
            }

            PhoneNumberType libType = _phoneNumberUtil.GetNumberType(parsedPhoneNumber);
            MobileCheckStatus mobileStatus = DetermineMobileStatus(libType);
            string? detectedRegion = _phoneNumberUtil.GetRegionCodeForNumber(parsedPhoneNumber);
            return new PhoneNumberValidationResult(e164Format, detectedRegion ?? "Unknown", mobileStatus);
        }, ex =>
        {
            string message = localizationProvider.Localize(VerificationFlowMessageKeys.PhoneValidationUnexpectedError,
                cultureName);
            return VerificationFlowFailure.Generic(message, ex);
        });
    }

    private static MobileCheckStatus DetermineMobileStatus(PhoneNumberType libType)
    {
        return libType is PhoneNumberType.MOBILE or PhoneNumberType.FIXED_LINE_OR_MOBILE
            ? MobileCheckStatus.IsMobile
            : MobileCheckStatus.IsNotMobile;
    }

    private static ValidationFailureReason MapLibValidationReasonToInternalReason(
        PhoneNumberUtil.ValidationResult libReason)
    {
        return libReason switch
        {
            PhoneNumberUtil.ValidationResult.INVALID_COUNTRY_CODE => ValidationFailureReason.InvalidCountryCode,
            PhoneNumberUtil.ValidationResult.TOO_SHORT => ValidationFailureReason.TooShort,
            PhoneNumberUtil.ValidationResult.TOO_LONG => ValidationFailureReason.TooLong,
            PhoneNumberUtil.ValidationResult.IS_POSSIBLE_LOCAL_ONLY => ValidationFailureReason.PossibleButNotCertain,
            _ => ValidationFailureReason.InvalidNumber
        };
    }

    private static string MapLibValidationReasonToMessageKey(PhoneNumberUtil.ValidationResult libReason)
    {
        return libReason switch
        {
            PhoneNumberUtil.ValidationResult.INVALID_COUNTRY_CODE => VerificationFlowMessageKeys
                .PhoneParsingInvalidCountryCode,
            PhoneNumberUtil.ValidationResult.TOO_SHORT => VerificationFlowMessageKeys.PhoneParsingTooShort,
            PhoneNumberUtil.ValidationResult.TOO_LONG => VerificationFlowMessageKeys.PhoneParsingTooLong,
            PhoneNumberUtil.ValidationResult.IS_POSSIBLE_LOCAL_ONLY => VerificationFlowMessageKeys
                .PhoneParsingPossibleButLocalOnly,
            _ => VerificationFlowMessageKeys.PhoneParsingInvalidNumber
        };
    }

    private record ParsedNumberDetails(PhoneNumber PhoneNumber, string E164Format);
}
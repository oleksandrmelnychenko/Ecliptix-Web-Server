using Ecliptix.Domain.Memberships.Failures;
using Ecliptix.Utilities;
using PhoneNumbers;

namespace Ecliptix.Domain.Memberships.MobileNumberValidation;

public class MobileNumberValidator(ILocalizationProvider localizationProvider) : IMobileNumberValidator
{
    private readonly PhoneNumberUtil _phoneNumberUtil = PhoneNumberUtil.GetInstance();

    public Result<MobileNumberValidationResult, VerificationFlowFailure> ValidateMobileNumber(
        string mobileNumber, string cultureName, string? defaultRegion = null)
    {
        if (string.IsNullOrWhiteSpace(mobileNumber))
        {
            string message = localizationProvider.Localize(VerificationFlowMessageKeys.MobileNumberEmpty, cultureName);
            return Result<MobileNumberValidationResult, VerificationFlowFailure>.Err(
                VerificationFlowFailure.MobileNumberInvalid(message)
            );
        }

        if (!string.IsNullOrEmpty(defaultRegion) &&
            !_phoneNumberUtil.GetSupportedRegions().Contains(defaultRegion))
        {
            string message =
                localizationProvider.Localize(VerificationFlowMessageKeys.InvalidDefaultRegion, cultureName);
            return Result<MobileNumberValidationResult, VerificationFlowFailure>.Err(
                VerificationFlowFailure.Generic(message)
            );
        }

        return ParseMobileNumber(mobileNumber, cultureName, defaultRegion)
            .Bind(parsedNumberDetails =>
                ValidateLibPhoneNumber(parsedNumberDetails.MobileNumber, parsedNumberDetails.E164Format, cultureName))
            .MapErr(failure => failure);
    }

    private Result<ParsedNumberDetails, VerificationFlowFailure> ParseMobileNumber(
        string mobileNumberStr, string cultureName, string? defaultRegion)
    {
        return Result<ParsedNumberDetails, VerificationFlowFailure>.Try(() =>
        {
            PhoneNumber parsedMobileNumber = _phoneNumberUtil.Parse(mobileNumberStr, defaultRegion);
            string e164Format = _phoneNumberUtil.Format(parsedMobileNumber, PhoneNumberFormat.E164);
            return new ParsedNumberDetails(parsedMobileNumber, e164Format);
        }, ex =>
        {
            if (ex is NumberParseException npe)
            {
                string errorKey = npe.ErrorType switch
                {
                    ErrorType.INVALID_COUNTRY_CODE => VerificationFlowMessageKeys.MobileParsingInvalidCountryCode,
                    ErrorType.NOT_A_NUMBER => VerificationFlowMessageKeys.MobileParsingInvalidNumber,
                    ErrorType.TOO_SHORT_AFTER_IDD => VerificationFlowMessageKeys.MobileParsingTooShort,
                    ErrorType.TOO_SHORT_NSN => VerificationFlowMessageKeys.MobileParsingTooShort,
                    ErrorType.TOO_LONG => VerificationFlowMessageKeys.MobileParsingTooLong,
                    _ => VerificationFlowMessageKeys.MobileParsingGenericError
                };

                string message = localizationProvider.Localize(errorKey, cultureName);
                return VerificationFlowFailure.MobileNumberInvalid(message, npe);
            }

            string genericMessage =
                localizationProvider.Localize(VerificationFlowMessageKeys.MobileParsingGenericError, cultureName);
            return VerificationFlowFailure.Generic(genericMessage, ex);
        });
    }

    private Result<MobileNumberValidationResult, VerificationFlowFailure> ValidateLibPhoneNumber(
        PhoneNumber parsedMobileNumber, string e164Format, string cultureName)
    {
        return Result<MobileNumberValidationResult, VerificationFlowFailure>.Try(() =>
        {
            if (!_phoneNumberUtil.IsValidNumber(parsedMobileNumber))
            {
                PhoneNumberUtil.ValidationResult possibility =
                    _phoneNumberUtil.IsPossibleNumberWithReason(parsedMobileNumber);
                ValidationFailureReason internalReason = MapLibValidationReasonToInternalReason(possibility);

                string messageKey = MapLibValidationReasonToMessageKey(possibility);
                string message = localizationProvider.Localize(messageKey, cultureName);

                return MobileNumberValidationResult.CreateInvalid(
                    message,
                    internalReason,
                    Option<string>.Some(e164Format),
                    Option<object[]>.None);
            }

            PhoneNumberType libType = _phoneNumberUtil.GetNumberType(parsedMobileNumber);
            MobileCheckStatus mobileStatus = DetermineMobileStatus(libType);
            string? detectedRegion = _phoneNumberUtil.GetRegionCodeForNumber(parsedMobileNumber);
            return new MobileNumberValidationResult(e164Format, detectedRegion ?? "Unknown", mobileStatus);
        }, ex =>
        {
            string message = localizationProvider.Localize(VerificationFlowMessageKeys.MobileValidationUnexpectedError,
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
                .MobileParsingInvalidCountryCode,
            PhoneNumberUtil.ValidationResult.TOO_SHORT => VerificationFlowMessageKeys.MobileParsingTooShort,
            PhoneNumberUtil.ValidationResult.TOO_LONG => VerificationFlowMessageKeys.MobileParsingTooLong,
            PhoneNumberUtil.ValidationResult.IS_POSSIBLE_LOCAL_ONLY => VerificationFlowMessageKeys
                .MobileParsingPossibleButLocalOnly,
            _ => VerificationFlowMessageKeys.MobileParsingInvalidNumber
        };
    }

    private record ParsedNumberDetails(PhoneNumber MobileNumber, string E164Format);
}

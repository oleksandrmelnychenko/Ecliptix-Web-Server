using Akka.Actor;
using Ecliptix.Domain.Memberships.Failures;
using Ecliptix.Domain.Utilities;
using PhoneNumbers;

namespace Ecliptix.Domain.Memberships;

public record ValidatePhoneNumberActorEvent(string PhoneNumber, string? DefaultRegion = null);

public enum MobileCheckStatus
{
    IsMobile,
    IsNotMobile
}

public record PhoneNumberValidationResult
{
    public bool IsValid { get; init; }
    public string? ParsedPhoneNumberE164 { get; init; }
    public string? DetectedRegion { get; init; }
    public MobileCheckStatus MobileStatus { get; init; }
    public string? ErrorMessage { get; init; }
    public ValidationFailureReason? FailureReason { get; init; }

    public PhoneNumberValidationResult(
        string parsedPhoneNumberE164,
        string detectedRegion,
        MobileCheckStatus mobileStatus,
        bool isValidNumber)
    {
        IsValid = isValidNumber;
        ParsedPhoneNumberE164 = parsedPhoneNumberE164;
        DetectedRegion = detectedRegion;
        MobileStatus = mobileStatus;
    }

    public PhoneNumberValidationResult(
        string? errorMessage,
        ValidationFailureReason? failureReason = null,
        string? parsedNumberIfAvailable = null)
    {
        IsValid = false;
        ErrorMessage = errorMessage;
        FailureReason = failureReason;
        ParsedPhoneNumberE164 = parsedNumberIfAvailable;
        MobileStatus = MobileCheckStatus.IsNotMobile;
    }
}

public enum ValidationFailureReason
{
    ParsingFailed,
    InvalidNumber,
    InvalidCountryCode,
    TooShort,
    TooLong,
    InvalidForRegion,
    PossibleButNotCertain,
    InternalError
}

public class PhoneNumberValidatorActor : ReceiveActor
{
    private readonly PhoneNumberUtil _phoneNumberUtil = PhoneNumberUtil.GetInstance();

    public PhoneNumberValidatorActor()
    {
        Receive<ValidatePhoneNumberActorEvent>(HandleValidatePhoneNumber);
    }

    private void HandleValidatePhoneNumber(ValidatePhoneNumberActorEvent actorEvent)
    {
        string originalPhoneNumberStr = actorEvent.PhoneNumber;
        PhoneNumber parsedPhoneNumber;
        string e164FormatKey;

        try
        {
            string? regionToParseWith = actorEvent.DefaultRegion;
            if (string.IsNullOrEmpty(regionToParseWith) && originalPhoneNumberStr.StartsWith($"+"))
            {
                regionToParseWith = "ZZ";
            }

            parsedPhoneNumber = _phoneNumberUtil.Parse(originalPhoneNumberStr, regionToParseWith);
            e164FormatKey = _phoneNumberUtil.Format(parsedPhoneNumber, PhoneNumberFormat.E164);
        }
        catch (NumberParseException ex)
        {
            Sender.Tell(Result<PhoneNumberValidationResult, VerificationFlowFailure>.Err(
                VerificationFlowFailure.Generic($"Failed to parse phone number: {ex.ErrorType}", ex)));
            return;
        }

        try
        {
            PhoneNumberValidationResult result;
            bool isLibValidNumber = _phoneNumberUtil.IsValidNumber(parsedPhoneNumber);

            if (!isLibValidNumber)
            {
                PhoneNumberUtil.ValidationResult possibility =
                    _phoneNumberUtil.IsPossibleNumberWithReason(parsedPhoneNumber);
                ValidationFailureReason failureReason = MapPossibilityToFailureReason(possibility);
                string errorMessage = $"Invalid number. Reason: {possibility}";

                if (possibility == PhoneNumberUtil.ValidationResult.IS_POSSIBLE_LOCAL_ONLY &&
                    actorEvent.DefaultRegion == null && !originalPhoneNumberStr.StartsWith("+"))
                {
                    errorMessage += ". Consider providing a DefaultRegion if this is a local number.";
                }

                result = new PhoneNumberValidationResult(errorMessage, failureReason, e164FormatKey);
            }
            else
            {
                PhoneNumberType libType = _phoneNumberUtil.GetNumberType(parsedPhoneNumber);
                MobileCheckStatus mobileStatus = DetermineMobileStatus(libType);
                string? detectedRegion = _phoneNumberUtil.GetRegionCodeForNumber(parsedPhoneNumber);
                result = new PhoneNumberValidationResult(e164FormatKey, detectedRegion ?? "Unknown", mobileStatus,
                    true);
            }

            Sender.Tell(Result<PhoneNumberValidationResult, VerificationFlowFailure>.Ok(result));
        }
        catch (Exception ex)
        {
            Sender.Tell(Result<PhoneNumberValidationResult, VerificationFlowFailure>.Err(
                VerificationFlowFailure.Generic("An unexpected error occurred during phone number validation.", ex)));
        }
    }

    private static MobileCheckStatus DetermineMobileStatus(PhoneNumberType libType) =>
        libType is PhoneNumberType.MOBILE or PhoneNumberType.FIXED_LINE_OR_MOBILE
            ? MobileCheckStatus.IsMobile
            : MobileCheckStatus.IsNotMobile;

    private ValidationFailureReason MapPossibilityToFailureReason(PhoneNumberUtil.ValidationResult possibility)
    {
        return possibility switch
        {
            PhoneNumberUtil.ValidationResult.INVALID_COUNTRY_CODE => ValidationFailureReason.InvalidCountryCode,
            PhoneNumberUtil.ValidationResult.TOO_SHORT => ValidationFailureReason.TooShort,
            PhoneNumberUtil.ValidationResult.TOO_LONG => ValidationFailureReason.TooLong,
            PhoneNumberUtil.ValidationResult.IS_POSSIBLE_LOCAL_ONLY =>
                ValidationFailureReason.PossibleButNotCertain,
            _ => ValidationFailureReason.InvalidNumber
        };
    }

    public static Props Build() =>
        Props.Create(() => new PhoneNumberValidatorActor());
}
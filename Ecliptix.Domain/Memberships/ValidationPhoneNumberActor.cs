using Akka.Actor;
using Ecliptix.Domain.Memberships.Failures;
using Ecliptix.Domain.Utilities;
using PhoneNumbers;

namespace Ecliptix.Domain.Memberships;

public record ValidatePhoneNumberActorEvent(string PhoneNumber, string PeerCulture, string? DefaultRegion = null);

public enum MobileCheckStatus
{
    IsMobile,
    IsNotMobile
}

public record PhoneNumberValidationResult
{
    public bool IsValid { get; }
    public string? ParsedPhoneNumberE164 { get; }
    public string? DetectedRegion { get; }
    public MobileCheckStatus MobileStatus { get; }
    public string? MessageKey { get; }
    public object[]? MessageArgs { get; }
    public ValidationFailureReason? LibFailureReason { get; }

    public PhoneNumberValidationResult(
        string parsedPhoneNumberE164,
        string detectedRegion,
        MobileCheckStatus mobileStatus)
    {
        IsValid = true;
        ParsedPhoneNumberE164 = parsedPhoneNumberE164;
        DetectedRegion = detectedRegion;
        MobileStatus = mobileStatus;
    }

    private PhoneNumberValidationResult(
        string messageKey,
        ValidationFailureReason? libFailureReason,
        string? parsedNumberIfAvailable = null,
        object[]? messageArgs = null)
    {
        IsValid = false;
        MessageKey = messageKey;
        LibFailureReason = libFailureReason;
        ParsedPhoneNumberE164 = parsedNumberIfAvailable;
        MobileStatus = MobileCheckStatus.IsNotMobile;
        MessageArgs = messageArgs;
    }

    public static PhoneNumberValidationResult CreateInvalid(
        string messageKey,
        ValidationFailureReason libFailureReason,
        string? parsedNumberIfAvailable = null,
        object[]? messageArgs = null)
    {
        return new PhoneNumberValidationResult(messageKey, libFailureReason, parsedNumberIfAvailable, messageArgs);
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
    private readonly ILocalizationProvider _localizationProvider;

    private readonly PhoneNumberUtil _phoneNumberUtil = PhoneNumberUtil.GetInstance();

    public PhoneNumberValidatorActor(ILocalizationProvider localizationProvider)
    {
        _localizationProvider = localizationProvider;
        Receive<ValidatePhoneNumberActorEvent>(actorEvent =>
        {
            Result<PhoneNumberValidationResult, VerificationFlowFailure> result =
                HandleValidatePhoneNumberFunctional(actorEvent);
            Sender.Tell(result);
        });
    }

    private Result<PhoneNumberValidationResult, VerificationFlowFailure> HandleValidatePhoneNumberFunctional(
        ValidatePhoneNumberActorEvent actorEvent)
    {
        if (string.IsNullOrWhiteSpace(actorEvent.PhoneNumber))
        {
            _localizationProvider.Localize(VerificationFlowMessageKeys.PhoneNumberEmpty, actorEvent.PeerCulture);

            return Result<PhoneNumberValidationResult, VerificationFlowFailure>.Err(
                VerificationFlowFailure.PhoneNumberInvalid(VerificationFlowMessageKeys.PhoneNumberEmpty, null)
            );
        }

        if (!string.IsNullOrEmpty(actorEvent.DefaultRegion) &&
            !_phoneNumberUtil.GetSupportedRegions().Contains(actorEvent.DefaultRegion))
        {
            return Result<PhoneNumberValidationResult, VerificationFlowFailure>.Err(
                VerificationFlowFailure.Generic("Invalid default region provided", null)
            );
        }

        return ParsePhoneNumber(actorEvent.PhoneNumber, actorEvent.PeerCulture, actorEvent.DefaultRegion)
            .Bind(parsedNumberDetails =>
                ValidateLibPhoneNumber(parsedNumberDetails.PhoneNumber, parsedNumberDetails.E164Format,
                    actorEvent.PeerCulture))
            .MapErr(failure => failure);
    }

    private record ParsedNumberDetails(PhoneNumber PhoneNumber, string E164Format);

    private Result<ParsedNumberDetails, VerificationFlowFailure> ParsePhoneNumber(string phoneNumberStr,
        string peerCulture,
        string? defaultRegion)
    {
        return Result<ParsedNumberDetails, VerificationFlowFailure>.Try(() =>
            {
                PhoneNumber parsedPhoneNumber = _phoneNumberUtil.Parse(phoneNumberStr, defaultRegion);
                string e164Format = _phoneNumberUtil.Format(parsedPhoneNumber, PhoneNumberFormat.E164);
                return new ParsedNumberDetails(parsedPhoneNumber, e164Format);
            },
            errorMapper: ex =>
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

                    string message = _localizationProvider.Localize(errorKey, peerCulture);
                    return VerificationFlowFailure.PhoneNumberInvalid(message, npe);
                }

                return VerificationFlowFailure.Generic(VerificationFlowMessageKeys.PhoneParsingGenericError, ex);
            });
    }

    private Result<PhoneNumberValidationResult, VerificationFlowFailure> ValidateLibPhoneNumber(
        PhoneNumber parsedPhoneNumber,
        string e164Format, string peerCulture)
    {
        return Result<PhoneNumberValidationResult, VerificationFlowFailure>.Try(() =>
            {
                if (!_phoneNumberUtil.IsValidNumber(parsedPhoneNumber))
                {
                    PhoneNumberUtil.ValidationResult possibility =
                        _phoneNumberUtil.IsPossibleNumberWithReason(parsedPhoneNumber);
                    ValidationFailureReason internalReason = MapLibValidationReasonToInternalReason(possibility);

                    string messageKey = MapLibValidationReasonToMessageKey(possibility);
                    string message = _localizationProvider.Localize(messageKey, peerCulture);

                    return PhoneNumberValidationResult.CreateInvalid(message, internalReason, e164Format);
                }

                PhoneNumberType libType = _phoneNumberUtil.GetNumberType(parsedPhoneNumber);
                MobileCheckStatus mobileStatus = DetermineMobileStatus(libType);
                string? detectedRegion = _phoneNumberUtil.GetRegionCodeForNumber(parsedPhoneNumber);
                return new PhoneNumberValidationResult(e164Format, detectedRegion ?? "Unknown", mobileStatus);
            },
            errorMapper: ex =>
                VerificationFlowFailure.Generic(VerificationFlowMessageKeys.PhoneValidationUnexpectedError, ex)
        );
    }

    private static MobileCheckStatus DetermineMobileStatus(PhoneNumberType libType) =>
        libType is PhoneNumberType.MOBILE or PhoneNumberType.FIXED_LINE_OR_MOBILE
            ? MobileCheckStatus.IsMobile
            : MobileCheckStatus.IsNotMobile;

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

    public static Props Build(ILocalizationProvider localizationProvider) =>
        Props.Create(() => new PhoneNumberValidatorActor(localizationProvider));
}
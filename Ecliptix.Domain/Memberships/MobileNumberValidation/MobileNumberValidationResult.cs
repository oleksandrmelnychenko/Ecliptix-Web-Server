using Ecliptix.Utilities;

namespace Ecliptix.Domain.Memberships.MobileNumberValidation;

public record MobileNumberValidationResult
{
    public MobileNumberValidationResult(
        string parsedMobileNumberE164,
        string detectedRegion,
        MobileCheckStatus mobileStatus)
    {
        IsValid = true;
        ParsedMobileNumberE164 = Option<string>.Some(parsedMobileNumberE164);
        DetectedRegion = Option<string>.Some(detectedRegion);
        MobileStatus = mobileStatus;
        MessageKey = Option<string>.None;
        MessageArgs = Option<object[]>.None;
        LibFailureReason = Option<ValidationFailureReason>.None;
    }

    private MobileNumberValidationResult(
        string messageKey,
        Option<ValidationFailureReason> libFailureReason,
        Option<string> parsedNumberIfAvailable,
        Option<object[]> messageArgs)
    {
        IsValid = false;
        MessageKey = Option<string>.Some(messageKey);
        LibFailureReason = libFailureReason;
        ParsedMobileNumberE164 = parsedNumberIfAvailable;
        MobileStatus = MobileCheckStatus.IsNotMobile;
        MessageArgs = messageArgs;
        DetectedRegion = Option<string>.None;
    }

    public bool IsValid { get; }
    public Option<string> ParsedMobileNumberE164 { get; }
    public Option<string> DetectedRegion { get; }
    public MobileCheckStatus MobileStatus { get; }
    public Option<string> MessageKey { get; }
    public Option<object[]> MessageArgs { get; }
    public Option<ValidationFailureReason> LibFailureReason { get; }

    public static MobileNumberValidationResult CreateInvalid(
        string messageKey,
        ValidationFailureReason libFailureReason,
        Option<string> parsedNumberIfAvailable,
        Option<object[]> messageArgs)
    {
        return new MobileNumberValidationResult(
            messageKey,
            Option<ValidationFailureReason>.Some(libFailureReason),
            parsedNumberIfAvailable,
            messageArgs);
    }
}
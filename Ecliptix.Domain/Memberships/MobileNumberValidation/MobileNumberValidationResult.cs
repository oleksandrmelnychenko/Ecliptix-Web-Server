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
        LocalizedMessage = Option<string>.None;
    }

    private MobileNumberValidationResult(
        string localizedMessage,
        Option<ValidationFailureReason> libFailureReason,
        Option<string> parsedNumberIfAvailable,
        Option<object[]> messageArgs)
    {
        IsValid = false;
        LocalizedMessage = Option<string>.Some(localizedMessage);
        ParsedMobileNumberE164 = parsedNumberIfAvailable;
        DetectedRegion = Option<string>.None;
    }

    public bool IsValid { get; }
    public Option<string> ParsedMobileNumberE164 { get; }
    public Option<string> DetectedRegion { get; }
    public Option<string> LocalizedMessage { get; }

    public static MobileNumberValidationResult CreateInvalid(
        string localizedMessage,
        ValidationFailureReason libFailureReason,
        Option<string> parsedNumberIfAvailable,
        Option<object[]> messageArgs)
    {
        return new MobileNumberValidationResult(
            localizedMessage,
            Option<ValidationFailureReason>.Some(libFailureReason),
            parsedNumberIfAvailable,
            messageArgs);
    }
}

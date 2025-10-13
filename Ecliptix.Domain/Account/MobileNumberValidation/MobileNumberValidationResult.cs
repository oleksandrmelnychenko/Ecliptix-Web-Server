namespace Ecliptix.Domain.Memberships.MobileNumberValidation;

public record MobileNumberValidationResult
{
    public MobileNumberValidationResult(
        string parsedMobileNumberE164,
        string detectedRegion,
        MobileCheckStatus mobileStatus)
    {
        IsValid = true;
        ParsedMobileNumberE164 = parsedMobileNumberE164;
        DetectedRegion = detectedRegion;
        MobileStatus = mobileStatus;
    }

    private MobileNumberValidationResult(
        string messageKey,
        ValidationFailureReason? libFailureReason,
        string? parsedNumberIfAvailable = null,
        object[]? messageArgs = null)
    {
        IsValid = false;
        MessageKey = messageKey;
        LibFailureReason = libFailureReason;
        ParsedMobileNumberE164 = parsedNumberIfAvailable;
        MobileStatus = MobileCheckStatus.IsNotMobile;
        MessageArgs = messageArgs;
    }

    public bool IsValid { get; }
    public string? ParsedMobileNumberE164 { get; }
    public string? DetectedRegion { get; }
    public MobileCheckStatus MobileStatus { get; }
    public string? MessageKey { get; }
    public object[]? MessageArgs { get; }
    public ValidationFailureReason? LibFailureReason { get; }

    public static MobileNumberValidationResult CreateInvalid(
        string messageKey,
        ValidationFailureReason libFailureReason,
        string? parsedNumberIfAvailable = null,
        object[]? messageArgs = null)
    {
        return new MobileNumberValidationResult(messageKey, libFailureReason, parsedNumberIfAvailable, messageArgs);
    }
}
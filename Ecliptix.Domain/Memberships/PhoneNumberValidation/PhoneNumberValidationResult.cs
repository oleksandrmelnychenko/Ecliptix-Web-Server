namespace Ecliptix.Domain.Memberships.PhoneNumberValidation;

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
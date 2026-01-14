using Ecliptix.SharedKernel;

namespace Ecliptix.IdentityAccess.Domain.Memberships.MobileNumberValidation;

public record MobileNumberValidationResult
{
    public MobileNumberValidationResult(
        string parsedMobileNumberE164,
        string detectedRegion,
        MobileCheckStatus mobileStatus)
    {
        if (mobileStatus != MobileCheckStatus.IsMobile)
        {
            throw new ArgumentException("Mobile status must be IsMobile for valid results.", nameof(mobileStatus));
        }

        IsValid = true;
        ParsedMobileNumberE164 = Option<string>.Some(parsedMobileNumberE164);
        DetectedRegion = Option<string>.Some(detectedRegion);
        LocalizedMessage = Option<string>.None;
        FailureReason = Option<ValidationFailureReason>.None;
        MobileStatus = Option<MobileCheckStatus>.Some(mobileStatus);
        LocalizationKey = Option<string>.None;
        MessageArgs = Option<object[]>.None;
    }

    private MobileNumberValidationResult(
        string localizedMessage,
        ValidationFailureReason failureReason,
        Option<string> parsedNumberIfAvailable,
        Option<string> localizationKey,
        Option<object[]> messageArgs,
        Option<MobileCheckStatus> mobileStatus)
    {
        IsValid = false;
        LocalizedMessage = Option<string>.Some(localizedMessage);
        ParsedMobileNumberE164 = parsedNumberIfAvailable;
        DetectedRegion = Option<string>.None;
        FailureReason = Option<ValidationFailureReason>.Some(failureReason);
        MobileStatus = mobileStatus;
        LocalizationKey = localizationKey;
        MessageArgs = messageArgs;
    }

    public bool IsValid { get; }
    public Option<string> ParsedMobileNumberE164 { get; }
    public Option<string> DetectedRegion { get; }
    public Option<string> LocalizedMessage { get; }
    public Option<ValidationFailureReason> FailureReason { get; }
    public Option<MobileCheckStatus> MobileStatus { get; }
    public Option<string> LocalizationKey { get; }
    public Option<object[]> MessageArgs { get; }
    public bool IsMobile => MobileStatus.Match(status => status == MobileCheckStatus.IsMobile, () => false);

    public static MobileNumberValidationResult CreateInvalid(
        string localizedMessage,
        ValidationFailureReason failureReason,
        Option<string> parsedNumberIfAvailable,
        Option<object[]> messageArgs,
        Option<string> localizationKey,
        Option<MobileCheckStatus> mobileStatus)
    {
        return new MobileNumberValidationResult(
            localizedMessage,
            failureReason,
            parsedNumberIfAvailable,
            localizationKey,
            messageArgs,
            mobileStatus);
    }
}

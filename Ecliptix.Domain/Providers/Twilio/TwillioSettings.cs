namespace Ecliptix.Domain.Providers.Twilio;

public sealed record TwilioSettings {
    public string? AccountSid { get; init; }

    public string? AuthToken { get; init; }

    public string? MobileNumber { get; init; }

    public string? SmsCallBackUrl { get; init; }
}
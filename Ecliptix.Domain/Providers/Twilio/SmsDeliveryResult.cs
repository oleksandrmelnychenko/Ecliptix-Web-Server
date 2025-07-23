namespace Ecliptix.Domain.Providers.Twilio;

public record SmsDeliveryResult
{
    public bool IsSuccess { get; init; }
    public string? MessageId { get; init; }
    public string? ErrorMessage { get; init; }
    public SmsDeliveryStatus Status { get; init; }
}
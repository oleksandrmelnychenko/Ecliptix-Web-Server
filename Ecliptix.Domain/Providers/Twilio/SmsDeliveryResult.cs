using Ecliptix.Utilities;

namespace Ecliptix.Domain.Providers.Twilio;

public record SmsDeliveryResult
{
    public bool IsSuccess { get; init; }
    public Option<string> MessageId { get; init; }
    public Option<string> ErrorMessage { get; init; }
    public SmsDeliveryStatus Status { get; init; }
}

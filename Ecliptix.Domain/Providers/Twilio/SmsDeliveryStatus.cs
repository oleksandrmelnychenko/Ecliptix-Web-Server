namespace Ecliptix.Domain.Providers.Twilio;

public enum SmsDeliveryStatus
{
    Sent,
    Failed,
    Pending,
    Delivered,
    Undelivered
}
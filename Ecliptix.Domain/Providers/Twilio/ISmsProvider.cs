namespace Ecliptix.Domain.Providers.Twilio;

public interface ISmsProvider
{
    Task<SmsDeliveryResult> SendOtpAsync(string phoneNumber, string code, CancellationToken cancellationToken = default, string? callbackUrl = null);
}

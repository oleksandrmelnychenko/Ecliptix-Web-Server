using Twilio;
using Twilio.Rest.Api.V2010.Account;
using Twilio.Types;

namespace Ecliptix.Domain.Providers.Twilio;

public class TwilioSmsProvider : ISmsProvider
{
    private readonly TwilioSettings _settings;

    public TwilioSmsProvider(TwilioSettings settings)
    {
        _settings = settings;
        TwilioClient.Init(settings.AccountSid, settings.AuthToken);
    }

    public async Task<SmsDeliveryResult> SendSmsAsync(string phoneNumber, string message, string? callbackUrl = null)
    {
        try
        {
            MessageResource? messageResource = await MessageResource.CreateAsync(
                body: message,
                from: new PhoneNumber(_settings.MobileNumber),
                to: new PhoneNumber(phoneNumber),
                statusCallback: callbackUrl != null ? new Uri(callbackUrl, UriKind.Absolute) : null);

            return new SmsDeliveryResult
            {
                IsSuccess = true,
                MessageId = messageResource.Sid,
                Status = MapTwilioStatus(messageResource.Status)
            };
        }
        catch (Exception ex)
        {
            return new SmsDeliveryResult
            {
                IsSuccess = false,
                ErrorMessage = ex.Message,
                Status = SmsDeliveryStatus.Failed
            };
        }
    }

    public async Task<SmsDeliveryResult> SendOtpAsync(string phoneNumber, string code, string? callbackUrl = null)
    {
        string message = $"Your verification code is: {code}. This code will expire in 5 minutes.";
        return await SendSmsAsync(phoneNumber, message, callbackUrl);
    }

    private static SmsDeliveryStatus MapTwilioStatus(MessageResource.StatusEnum status)
    {
        if (status == MessageResource.StatusEnum.Queued || status == MessageResource.StatusEnum.Accepted || status == MessageResource.StatusEnum.Sending)
            return SmsDeliveryStatus.Pending;
        if (status == MessageResource.StatusEnum.Sent) return SmsDeliveryStatus.Sent;
        if (status == MessageResource.StatusEnum.Delivered) return SmsDeliveryStatus.Delivered;
        if (status == MessageResource.StatusEnum.Failed) return SmsDeliveryStatus.Failed;
        return status == MessageResource.StatusEnum.Undelivered ? SmsDeliveryStatus.Undelivered : SmsDeliveryStatus.Failed;
    }
}
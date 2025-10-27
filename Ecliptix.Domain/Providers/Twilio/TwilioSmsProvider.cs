using System.Threading;
using System.Threading.Tasks;
using Ecliptix.Utilities;
using Twilio;
using Twilio.Rest.Api.V2010.Account;
using Twilio.Types;

namespace Ecliptix.Domain.Providers.Twilio;

public sealed class TwilioSmsProvider : ISmsProvider
{
    private readonly TwilioSettings _settings;

    public TwilioSmsProvider(TwilioSettings settings)
    {
        _settings = settings;
        TwilioClient.Init(settings.AccountSid, settings.AuthToken);
    }

    public async Task<SmsDeliveryResult> SendSmsAsync(string phoneNumber, string message, string? callbackUrl = null, CancellationToken cancellationToken = default)
    {
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            await Task.Yield();
            return new SmsDeliveryResult
            {
                IsSuccess = true,
                MessageId = Option<string>.Some(Guid.NewGuid().ToString()),
                ErrorMessage = Option<string>.None,
                Status = MapTwilioStatus(MessageResource.StatusEnum.Sent)
            };
        }
        catch (Exception ex)
        {
            return new SmsDeliveryResult
            {
                IsSuccess = false,
                MessageId = Option<string>.None,
                ErrorMessage = Option<string>.Some(ex.Message),
                Status = SmsDeliveryStatus.Failed
            };
        }
    }

    public async Task<SmsDeliveryResult> SendOtpAsync(string phoneNumber, string code, CancellationToken cancellationToken = default, string? callbackUrl = null)
    {
        await Task.Yield();
        string message = $"Your verification code is: {code}. This code will expire in 5 minutes.";
        return await SendSmsAsync(phoneNumber, message, callbackUrl, cancellationToken);
    }

    private static SmsDeliveryStatus MapTwilioStatus(MessageResource.StatusEnum status)
    {
        if (status == MessageResource.StatusEnum.Queued || status == MessageResource.StatusEnum.Accepted || status == MessageResource.StatusEnum.Sending)
        {
            return SmsDeliveryStatus.Pending;
        }

        if (status == MessageResource.StatusEnum.Sent)
        {
            return SmsDeliveryStatus.Sent;
        }

        if (status == MessageResource.StatusEnum.Delivered)
        {
            return SmsDeliveryStatus.Delivered;
        }

        if (status == MessageResource.StatusEnum.Failed)
        {
            return SmsDeliveryStatus.Failed;
        }

        return status == MessageResource.StatusEnum.Undelivered ? SmsDeliveryStatus.Undelivered : SmsDeliveryStatus.Failed;
    }
}

using Amazon.Runtime;
using Ecliptix.Domain.Utilities;
using Polly;

namespace Ecliptix.Domain.Memberships;

public class SNSProvider
{
    public SNSProvider()
    {
    }

    public Task<Result<Unit, ShieldFailure>> SendSmsAsync(string mobile, string message)
    {
        /*// Prepare SNS request
        var request = new PublishRequest
        {
            Message = message,
            PhoneNumber = user.PhoneNumber
        };

        // Retry policy for transient SNS failures
        var retryPolicy = Policy
            .Handle<AmazonServiceException>()
            .WaitAndRetryAsync(3, attempt => TimeSpan.FromSeconds(Math.Pow(2, attempt)),
                (ex, time) => _logger.LogWarning("Retry SNS send for UserId: {UserId} after {Time}ms: {Error}", userId,
                    time.TotalMilliseconds, ex.Message));

        await retryPolicy.ExecuteAsync(async () =>
        {
            var response = await _snsClient.PublishAsync(request);
            _logger.LogInformation("OTP sent to {PhoneNumber}, MessageId: {MessageId}", user.PhoneNumber,
                response.MessageId);
        });*/

        return Task.FromResult(Result<Unit, ShieldFailure>.Ok(Unit.Value));
    }
}
using System.Data.Common;
using Ecliptix.Utilities;
using Microsoft.Data.SqlClient;
using Polly;
using Polly.Retry;
using Polly.Timeout;
using Polly.Wrap;
using Serilog;

namespace Ecliptix.Domain.Memberships.Persistors;

public static class PersistorRetryPolicy
{
    private static AsyncRetryPolicy CreateRetryPolicy(
        string operationName,
        int maxRetries = 3)
    {
        return Policy
            .Handle<DbException>(ShouldRetryDbException)
            .Or<TimeoutRejectedException>()
            .Or<TimeoutException>()
            .WaitAndRetryAsync(
                maxRetries,
                retryAttempt => TimeSpan.FromMilliseconds(Math.Pow(2, retryAttempt) * 200),
                onRetry: (exception, delay, retryCount, context) =>
                {
                    Log.Debug("Persistor operation '{OperationName}' retry {RetryCount}/{MaxRetries} after {Delay}ms due to {ExceptionType}",
                        operationName, retryCount, maxRetries, delay.TotalMilliseconds, exception.GetType().Name);
                });
    }

    private static AsyncTimeoutPolicy CreateTimeoutPolicy(
        string operationName,
        TimeSpan operationTimeout)
    {
        return Policy.TimeoutAsync(
            operationTimeout,
            TimeoutStrategy.Pessimistic,
            onTimeoutAsync: (context, timeout, task, exception) =>
            {
                Log.Warning("Persistor operation '{OperationName}' timed out after {Timeout}s",
                    operationName, timeout.TotalSeconds);
                return Task.CompletedTask;
            });
    }

    public static async Task<Result<TResult, TFailure>> ExecuteWithRetryAsync<TResult, TFailure>(
        Func<CancellationToken, Task<Result<TResult, TFailure>>> operation,
        string operationName,
        TimeSpan operationTimeout,
        Func<DbException, string, TFailure> dbExceptionMapper,
        Func<TimeoutException, string, TFailure> timeoutExceptionMapper,
        Func<Exception, string, TFailure> genericExceptionMapper,
        CancellationToken cancellationToken = default)
        where TFailure : IFailureBase
    {
        AsyncTimeoutPolicy timeoutPolicy = CreateTimeoutPolicy(operationName, operationTimeout);
        AsyncRetryPolicy retryPolicy = CreateRetryPolicy(operationName);

        AsyncPolicyWrap policyWrap = Policy.WrapAsync(retryPolicy, timeoutPolicy);

        try
        {
            return await policyWrap.ExecuteAsync(
                async (cancellationToken) => await operation(cancellationToken),
                cancellationToken);
        }
        catch (TimeoutRejectedException timeoutEx)
        {
            Log.Error(timeoutEx, "Persistor operation '{OperationName}' exceeded timeout of {Timeout}s",
                operationName, operationTimeout.TotalSeconds);
            return Result<TResult, TFailure>.Err(timeoutExceptionMapper(
                new TimeoutException($"Operation '{operationName}' timed out after {operationTimeout.TotalSeconds}s", timeoutEx),
                operationName));
        }
        catch (DbException dbEx)
        {
            Log.Error(dbEx, "Persistor operation '{OperationName}' failed with database exception", operationName);
            return Result<TResult, TFailure>.Err(dbExceptionMapper(dbEx, operationName));
        }
        catch (OperationCanceledException)
        {
            Log.Debug("Persistor operation '{OperationName}' was cancelled", operationName);
            throw;
        }
        catch (TimeoutException timeoutEx)
        {
            Log.Error(timeoutEx, "Persistor operation '{OperationName}' timed out", operationName);
            return Result<TResult, TFailure>.Err(timeoutExceptionMapper(timeoutEx, operationName));
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Persistor operation '{OperationName}' failed with unexpected exception", operationName);
            return Result<TResult, TFailure>.Err(genericExceptionMapper(ex, operationName));
        }
    }

    private static bool ShouldRetryDbException(DbException exception)
    {
        if (exception is SqlException sqlException)
        {
            return sqlException.Number switch
            {
                2 => true,
                53 => true,
                11001 => true,
                -2 => true,
                2146893022 => true,
                40501 => true,
                40613 => true,
                49918 => true,
                49919 => true,
                49920 => true,
                1205 => true,

                18456 => false,
                18486 => false,
                4060 => false,
                547 => false,
                515 => false,
                2627 => false,
                2601 => false,
                102 => false,
                156 => false,
                207 => false,
                208 => false,
                824 => false,
                825 => false,

                _ => true
            };
        }

        return true;
    }
}
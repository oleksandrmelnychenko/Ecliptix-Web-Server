using System.Data.Common;
using Ecliptix.Utilities;
using Microsoft.Data.SqlClient;
using Polly;
using Polly.Retry;
using Serilog;

namespace Ecliptix.Domain.Memberships.Persistors;

public static class PersistorRetryPolicy
{
    private static AsyncRetryPolicy CreateRetryPolicy(string operationName)
    {
        return Policy
            .Handle<DbException>(ShouldRetryDbException)
            .Or<TimeoutException>()
            .WaitAndRetryAsync(
                retryCount: 3,
                sleepDurationProvider: retryAttempt => TimeSpan.FromMilliseconds(Math.Pow(2, retryAttempt) * 200),
                onRetry: (outcome, timespan, retryCount, context) =>
                {

                });
    }

    public static async Task<Result<TResult, TFailure>> ExecuteWithRetryAsync<TResult, TFailure>(
        Func<Task<Result<TResult, TFailure>>> operation,
        string operationName,
        Func<DbException, string, TFailure> dbExceptionMapper,
        Func<TimeoutException, string, TFailure> timeoutExceptionMapper,
        Func<Exception, string, TFailure> genericExceptionMapper)
        where TFailure : IFailureBase
    {
        AsyncRetryPolicy policy = CreateRetryPolicy(operationName);

        try
        {
            return await policy.ExecuteAsync(async () => await operation());
        }
        catch (DbException dbEx)
        {

            return Result<TResult, TFailure>.Err(dbExceptionMapper(dbEx, operationName));
        }
        catch (TimeoutException timeoutEx)
        {

            return Result<TResult, TFailure>.Err(timeoutExceptionMapper(timeoutEx, operationName));
        }
        catch (Exception ex)
        {

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
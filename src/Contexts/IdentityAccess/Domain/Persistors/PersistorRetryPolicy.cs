using System.Data.Common;
using Ecliptix.SharedKernel;
using Polly;
using Polly.Retry;
using Polly.Timeout;
using Polly.Wrap;
using Npgsql;
using Serilog;

namespace Ecliptix.IdentityAccess.Domain.Persistors;

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
                onRetry: (exception, delay, retryCount, _) =>
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
            onTimeoutAsync: (_, timeout, _, _) =>
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
                async token => await operation(token),
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
        if (exception is PostgresException pgEx)
        {
            return pgEx.SqlState switch
            {
                PostgresErrorCodes.ConnectionException or PostgresErrorCodes.ConnectionFailure
                    or PostgresErrorCodes.ConnectionDoesNotExist => true,
                PostgresErrorCodes.QueryCanceled => true,
                PostgresErrorCodes.DeadlockDetected => true,
                PostgresErrorCodes.SerializationFailure => true,
                PostgresErrorCodes.LockNotAvailable => true,
                PostgresErrorCodes.TooManyConnections => true,

                PostgresErrorCodes.InvalidPassword or PostgresErrorCodes.InvalidAuthorizationSpecification => false,
                PostgresErrorCodes.InvalidCatalogName => false,
                PostgresErrorCodes.UniqueViolation => false,
                PostgresErrorCodes.ForeignKeyViolation => false,
                PostgresErrorCodes.NotNullViolation => false,
                PostgresErrorCodes.CheckViolation => false,
                PostgresErrorCodes.SyntaxError or PostgresErrorCodes.UndefinedTable
                    or PostgresErrorCodes.UndefinedColumn => false,
                PostgresErrorCodes.DataCorrupted or PostgresErrorCodes.IndexCorrupted => false,

                _ => true
            };
        }

        return true;
    }
}

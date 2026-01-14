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
        PersistorOperation operation,
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
                    Log.Debug("Persistor operation '{Operation}' retry {RetryCount}/{MaxRetries} after {Delay}ms due to {ExceptionType}",
                        operation, retryCount, maxRetries, delay.TotalMilliseconds, exception.GetType().Name);
                });
    }

    private static AsyncTimeoutPolicy CreateTimeoutPolicy(
        PersistorOperation operation,
        TimeSpan operationTimeout)
    {
        return Policy.TimeoutAsync(
            operationTimeout,
            TimeoutStrategy.Pessimistic,
            onTimeoutAsync: (_, timeout, _, _) =>
            {
                Log.Warning("Persistor operation '{Operation}' timed out after {Timeout}s",
                    operation, timeout.TotalSeconds);
                return Task.CompletedTask;
            });
    }

    public static async Task<Result<TResult, TFailure>> ExecuteWithRetryAsync<TResult, TFailure>(
        Func<CancellationToken, Task<Result<TResult, TFailure>>> operation,
        PersistorOperation operationType,
        TimeSpan operationTimeout,
        Func<DbException, PersistorOperation, TFailure> dbExceptionMapper,
        Func<TimeoutException, PersistorOperation, TFailure> timeoutExceptionMapper,
        Func<Exception, PersistorOperation, TFailure> genericExceptionMapper,
        CancellationToken cancellationToken = default)
        where TFailure : IFailureBase
    {
        AsyncTimeoutPolicy timeoutPolicy = CreateTimeoutPolicy(operationType, operationTimeout);
        AsyncRetryPolicy retryPolicy = CreateRetryPolicy(operationType);
        AsyncPolicyWrap policyWrap = Policy.WrapAsync(retryPolicy, timeoutPolicy);

        try
        {
            return await policyWrap.ExecuteAsync(
                async token => await operation(token),
                cancellationToken);
        }
        catch (TimeoutRejectedException timeoutEx)
        {
            Log.Error(timeoutEx, "Persistor operation '{Operation}' exceeded timeout of {Timeout}s",
                operationType, operationTimeout.TotalSeconds);
            return Result<TResult, TFailure>.Err(timeoutExceptionMapper(
                new TimeoutException($"Operation '{operationType}' timed out after {operationTimeout.TotalSeconds}s", timeoutEx),
                operationType));
        }
        catch (DbException dbEx)
        {
            Log.Error(dbEx, "Persistor operation '{Operation}' failed with database exception", operationType);
            return Result<TResult, TFailure>.Err(dbExceptionMapper(dbEx, operationType));
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (TimeoutException timeoutEx)
        {
            Log.Error(timeoutEx, "Persistor operation '{Operation}' timed out", operationType);
            return Result<TResult, TFailure>.Err(timeoutExceptionMapper(timeoutEx, operationType));
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Persistor operation '{Operation}' failed with unexpected exception", operationType);
            return Result<TResult, TFailure>.Err(genericExceptionMapper(ex, operationType));
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

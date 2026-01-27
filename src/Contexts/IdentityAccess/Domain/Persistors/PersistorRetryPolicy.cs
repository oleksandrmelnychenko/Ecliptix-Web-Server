using System.Data.Common;
using Ecliptix.SharedKernel;
using Polly;
using Polly.Retry;
using Polly.Timeout;
using Npgsql;
using Serilog;

namespace Ecliptix.IdentityAccess.Domain.Persistors;

public static class PersistorRetryPolicy
{
    private static AsyncRetryPolicy<Result<TResult, TFailure>> CreateRetryPolicy<TResult, TFailure>(
        PersistorOperation operation,
        int maxRetries = 3)
        where TFailure : IFailureBase
    {
        return Policy<Result<TResult, TFailure>>
            .HandleResult(result => result.IsErr && result.UnwrapErr().Retryable)
            .Or<DbException>(ShouldRetryDbException)
            .Or<TimeoutRejectedException>()
            .Or<TimeoutException>()
            .WaitAndRetryAsync(
                maxRetries,
                retryAttempt => TimeSpan.FromMilliseconds(Math.Pow(2, retryAttempt) * 200),
                onRetry: (outcome, delay, retryCount, _) =>
                {
                    string reason = outcome.Exception?.GetType().Name ??
                                    (outcome.Result.IsErr ? outcome.Result.UnwrapErr().GetType().Name : "Unknown");
                    Log.Debug("Persistor operation '{Operation}' retry {RetryCount}/{MaxRetries} after {Delay}ms due to {Reason}",
                        operation, retryCount, maxRetries, delay.TotalMilliseconds, reason);
                });
    }

    private static IAsyncPolicy<Result<TResult, TFailure>> CreateTimeoutPolicy<TResult, TFailure>(
        PersistorOperation operation,
        TimeSpan operationTimeout)
    {
        if (operationTimeout == Timeout.InfiniteTimeSpan || operationTimeout <= TimeSpan.Zero)
        {
            return Policy.NoOpAsync<Result<TResult, TFailure>>();
        }

        return Policy.TimeoutAsync<Result<TResult, TFailure>>(
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
        IAsyncPolicy<Result<TResult, TFailure>> timeoutPolicy =
            CreateTimeoutPolicy<TResult, TFailure>(operationType, operationTimeout);
        AsyncRetryPolicy<Result<TResult, TFailure>> retryPolicy =
            CreateRetryPolicy<TResult, TFailure>(operationType);
        IAsyncPolicy<Result<TResult, TFailure>> policyWrap = Policy.WrapAsync(retryPolicy, timeoutPolicy);

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

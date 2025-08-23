using System.Data.Common;
using Ecliptix.Domain.Utilities;
using Microsoft.Data.SqlClient;
using Serilog;

namespace Ecliptix.Domain.Memberships.Persistors;

public static class PersistorRetryPolicy
{
    private static readonly TimeSpan[] RetryDelays = 
    {
        TimeSpan.FromMilliseconds(250),
        TimeSpan.FromMilliseconds(500), 
        TimeSpan.FromSeconds(1),
        TimeSpan.FromSeconds(2)
    };

    public static async Task<Result<TResult, TFailure>> ExecuteWithRetryAsync<TResult, TFailure>(
        Func<Task<Result<TResult, TFailure>>> operation,
        string operationName,
        Func<DbException, string, TFailure> dbExceptionMapper,
        Func<TimeoutException, string, TFailure> timeoutExceptionMapper,
        Func<Exception, string, TFailure> genericExceptionMapper,
        int maxRetries = 3)
        where TFailure : IFailureBase
    {
        Exception? lastException = null;
        
        for (int attempt = 0; attempt <= maxRetries; attempt++)
        {
            try
            {
                Result<TResult, TFailure> result = await operation();
                
                if (result.IsOk || !ShouldRetryFailure(result.UnwrapErr(), attempt))
                {
                    return result;
                }
                
                if (attempt < maxRetries)
                {
                    TimeSpan delay = GetRetryDelay(attempt);
                    Log.Warning("Retry {RetryCount} for operation {OperationName} after {Delay}ms",
                        attempt + 1, operationName, delay.TotalMilliseconds);
                    await Task.Delay(delay);
                }
            }
            catch (DbException dbEx) when (ShouldRetryDbException(dbEx) && attempt < maxRetries)
            {
                lastException = dbEx;
                TimeSpan delay = GetRetryDelay(attempt);
                Log.Warning("Retry {RetryCount} for operation {OperationName} after {Delay}ms due to {ExceptionType}: {Message}",
                    attempt + 1, operationName, delay.TotalMilliseconds, dbEx.GetType().Name, dbEx.Message);
                await Task.Delay(delay);
            }
            catch (DbException dbEx)
            {
                Log.Error(dbEx, "Database exception in operation {OperationName}: {Message}", operationName, dbEx.Message);
                return Result<TResult, TFailure>.Err(dbExceptionMapper(dbEx, operationName));
            }
            catch (TimeoutException timeoutEx) when (attempt < maxRetries)
            {
                lastException = timeoutEx;
                TimeSpan delay = GetRetryDelay(attempt);
                Log.Warning("Retry {RetryCount} for operation {OperationName} after {Delay}ms due to timeout: {Message}",
                    attempt + 1, operationName, delay.TotalMilliseconds, timeoutEx.Message);
                await Task.Delay(delay);
            }
            catch (TimeoutException timeoutEx)
            {
                Log.Error(timeoutEx, "Timeout exception in operation {OperationName}: {Message}", operationName, timeoutEx.Message);
                return Result<TResult, TFailure>.Err(timeoutExceptionMapper(timeoutEx, operationName));
            }
            catch (Exception ex)
            {
                Log.Error(ex, "Unexpected exception in operation {OperationName}", operationName);
                return Result<TResult, TFailure>.Err(genericExceptionMapper(ex, operationName));
            }
        }
        
        Log.Error("All retry attempts failed for operation {OperationName}", operationName);
        return Result<TResult, TFailure>.Err(genericExceptionMapper(
            lastException ?? new InvalidOperationException("All retry attempts failed"), 
            operationName));
    }

    private static bool ShouldRetryDbException(DbException exception)
    {
        if (exception is SqlException sqlException)
        {
            return sqlException.Number switch
            {
                2 => true,    // Network error
                53 => true,   // Network path not found  
                11001 => true, // Host not found
                -2 => true,   // Timeout
                2146893022 => true, // Connection timeout
                40501 => true, // Azure SQL transient
                40613 => true, // Azure SQL transient
                49918 => true, // Azure SQL transient
                49919 => true, // Azure SQL transient
                49920 => true, // Azure SQL transient
                1205 => true,  // Deadlock - can be retried
                
                18456 => false, // Authentication failed
                18486 => false, // Account locked
                4060 => false,  // Database not accessible
                547 => false,   // Foreign key violation
                515 => false,   // NOT NULL violation
                2627 => false,  // Unique constraint
                2601 => false,  // Unique index
                102 => false,   // Syntax error
                156 => false,   // Syntax error
                207 => false,   // Invalid column
                208 => false,   // Invalid object
                824 => false,   // Data corruption
                825 => false,   // Data corruption
                
                _ => true
            };
        }
        
        return true;
    }

    private static bool ShouldRetryFailure<TFailure>(TFailure failure, int attempt) where TFailure : IFailureBase
    {
        // Basic implementation - can be enhanced based on failure types
        return attempt < 3;
    }

    private static TimeSpan GetRetryDelay(int attempt)
    {
        if (attempt < RetryDelays.Length)
        {
            TimeSpan baseDelay = RetryDelays[attempt];
            TimeSpan jitter = TimeSpan.FromMilliseconds(Random.Shared.Next(0, 100));
            return baseDelay + jitter;
        }
        return TimeSpan.FromSeconds(5);
    }
}
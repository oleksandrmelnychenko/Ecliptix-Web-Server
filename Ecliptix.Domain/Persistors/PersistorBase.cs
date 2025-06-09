using System.Diagnostics;
using Akka.Actor;
using Ecliptix.Domain.Utilities;
using Microsoft.Extensions.Logging;
using Npgsql;

namespace Ecliptix.Domain.Persistors;

public abstract class PersistorBase<TFailure>(
    IDbDataSource npgsqlDataSource,
    ILogger logger
) : ReceiveActor
    where TFailure : struct
{
    private static readonly ActivitySource ActivitySource = new("Ecliptix.Persistor");

    protected async Task ExecuteWithConnection<TResult>(
        Func<IDbConnection, Task<Result<TResult, TFailure>>> operation,
        string operationName = "Unknown")
    {
        using Activity? activity = StartActivity(operationName);
        Stopwatch stopwatch = Stopwatch.StartNew();

        try
        {
            await using IDbConnection conn = await CreateAndOpenConnectionAsync();
            SetConnectionTags(activity, conn);

            Result<TResult, TFailure> result = await operation(conn);

            HandleOperationComplete(stopwatch, activity, result, operationName);
            Sender.Tell(result);
        }
        catch (NpgsqlException dbEx)
        {
            HandleDatabaseException<TResult>(stopwatch, activity, dbEx, operationName);
        }
        catch (TimeoutException timeoutEx)
        {
            HandleTimeoutException<TResult>(stopwatch, activity, timeoutEx, operationName);
        }
        catch (Exception ex)
        {
            HandleUnexpectedException<TResult>(stopwatch, activity, ex, operationName);
        }
    }

    protected static IDbCommand CreateCommand(IDbConnection connection, string sql,
        params NpgsqlParameter[] parameters)
    {
        IDbCommand command = connection.CreateCommand();
        command.CommandText = sql;
        foreach (var parameter in parameters)
        {
            command.Parameters.Add(parameter);
        }

        return command;
    }

    protected static NpgsqlCommand CreateCommandWithTimeout(NpgsqlConnection connection, string sql,
        int timeoutSeconds, params NpgsqlParameter[] parameters)
    {
        NpgsqlCommand command = new(sql, connection)
        {
            CommandTimeout = timeoutSeconds
        };
        command.Parameters.AddRange(parameters);
        return command;
    }

    /// <summary>
    /// Maps NpgsqlException to domain-specific failure type.
    /// Must be implemented by derived classes for their specific failure types.
    /// </summary>
    protected abstract TFailure MapNpgsqlException(NpgsqlException ex);

    /// <summary>
    /// Creates a timeout failure for the specific domain.
    /// Must be implemented by derived classes for their specific failure types.
    /// </summary>
    protected abstract TFailure CreateTimeoutFailure(TimeoutException ex);

    /// <summary>
    /// Creates a generic failure for the specific domain.
    /// Must be implemented by derived classes for their specific failure types.
    /// </summary>
    protected abstract TFailure CreateGenericFailure(Exception ex);

    private static Activity? StartActivity(string operationName)
    {
        Activity? activity = ActivitySource.StartActivity($"Persistor.{operationName}");
        activity?.SetTag(ActivityTags.OperationType, OperationTypes.Database);
        activity?.SetTag(ActivityTags.OperationName, operationName);
        return activity;
    }

    /*private async Task<NpgsqlConnection> CreateAndOpenConnectionAsync()
    {
        NpgsqlConnection conn = npgsqlDataSource.CreateConnection();
        await conn.OpenAsync();
        return conn;
    }*/
    
    private async Task<IDbConnection> CreateAndOpenConnectionAsync()
    {
        IDbConnection conn = await npgsqlDataSource.CreateConnection();
        await conn.OpenAsync();
        return conn;
    }

    private static void SetConnectionTags(Activity? activity, IDbConnection conn)
    {
        activity?.SetTag(ActivityTags.DbConnectionString, conn.Host);
    }

    private void HandleOperationComplete<T>(Stopwatch stopwatch, Activity? activity,
        Result<T, TFailure> result, string operationName)
    {
        stopwatch.Stop();
        CompleteActivity(stopwatch, activity, result.IsOk);

        if (result.IsOk)
        {
            logger.LogDebug(LogMessages.OperationCompleted, operationName, stopwatch.ElapsedMilliseconds);
        }
        else
        {
            logger.LogWarning(LogMessages.OperationFailed, operationName, result.UnwrapErr());
            activity?.SetTag(ActivityTags.ErrorMessage, result.UnwrapErr().ToString());
        }
    }

    private void HandleDatabaseException<T>(Stopwatch stopwatch, Activity? activity,
        NpgsqlException dbEx, string operationName)
    {
        stopwatch.Stop();

        SetErrorActivity(activity, dbEx.Message, ErrorTypes.Database, dbEx.SqlState);
        LogDatabaseError(dbEx, operationName, stopwatch.ElapsedMilliseconds);

        TFailure failure = MapNpgsqlException(dbEx);
        Sender.Tell(Result<T, TFailure>.Err(failure));
    }

    private void HandleTimeoutException<T>(Stopwatch stopwatch, Activity? activity,
        TimeoutException timeoutEx, string operationName)
    {
        stopwatch.Stop();

        SetErrorActivity(activity, "Operation timeout", ErrorTypes.Timeout);
        LogTimeoutError(timeoutEx, operationName, stopwatch.ElapsedMilliseconds);

        TFailure failure = CreateTimeoutFailure(timeoutEx);
        Sender.Tell(Result<T, TFailure>.Err(failure));
    }

    private void HandleUnexpectedException<T>(Stopwatch stopwatch, Activity? activity,
        Exception ex, string operationName)
    {
        stopwatch.Stop();

        SetErrorActivity(activity, ex.Message, ErrorTypes.Unexpected);
        LogUnexpectedError(ex, operationName, stopwatch.ElapsedMilliseconds);

        TFailure failure = CreateGenericFailure(ex);
        Sender.Tell(Result<T, TFailure>.Err(failure));
    }

    private static void CompleteActivity(Stopwatch stopwatch, Activity? activity, bool isSuccess)
    {
        activity?.SetTag(ActivityTags.OperationDuration, stopwatch.ElapsedMilliseconds);
        activity?.SetStatus(isSuccess ? ActivityStatusCode.Ok : ActivityStatusCode.Error);
    }

    private static void SetErrorActivity(Activity? activity, string message, string errorType, string? errorCode = null)
    {
        activity?.SetStatus(ActivityStatusCode.Error, message);
        activity?.SetTag(ActivityTags.ErrorType, errorType);
        if (errorCode != null)
            activity?.SetTag(ActivityTags.ErrorCode, errorCode);
    }

    private void LogDatabaseError(NpgsqlException dbEx, string operationName, long elapsedMs) =>
        logger.LogError(dbEx, LogMessages.DatabaseError,
            operationName, elapsedMs, dbEx.SqlState, dbEx.Message);

    private void LogTimeoutError(TimeoutException timeoutEx, string operationName, long elapsedMs) =>
        logger.LogError(timeoutEx, LogMessages.TimeoutError, operationName, elapsedMs);

    private void LogUnexpectedError(Exception ex, string operationName, long elapsedMs) =>
        logger.LogError(ex, LogMessages.UnexpectedError, operationName, elapsedMs);
}
using System.Data;
using System.Data.Common;
using System.Diagnostics;
using Akka.Actor;
using Ecliptix.Domain.DbConnectionFactory;
using Ecliptix.Domain.Utilities;
using Microsoft.Extensions.Logging;

namespace Ecliptix.Domain.Persistors;

public abstract class PersistorBase<TFailure>(
    IDbConnectionFactory connectionFactory,
    ILogger logger
) : ReceiveActor
    where TFailure : struct
{
    private static readonly ActivitySource ActivitySource = new("Ecliptix.Persistor");

    protected async Task<object> ExecuteWithConnection<TResult>(
        Func<IDbConnection, Task<Result<TResult, TFailure>>> operation,
        string operationName)
    {
        using var activity = StartActivity(operationName);
        Stopwatch stopwatch = Stopwatch.StartNew();

        try
        {
            using IDbConnection conn = await connectionFactory.CreateOpenConnectionAsync();
            SetConnectionTags(activity, conn);

            Result<TResult, TFailure> result = await operation(conn);

            HandleOperationComplete(stopwatch, activity, result, operationName);
            return result;
        }
        catch (TimeoutException timeoutEx)
        {
            return HandleTimeoutException<TResult>(stopwatch, activity, timeoutEx, operationName);
        }
        catch (DbException dbEx)
        {
            return HandleDatabaseException<TResult>(stopwatch, activity, dbEx, operationName);
        }
        catch (Exception ex)
        {
            return HandleUnexpectedException<TResult>(stopwatch, activity, ex, operationName);
        }
    }

    protected static IDbCommand CreateCommand(IDbConnection connection, string sql, CommandType commandType,
        params IDbDataParameter[] parameters)
    {
        IDbCommand command = connection.CreateCommand();
        command.CommandText = sql;
        command.CommandType = commandType;
        foreach (IDbDataParameter parameter in parameters)
        {
            command.Parameters.Add(parameter);
        }

        return command;
    }

    protected abstract IDbDataParameter CreateParameter(string name, object value);
    protected abstract TFailure MapDbException(DbException ex);
    protected abstract TFailure CreateTimeoutFailure(TimeoutException ex);
    protected abstract TFailure CreateGenericFailure(Exception ex);

    private void HandleOperationComplete<TResult>(Stopwatch stopwatch, Activity? activity,
        Result<TResult, TFailure> result, string operationName)
    {
        stopwatch.Stop();
        CompleteActivity(stopwatch, activity, result.IsOk);

        if (result.IsOk)
        {
            logger.LogDebug("Operation {OperationName} completed successfully in {ElapsedMilliseconds}ms.",
                operationName, stopwatch.ElapsedMilliseconds);
        }
        else
        {
            var error = result.UnwrapErr();
            logger.LogWarning("Operation {OperationName} failed with error: {Error}", operationName, error);
            activity?.SetTag("error.message", error.ToString());
        }
    }

    private Result<T, TFailure> HandleDatabaseException<T>(Stopwatch stopwatch, Activity? activity, DbException dbEx,
        string operationName)
    {
        stopwatch.Stop();
        TFailure failure = MapDbException(dbEx);

        SetErrorActivity(activity, dbEx.Message, "db_error", dbEx.ErrorCode.ToString());
        CompleteActivity(stopwatch, activity, false);

        logger.LogError(dbEx,
            "Database error during operation {OperationName} after {ElapsedMilliseconds}ms. ErrorCode: {ErrorCode}",
            operationName, stopwatch.ElapsedMilliseconds, dbEx.ErrorCode);

        return Result<T, TFailure>.Err(failure);
    }

    private Result<T, TFailure> HandleTimeoutException<T>(Stopwatch stopwatch, Activity? activity,
        TimeoutException timeoutEx, string operationName)
    {
        stopwatch.Stop();
        TFailure failure = CreateTimeoutFailure(timeoutEx);

        SetErrorActivity(activity, "Operation timeout", "timeout");
        CompleteActivity(stopwatch, activity, false);

        logger.LogError(timeoutEx, "Timeout error during operation {OperationName} after {ElapsedMilliseconds}ms.",
            operationName, stopwatch.ElapsedMilliseconds);

        return Result<T, TFailure>.Err(failure);
    }

    private Result<T, TFailure> HandleUnexpectedException<T>(Stopwatch stopwatch, Activity? activity, Exception ex,
        string operationName)
    {
        stopwatch.Stop();
        TFailure failure = CreateGenericFailure(ex);

        SetErrorActivity(activity, ex.Message, "unexpected");
        CompleteActivity(stopwatch, activity, false);

        logger.LogError(ex, "Unexpected error during operation {OperationName} after {ElapsedMilliseconds}ms.",
            operationName, stopwatch.ElapsedMilliseconds);

        return Result<T, TFailure>.Err(failure);
    }

    private static Activity? StartActivity(string operationName)
    {
        Activity? activity = ActivitySource.StartActivity($"Persistor.{operationName}");
        activity?.SetTag("db.system", "mssql");
        activity?.SetTag("db.operation", operationName);
        return activity;
    }

    private static void SetConnectionTags(Activity? activity, IDbConnection conn)
    {
        activity?.SetTag("db.name", conn.Database);
    }

    private static void CompleteActivity(Stopwatch stopwatch, Activity? activity, bool isSuccess)
    {
        if (activity is null) return;
        activity.SetTag("otel.duration_ms", stopwatch.ElapsedMilliseconds);
        activity.SetStatus(isSuccess ? ActivityStatusCode.Ok : ActivityStatusCode.Error);
    }

    private static void SetErrorActivity(Activity? activity, string message, string errorType, string? errorCode = null)
    {
        if (activity is null) return;
        activity.SetStatus(ActivityStatusCode.Error, message);
        activity.SetTag("error.type", errorType);
        if (!string.IsNullOrEmpty(errorCode))
            activity.SetTag("error.code", errorCode);
    }
}
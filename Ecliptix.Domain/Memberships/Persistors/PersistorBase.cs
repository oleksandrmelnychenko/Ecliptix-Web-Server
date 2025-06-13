using System.Data;
using System.Data.Common;
using System.Diagnostics;
using Akka.Actor;
using Ecliptix.Domain.DbConnectionFactory;
using Ecliptix.Domain.Utilities;
using Microsoft.Extensions.Logging;

namespace Ecliptix.Domain.Memberships.Persistors;

public abstract class PersistorBase<TFailure>(
    IDbConnectionFactory connectionFactory,
    ILogger logger
) : ReceiveActor
    where TFailure : IFailureBase
{
    private static readonly ActivitySource ActivitySource = new("Ecliptix.Persistor");

    protected async Task<Result<TResult, TFailure>> ExecuteWithConnection<TResult>(
        Func<IDbConnection, Task<Result<TResult, TFailure>>> operation,
        string operationName,
        string? commandText = null)
    {
        using Activity? activity = StartActivity(operationName, commandText);

        try
        {
            using IDbConnection conn = await connectionFactory.CreateOpenConnectionAsync();
            activity?.SetTag("db.name", conn.Database);

            Result<TResult, TFailure> result = await operation(conn);

            HandleOperationResult(activity, result, operationName);
            return result;
        }
        catch (Exception ex)
        {
            return HandleException<TResult>(ex, activity, operationName);
        }
    }

    protected abstract TFailure MapDbException(DbException ex);
    protected abstract TFailure CreateTimeoutFailure(TimeoutException ex);
    protected abstract TFailure CreateGenericFailure(Exception ex);

    private void HandleOperationResult<TResult>(Activity? activity, Result<TResult, TFailure> result,
        string operationName)
    {
        if (result.IsOk)
        {
            logger.LogDebug("Operation {OperationName} completed successfully", operationName);
            activity?.SetStatus(ActivityStatusCode.Ok);
        }
        else
        {
            TFailure failure = result.UnwrapErr();
            logger.LogWarning("Operation {OperationName} completed with a domain failure: {@FailureDetails}",
                operationName, failure.ToStructuredLog());

            activity?.SetStatus(ActivityStatusCode.Ok);
            activity?.AddEvent(new ActivityEvent("DomainFailure", tags: new ActivityTagsCollection
            {
                { "failure.type", failure.GetType().Name },
                { "failure.details", failure.ToString() }
            }));
        }
    }

    private Result<T, TFailure> HandleException<T>(Exception ex, Activity? activity, string operationName)
    {
        activity?.SetStatus(ActivityStatusCode.Error, ex.Message);
        activity?.AddException(ex);

        (TFailure failure, LogLevel level) = ex switch
        {
            TimeoutException timeoutEx => (CreateTimeoutFailure(timeoutEx), LogLevel.Error),
            DbException dbEx => (MapDbException(dbEx), LogLevel.Error),
            _ => (CreateGenericFailure(ex), LogLevel.Critical)
        };

        logger.Log(level, ex, "Operation {OperationName} failed with an unhandled exception", operationName);

        return Result<T, TFailure>.Err(failure);
    }

    private static Activity? StartActivity(string operationName, string? commandText)
    {
        Activity? activity = ActivitySource.StartActivity($"{operationName}", ActivityKind.Client);
        if (activity is null) return null;

        activity.SetTag("db.system", "mssql");
        activity.SetTag("db.operation", operationName);
        if (!string.IsNullOrWhiteSpace(commandText)) activity.SetTag("db.statement", commandText);

        return activity;
    }
}
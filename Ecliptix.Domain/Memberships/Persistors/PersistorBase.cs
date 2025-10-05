using System.Data;
using System.Data.Common;
using System.Diagnostics;
using Akka.Actor;
using Ecliptix.Memberships.Persistor.Schema;
using Ecliptix.Utilities;
using Ecliptix.Utilities.Configuration;
using Microsoft.EntityFrameworkCore;
using Serilog;

namespace Ecliptix.Domain.Memberships.Persistors;

public abstract class PersistorBase<TFailure> : ReceiveActor, IDisposable
    where TFailure : IFailureBase
{
    private readonly IDbContextFactory<EcliptixSchemaContext> _dbContextFactory;
    private readonly ActivitySource _activitySource;
    private readonly Dictionary<string, TimeSpan> _operationTimeouts;
    private bool _disposed;

    protected PersistorBase(IDbContextFactory<EcliptixSchemaContext> dbContextFactory)
    {
        _dbContextFactory = dbContextFactory ?? throw new ArgumentNullException(nameof(dbContextFactory));
        _activitySource = new ActivitySource($"Ecliptix.Persistor.{GetType().Name}");
        _operationTimeouts = GetOperationTimeouts();
    }

    protected async Task<Result<TResult, TFailure>> ExecuteWithContext<TResult>(
        Func<EcliptixSchemaContext, Task<Result<TResult, TFailure>>> operation,
        string operationName)
    {
        if (_disposed)
            throw new ObjectDisposedException(nameof(PersistorBase<TFailure>));

        using Activity? activity = StartActivity(operationName, null);

        return await PersistorRetryPolicy.ExecuteWithRetryAsync(
            async () =>
            {
                await using EcliptixSchemaContext ctx = await _dbContextFactory.CreateDbContextAsync();

                activity?.SetTag("db.name", ctx.Database.GetDbConnection().Database);
                activity?.SetTag("db.connection_state", ctx.Database.GetDbConnection().State.ToString());
                activity?.SetTag("operation.start_time", DateTime.UtcNow.ToString("O"));

                Result<TResult, TFailure> result = await operation(ctx);

                HandleOperationResult(activity, result, operationName);
                return result;
            },
            operationName,
            (dbEx, opName) => MapDbException(dbEx),
            (timeoutEx, opName) => CreateTimeoutFailure(timeoutEx),
            (ex, opName) => CreateGenericFailure(ex));
    }

    protected abstract TFailure MapDbException(DbException ex);
    protected abstract TFailure CreateTimeoutFailure(TimeoutException ex);
    protected abstract TFailure CreateGenericFailure(Exception ex);

    private static Dictionary<string, TimeSpan> GetOperationTimeouts()
    {
        return new Dictionary<string, TimeSpan>
        {
            ["Create"] = TimeoutConfiguration.Database.CreateTimeout,
            ["Update"] = TimeoutConfiguration.Database.UpdateTimeout,
            ["Delete"] = TimeoutConfiguration.Database.DeleteTimeout,
            ["Get"] = TimeoutConfiguration.Database.GetTimeout,
            ["Query"] = TimeoutConfiguration.Database.QueryTimeout,
            ["List"] = TimeoutConfiguration.Database.ListTimeout
        };
    }

    protected override SupervisorStrategy SupervisorStrategy()
    {
        return PersistorSupervisorStrategy.CreateStrategy();
    }

    private void HandleOperationResult<TResult>(Activity? activity, Result<TResult, TFailure> result,
        string operationName)
    {
        if (result.IsOk)
        {

            activity?.SetStatus(ActivityStatusCode.Ok);
            activity?.SetTag("operation.success", true);
        }
        else
        {
            TFailure failure = result.UnwrapErr();

            activity?.SetStatus(ActivityStatusCode.Error, failure.ToString());
            activity?.AddEvent(new ActivityEvent("DomainFailure", tags: new ActivityTagsCollection
            {
                ["failure.type"] = failure.GetType().Name,
                ["failure.details"] = failure.ToString(),
                ["operation.success"] = false
            }));
        }
    }

    private Activity? StartActivity(string operationName, string? commandText)
    {
        Activity? activity = _activitySource.StartActivity($"{GetType().Name}.{operationName}", ActivityKind.Client);
        if (activity is null) return null;

        activity.SetTag("db.system", "mssql");
        activity.SetTag("db.operation", operationName);
        activity.SetTag("persistor.type", GetType().Name);
        activity.SetTag("operation.start_time", DateTime.UtcNow.ToString("O"));

        if (!string.IsNullOrWhiteSpace(commandText))
        {
            activity.SetTag("db.statement", commandText.Length > 1000 ? commandText[..1000] + "..." : commandText);
        }

        return activity;
    }


    protected override void PostStop()
    {
        Dispose();
        base.PostStop();
    }

    public void Dispose()
    {
        if (_disposed) return;

        _activitySource.Dispose();
        _disposed = true;

    }
}
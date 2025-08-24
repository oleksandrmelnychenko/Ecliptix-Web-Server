using System.Data;
using System.Data.Common;
using System.Diagnostics;
using Akka.Actor;
using Ecliptix.Domain.DbConnectionFactory;
using Ecliptix.Domain.Utilities;
using Serilog;

namespace Ecliptix.Domain.Memberships.Persistors;

public abstract class PersistorBase<TFailure> : ReceiveActor, IDisposable
    where TFailure : IFailureBase
{
    private readonly IDbConnectionFactory _connectionFactory;
    private readonly ActivitySource _activitySource;
    private readonly Dictionary<string, TimeSpan> _operationTimeouts;
    private bool _disposed;

    protected PersistorBase(IDbConnectionFactory connectionFactory)
    {
        _connectionFactory = connectionFactory ?? throw new ArgumentNullException(nameof(connectionFactory));
        _activitySource = new ActivitySource($"Ecliptix.Persistor.{GetType().Name}");
        _operationTimeouts = GetOperationTimeouts();
    }

    protected async Task<Result<TResult, TFailure>> ExecuteWithConnection<TResult>(
        Func<IDbConnection, Task<Result<TResult, TFailure>>> operation,
        string operationName,
        string? commandText = null)
    {
        if (_disposed)
            throw new ObjectDisposedException(nameof(PersistorBase<TFailure>));

        using Activity? activity = StartActivity(operationName, commandText);

        return await PersistorRetryPolicy.ExecuteWithRetryAsync(
            async () =>
            {
                using IDbConnection connection = await CreateConnectionWithTimeout(operationName);
                activity?.SetTag("db.name", connection.Database);
                activity?.SetTag("db.connection_state", connection.State.ToString());

                ValidateConnection(connection, operationName);
                ConfigureConnectionTimeout(connection, operationName);

                Result<TResult, TFailure> result = await operation(connection);

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
            ["Create"] = TimeSpan.FromSeconds(30),
            ["Update"] = TimeSpan.FromSeconds(30),
            ["Delete"] = TimeSpan.FromSeconds(20),
            ["Get"] = TimeSpan.FromSeconds(10),
            ["Query"] = TimeSpan.FromSeconds(15),
            ["List"] = TimeSpan.FromSeconds(20)
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
            Log.Debug("Persistor operation {OperationName} completed successfully for actor {ActorType}",
                operationName, GetType().Name);
            activity?.SetStatus(ActivityStatusCode.Ok);
            activity?.SetTag("operation.success", true);
        }
        else
        {
            TFailure failure = result.UnwrapErr();
            Log.Warning("Persistor operation {OperationName} failed for actor {ActorType}: {@FailureDetails}",
                operationName, GetType().Name, failure.ToStructuredLog());

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

    private async Task<IDbConnection> CreateConnectionWithTimeout(string operationName)
    {
        using CancellationTokenSource timeoutCts = new(TimeSpan.FromSeconds(30));

        try
        {
            return await _connectionFactory.CreateOpenConnectionAsync(timeoutCts.Token);
        }
        catch (OperationCanceledException) when (timeoutCts.Token.IsCancellationRequested)
        {
            throw new TimeoutException($"Connection creation timed out for operation {operationName}");
        }
    }

    private void ValidateConnection(IDbConnection connection, string operationName)
    {
        if (connection.State != ConnectionState.Open)
        {
            throw new InvalidOperationException(
                $"Connection not open for operation {operationName}. State: {connection.State}");
        }
    }

    private void ConfigureConnectionTimeout(IDbConnection connection, string operationName)
    {
        if (connection is not DbConnection dbConnection) return;

        TimeSpan timeout = GetTimeoutForOperation(operationName);
        if (dbConnection.ConnectionTimeout != (int)timeout.TotalSeconds)
        {
            Log.Debug("Using timeout {Timeout}s for operation {OperationName}", timeout.TotalSeconds, operationName);
        }
    }

    private TimeSpan GetTimeoutForOperation(string operationName)
    {
        foreach (KeyValuePair<string, TimeSpan> kvp in _operationTimeouts.Where(kvp =>
                     operationName.Contains(kvp.Key, StringComparison.OrdinalIgnoreCase)))
        {
            return kvp.Value;
        }

        return TimeSpan.FromSeconds(15);
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

        Log.Debug("Disposed persistor actor {ActorType}", GetType().Name);
    }
}